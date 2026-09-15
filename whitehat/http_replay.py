"""Exact-request replay with credential references and persistent session budgets."""

from __future__ import annotations

import base64
import http.client
import ipaddress
import os
import re
import socket
import ssl
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .http_evidence import digest, evidence_document, exchange, label, pointers
from .network_engine import (
    _complete_request,
    _connect,
    _ensure_state,
    _reserve_request,
    _state_path,
)
from .reports import (
    ReportError,
    ReportLimitError,
    canonical,
    endpoint,
    parse_json,
    read_bytes,
    text,
)
from .reports import relative_path
from .runner import ProcessLimits, execute_fixed_profile

SESSION_SCHEMA = "whitehat-replay-session-v1"
REQUEST_SCHEMA = "whitehat-prepared-request-v1"
_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
_BLOCKED_HEADERS = {
    "authorization",
    "cookie",
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "expect",
    "upgrade",
    "trailer",
    "te",
    "accept-encoding",
}


def _fields(value: Any, expected: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ReportError(f"invalid {name} fields")
    return value


def _time(value: Any) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value
    ):
        raise ReportError("session time must be UTC RFC3339")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ReportError("invalid session timestamp") from exc


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ReportError(f"{name} must be between {minimum} and {maximum}")
    return value


def origin(value: Any) -> str:
    value = text(value, "origin", 512)
    try:
        parsed = urlsplit(value)
        if (
            parsed.username is not None
            or parsed.password is not None
            or not parsed.hostname
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError
        host = parsed.hostname
        if (
            host != host.lower()
            or not host.isascii()
            or not re.fullmatch(r"[a-z0-9.-]{1,253}", host)
        ):
            raise ValueError
        if parsed.scheme not in {"http", "https"} or (
            parsed.scheme == "http" and host != "127.0.0.1"
        ):
            raise ValueError
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
    except ValueError as exc:
        raise ReportError(
            "origin must be exact HTTPS or owned http://127.0.0.1"
        ) from exc
    return f"{parsed.scheme}://{host}" + (f":{port}" if port is not None else "")


def prepared_request(value: Any) -> dict[str, Any]:
    _fields(
        value,
        {
            "schemaVersion",
            "method",
            "url",
            "headers",
            "body",
            "objectId",
            "operationId",
        },
        "prepared request",
    )
    if (
        value["schemaVersion"] != REQUEST_SCHEMA
        or not isinstance(value["method"], str)
        or value["method"] not in _METHODS
    ):
        raise ReportError("unsupported request schema/method")
    url = text(value["url"], "request URL", 8192)
    parsed = urlsplit(url)
    origin(f"{parsed.scheme}://{parsed.netloc}")
    path = parsed.path or "/"
    # Only ordinary, unambiguous paths in the initial replay profile.
    if (
        not url.isascii()
        or parsed.fragment
        or not path.startswith("/")
        or path.startswith("//")
        or "%" in path
        or "\\" in path
        or any(p in {".", ".."} for p in path.split("/"))
    ):
        raise ReportError("request path is ambiguous or unsupported")
    headers = value["headers"]
    if not isinstance(headers, dict) or len(headers) > 30:
        raise ReportError("prepared headers must be a bounded object")
    seen = set()
    for name, content in headers.items():
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9-]{1,80}", name)
            or name.lower() in _BLOCKED_HEADERS
            or name.lower().startswith("proxy-")
            or name.lower() in seen
        ):
            raise ReportError(
                "prepared request contains a forbidden or duplicate header"
            )
        seen.add(name.lower())
        text(content, "header value", 1000)
        if not content.isascii():
            raise ReportError("initial header profile requires ASCII")
    if value["body"] is not None and (
        not isinstance(value["body"], str)
        or len(value["body"].encode("utf-8")) > 64 * 1024
    ):
        raise ReportLimitError("prepared body limit exceeded")
    if value["method"] in {"GET", "HEAD", "OPTIONS"} and value["body"] is not None:
        raise ReportError("this method profile does not accept a request body")
    label(value["objectId"], "object")
    label(value["operationId"], "operation")
    return value


def request_preview(path: str) -> dict[str, Any]:
    value = prepared_request(parse_json(read_bytes(Path(path), 128 * 1024)))
    return {
        "schemaVersion": "whitehat-request-preview-v1",
        "ok": True,
        "requestSha256": digest(value),
        "method": value["method"],
        "endpoint": endpoint(value["url"]),
        "objectId": value["objectId"],
        "operationId": value["operationId"],
        "executionPerformed": False,
    }


def validate_session(value: Any, *, check_time: bool = True) -> dict[str, Any]:
    _fields(
        value,
        {
            "schemaVersion",
            "sessionId",
            "projectId",
            "origin",
            "startsAt",
            "expiresAt",
            "authority",
            "requestSha256",
            "identities",
            "responsePointers",
            "budgets",
            "allowMutation",
        },
        "replay session",
    )
    if value["schemaVersion"] != SESSION_SCHEMA:
        raise ReportError("unsupported replay session")
    label(value["sessionId"], "session")
    label(value["projectId"], "project")
    if origin(value["origin"]) != value["origin"]:
        raise ReportError(
            "session origin must use canonical spelling without trailing slash"
        )
    start, end = _time(value["startsAt"]), _time(value["expiresAt"])
    if not 0 < (end - start).total_seconds() <= 8 * 3600:
        raise ReportError("session must last at most eight hours")
    authority = _fields(
        value["authority"],
        {"policy", "reviewedAt", "approved", "researcherControlled"},
        "authority",
    )
    text(authority["policy"], "policy reference", 1024)
    reviewed = _time(authority["reviewedAt"])
    if (
        not start.replace(hour=0, minute=0, second=0, microsecond=0)
        <= reviewed
        <= start
    ):
        raise ReportError(
            "policy review must be on the session's start date before activation"
        )
    if (
        authority["approved"] is not True
        or authority["researcherControlled"] is not True
    ):
        raise ReportError(
            "session needs explicit policy approval and controlled identities/objects"
        )
    if check_time and not start <= datetime.now(timezone.utc) < end:
        raise ReportError("session is not active")
    hashes = value["requestSha256"]
    if (
        not isinstance(hashes, list)
        or not 1 <= len(hashes) <= 100
        or any(
            not isinstance(h, str) or not re.fullmatch(r"[a-f0-9]{64}", h)
            for h in hashes
        )
        or len(hashes) != len(set(hashes))
    ):
        raise ReportError("session needs unique reviewed request hashes")
    identities = value["identities"]
    if not isinstance(identities, list) or not 1 <= len(identities) <= 10:
        raise ReportError("session needs 1-10 controlled identity profiles")
    seen = set()
    for identity in identities:
        _fields(identity, {"id", "auth", "credentialEnv"}, "identity")
        name = label(identity["id"], "identity")
        if (
            name in seen
            or not isinstance(identity["auth"], str)
            or identity["auth"] not in {"none", "bearer", "cookie"}
        ):
            raise ReportError("duplicate/invalid identity")
        seen.add(name)
        env = identity["credentialEnv"]
        if identity["auth"] == "none":
            if env is not None:
                raise ReportError("anonymous identity must not reference credentials")
        elif not isinstance(env, str) or not re.fullmatch(
            r"WHITEHAT_CREDENTIAL_[A-Z0-9_]{1,60}", env
        ):
            raise ReportError(
                "credential reference must use a WHITEHAT_CREDENTIAL_ environment name"
            )
    pointers(value["responsePointers"])
    budgets = _fields(
        value["budgets"],
        {"maxRequests", "minDelayMs", "timeoutSeconds", "maxResponseBytes"},
        "budgets",
    )
    _integer(budgets["maxRequests"], "maxRequests", 1, 100)
    _integer(budgets["minDelayMs"], "minDelayMs", 0, 60_000)
    _integer(budgets["timeoutSeconds"], "timeoutSeconds", 1, 10)
    _integer(budgets["maxResponseBytes"], "maxResponseBytes", 1, 1024 * 1024)
    if type(value["allowMutation"]) is not bool:
        raise ReportError("allowMutation must be boolean")
    return value


def _bind(state: Path, session: dict[str, Any]) -> None:
    connection = _connect(state)
    try:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS replay_binding (id INTEGER PRIMARY KEY CHECK(id=1), session_sha256 TEXT NOT NULL)"
        )
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "INSERT OR IGNORE INTO replay_binding VALUES (1, ?)", (digest(session),)
        )
        if connection.execute(
            "SELECT session_sha256 FROM replay_binding WHERE id=1"
        ).fetchone()[0] != digest(session):
            connection.execute("ROLLBACK")
            raise ReportError(
                "ledger is bound to a different session; edits cannot reset its budget"
            )
        connection.execute("COMMIT")
    finally:
        connection.close()


def _budget_session(session: dict[str, Any]) -> dict[str, Any]:
    return {
        "sessionId": session["sessionId"],
        "budgets": {**session["budgets"], "maxConcurrency": 1},
    }


def _credential(profile: dict[str, Any]) -> dict[str, str]:
    if profile["auth"] == "none":
        return {}
    value = os.environ.get(profile["credentialEnv"])
    if (
        not value
        or len(value) > 8192
        or not value.isascii()
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise ReportError("credential reference is missing or invalid")
    if profile["auth"] == "bearer":
        if not re.fullmatch(r"[A-Za-z0-9._~+/=-]+", value):
            raise ReportError("bearer credential has invalid characters")
        return {"Authorization": "Bearer " + value}
    return {"Cookie": value}


def _resolve(host: str, port: int, timeout: float) -> str:
    if host == "127.0.0.1":
        return host
    try:
        addresses = [str(ipaddress.ip_address(host))]
    except ValueError:
        execution = execute_fixed_profile(
            profile="http.dns.resolve",
            executable=sys.executable,
            arguments=["-I", "-B", str(Path(__file__).with_name("dns_worker.py"))],
            input_bytes=canonical({"host": host, "port": port}),
            limits=ProcessLimits(
                timeout_seconds=max(0.05, min(timeout, 5)),
                max_input_bytes=2048,
                max_stdout_bytes=2048,
                max_stderr_bytes=2048,
            ),
        )
        value = parse_json(execution.stdout)
        if not isinstance(value, dict) or set(value) != {"addresses"}:
            raise ReportError("invalid resolver response")
        addresses = value["addresses"]
    if not isinstance(addresses, list) or not 1 <= len(addresses) <= 16:
        raise ReportError("invalid resolution")
    try:
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if (
                not ip.is_global
                or ip.is_multicast
                or ip.is_reserved
                or getattr(ip, "ipv4_mapped", None) is not None
                or getattr(ip, "sixtofour", None) is not None
                or getattr(ip, "teredo", None) is not None
            ):
                raise ValueError
    except (ValueError, TypeError) as exc:
        raise ReportError("external host resolved to a non-public address") from exc
    return sorted(addresses)[0]


def _send(
    request: dict[str, Any], session: dict[str, Any], auth: dict[str, str]
) -> tuple[int, list[dict[str, str]], bytes]:
    parsed = urlsplit(request["url"])
    host = parsed.hostname
    assert host is not None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    remaining = min(
        float(session["budgets"]["timeoutSeconds"]),
        (_time(session["expiresAt"]) - datetime.now(timezone.utc)).total_seconds(),
    )
    if remaining <= 0:
        raise ReportError("session expired before transport")
    deadline = time.monotonic() + remaining
    address = _resolve(host, port, remaining)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ReportLimitError("resolution exhausted the request deadline")
    wire = socket.create_connection((address, port), timeout=remaining)
    holder = {"socket": wire}
    expired = threading.Event()

    def abort() -> None:
        expired.set()
        try:
            holder["socket"].shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    timer = threading.Timer(max(0.001, deadline - time.monotonic()), abort)
    timer.daemon = True
    timer.start()
    connection = http.client.HTTPConnection(host, port, timeout=remaining)
    try:
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            wire = context.wrap_socket(
                wire, server_hostname=host, do_handshake_on_connect=False
            )
            holder["socket"] = wire
            wire.settimeout(max(0.001, deadline - time.monotonic()))
            wire.do_handshake()
        connection.sock = wire
        headers = {**request["headers"], **auth, "Accept-Encoding": "identity"}
        target = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
        body = request["body"].encode("utf-8") if request["body"] is not None else None
        connection.request(request["method"], target, body=body, headers=headers)
        response = connection.getresponse()
        response_headers = response.getheaders()
        if len(response_headers) > 100:
            raise ReportLimitError("response header count exceeded")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise ReportError("compressed replay responses are unsupported")
        raw = response.read(session["budgets"]["maxResponseBytes"] + 1)
        if len(raw) > session["budgets"]["maxResponseBytes"]:
            raise ReportLimitError("response byte budget exceeded")
        if expired.is_set() or time.monotonic() >= deadline:
            raise ReportLimitError("request deadline exceeded")
        return response.status, [{"name": name} for name, _ in response_headers], raw
    finally:
        timer.cancel()
        connection.close()
        holder["socket"].close()


def replay(
    session_path: str,
    request_path: str,
    identity: str,
    state_path: str,
    *,
    _batch_owner: str | None = None,
) -> dict[str, Any]:
    session = validate_session(parse_json(read_bytes(Path(session_path), 256 * 1024)))
    request = prepared_request(parse_json(read_bytes(Path(request_path), 128 * 1024)))
    parsed = urlsplit(request["url"])
    if (
        origin(f"{parsed.scheme}://{parsed.netloc}") != session["origin"]
        or digest(request) not in session["requestSha256"]
    ):
        raise ReportError(
            "request does not match the approved origin and exact request hash"
        )
    if (
        request["method"] in {"POST", "PUT", "PATCH", "DELETE"}
        and not session["allowMutation"]
    ):
        raise ReportError("session does not permit this state-changing method")
    profiles = [p for p in session["identities"] if p["id"] == identity]
    if len(profiles) != 1:
        raise ReportError("identity is not in the session")
    auth = _credential(profiles[0])
    state = _state_path(state_path)
    _bind(state, session)
    reservation = _reserve_request(
        state,
        digest(session),
        _budget_session(session),
        request["method"],
        session["origin"],
        parsed.path,
        datetime.now(timezone.utc),
        batch_owner=_batch_owner,
    )
    status = size = None
    outcome, stop = "failed", "transport-failure"
    try:
        status, headers, raw = _send(request, session, auth)
        size = len(raw)
        outcome, stop = "completed", None
        if 300 <= status < 400:
            outcome, stop = "redirect-rejected", "unexpected-redirect"
        elif status == 429:
            outcome, stop = "rate-limited", "rate-limited"
        record = exchange(
            session["projectId"],
            {
                "method": request["method"],
                "url": request["url"],
                "headers": [{"name": k} for k in request["headers"]],
                "postData": {"text": request["body"]}
                if request["body"] is not None
                else {},
            },
            {
                "status": status,
                "headers": headers,
                "content": {
                    "text": base64.b64encode(raw).decode("ascii"),
                    "encoding": "base64",
                },
            },
            identity=identity,
            object_id=request["objectId"],
            operation=request["operationId"],
            selected=session["responsePointers"],
        )
        secrets = list(auth.values())
        if "Authorization" in auth:
            secrets.append(auth["Authorization"].removeprefix("Bearer "))
        if "Cookie" in auth:
            secrets.extend(
                part.split("=", 1)[1].strip()
                for part in auth["Cookie"].split(";")
                if "=" in part
            )
        if any(
            isinstance(v, str) and any(s and s in v for s in secrets)
            for v in record["response"]["json"]["values"].values()
        ):
            raise ReportError(
                "selected evidence contains a credential value; no evidence exported"
            )
    except Exception as exc:
        if outcome == "completed":
            outcome, stop = "evidence-rejected", "evidence-rejected"
        _complete_request(
            state,
            digest(session),
            reservation.sequence,
            datetime.now(timezone.utc),
            outcome,
            status,
            size,
            stop,
        )
        if isinstance(exc, (ReportError, ReportLimitError)):
            raise
        raise ReportError(
            "replay transport failed; attempt consumed and session stopped"
        ) from exc
    ledger = _complete_request(
        state,
        digest(session),
        reservation.sequence,
        datetime.now(timezone.utc),
        outcome,
        status,
        size,
        stop,
    )
    return evidence_document(
        session["projectId"],
        [record],
        {
            "kind": "replay",
            "sessionSha256": digest(session),
            "requestSha256": digest(request),
            "identityId": identity,
            "sequence": reservation.sequence,
            "outcome": outcome,
            "ledger": ledger,
            "executionVerified": True,
            "identityBinding": "operator-asserted",
        },
    )


def stop_session(session_path: str, state_path: str) -> dict[str, Any]:
    session = validate_session(
        parse_json(read_bytes(Path(session_path), 256 * 1024)), check_time=False
    )
    state = _state_path(state_path)
    _bind(state, session)
    connection = _connect(state)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _ensure_state(connection, digest(session), _budget_session(session))
        connection.execute(
            "UPDATE session_state SET stopped=1, stop_reason='user-stop' WHERE session_sha256=?",
            (digest(session),),
        )
        connection.execute("COMMIT")
    finally:
        connection.close()
    return {
        "schemaVersion": "whitehat-replay-stop-v1",
        "ok": True,
        "sessionId": session["sessionId"],
        "stopped": True,
    }


def run_scenario(
    scenario_path: str, session_path: str, state_path: str
) -> dict[str, Any]:
    path = Path(scenario_path)
    scenario = parse_json(read_bytes(path, 256 * 1024))
    _fields(scenario, {"schemaVersion", "projectId", "steps"}, "scenario")
    if scenario["schemaVersion"] != "whitehat-http-scenario-v1":
        raise ReportError("unsupported scenario")
    session = validate_session(parse_json(read_bytes(Path(session_path), 256 * 1024)))
    if scenario["projectId"] != session["projectId"]:
        raise ReportError("scenario/session project mismatch")
    steps = scenario["steps"]
    if not isinstance(steps, list) or not 1 <= len(steps) <= 20:
        raise ReportError("scenario requires 1-20 explicit steps")
    prepared = []
    seen_steps = set()
    for step in steps:
        _fields(step, {"id", "request", "identityId", "expect"}, "scenario step")
        label(step["id"], "step")
        if step["id"] in seen_steps:
            raise ReportError("duplicate scenario step id")
        seen_steps.add(step["id"])
        request_path = path.resolve().parent / relative_path(step["request"])
        try:
            request_path.resolve(strict=True).relative_to(path.resolve().parent)
        except (OSError, ValueError) as exc:
            raise ReportError("scenario request escapes its directory") from exc
        request = prepared_request(parse_json(read_bytes(request_path, 128 * 1024)))
        if digest(request) not in session["requestSha256"]:
            raise ReportError("scenario includes a request outside the session")
        request_url = urlsplit(request["url"])
        if origin(f"{request_url.scheme}://{request_url.netloc}") != session["origin"]:
            raise ReportError("scenario request origin differs from its session")
        if (
            request["method"] in {"POST", "PUT", "PATCH", "DELETE"}
            and not session["allowMutation"]
        ):
            raise ReportError("scenario mutation is not enabled by the session")
        profiles = [p for p in session["identities"] if p["id"] == step["identityId"]]
        if len(profiles) != 1:
            raise ReportError("scenario identity is not in the session")
        _credential(profiles[0])
        expectation = _fields(
            step["expect"], {"status", "values", "absent"}, "state expectation"
        )
        _integer(expectation["status"], "expected status", 100, 599)
        if not isinstance(expectation["values"], dict):
            raise ReportError("expected values must be an object")
        if not isinstance(expectation["absent"], list):
            raise ReportError("absent pointers must be an array")
        selectors = pointers(list(expectation["values"]) + expectation["absent"])
        if any(p not in session["responsePointers"] for p in selectors):
            raise ReportError("scenario expectation was not selected for evidence")
        if any(isinstance(v, (dict, list)) for v in expectation["values"].values()):
            raise ReportError("state expectations must use scalars")
        prepared.append((step, str(request_path)))
    records, results = [], []
    for step, request_path in prepared:
        if records and session["budgets"]["minDelayMs"]:
            time.sleep(session["budgets"]["minDelayMs"] / 1000)
        result = replay(session_path, request_path, step["identityId"], state_path)
        entry = result["exchanges"][0]
        records.append(entry)
        expected = step["expect"]
        values = entry["response"]["json"]["values"]
        passed = (
            entry["response"]["status"] == expected["status"]
            and (
                not expected["values"]
                and not expected["absent"]
                or entry["response"]["json"]["parsed"]
            )
            and all(
                k in values and values[k] == v for k, v in expected["values"].items()
            )
            and all(k not in values for k in expected["absent"])
        )
        results.append(
            {
                "stepId": step["id"],
                "outcome": "consistent" if passed else "mismatch",
                "evidenceSha256": entry["evidenceSha256"],
            }
        )
        if not passed:
            stop_session(session_path, state_path)
            break
    return evidence_document(
        session["projectId"],
        records,
        {
            "kind": "replay",
            "profile": "explicit-scenario",
            "sessionSha256": digest(session),
            "scenarioSha256": digest(scenario),
            "evaluations": results,
            "plannedSteps": len(prepared),
            "executedSteps": len(records),
            "executionVerified": True,
        },
    )
