"""Prepare concrete request artifacts without sending or approving them."""

from __future__ import annotations

import copy
import hashlib
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from .evidence_links import contained_path, fields, sha256
from .http_evidence import (
    capture_entries,
    digest,
    import_capture,
    label,
    load_evidence,
    pointers,
)
from .http_replay import REQUEST_SCHEMA, SESSION_SCHEMA, origin, prepared_request
from .records import RecordError, write_json_document
from .reports import ReportError, endpoint, parse_json, read_bytes, seal

_SENSITIVE = re.compile(
    r"token|password|passwd|secret|authorization|cookie|credential|private.?key|api.?key|csrf|xsrf|session",
    re.I,
)
_TRANSPORT = {
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "accept-encoding",
    "te",
    "trailer",
    "upgrade",
}


def _write_bundle(directory: str, documents: dict[str, dict]) -> None:
    root = Path(directory)
    if root.exists() or root.is_symlink():
        raise RecordError("preparation output directory already exists")
    parent = root.parent.resolve(strict=True)
    root = parent / root.name
    root.mkdir()
    try:
        for name, document in documents.items():
            write_json_document(document, root / name)
    except Exception:
        # Only remove the exact newly created files, never recursively delete.
        for name in documents:
            (root / name).unlink(missing_ok=True)
        root.rmdir()
        raise


def session_draft(
    request: dict, project: str, identity: str, auth: str = "none"
) -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    parsed = urlsplit(request["url"])
    return {
        "schemaVersion": SESSION_SCHEMA,
        "sessionId": "draft-" + digest(request)[:16],
        "projectId": label(project, "project"),
        "origin": origin(f"{parsed.scheme}://{parsed.netloc}"),
        "startsAt": now.isoformat().replace("+00:00", "Z"),
        "expiresAt": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "authority": {
            "policy": "Replace with the reviewed policy or owned-lab record",
            "reviewedAt": now.isoformat().replace("+00:00", "Z"),
            "approved": False,
            "researcherControlled": False,
        },
        "requestSha256": [digest(request)],
        "identities": [
            {
                "id": label(identity, "identity"),
                "auth": auth,
                "credentialEnv": None
                if auth == "none"
                else "WHITEHAT_CREDENTIAL_REPLACE_ME",
            }
        ],
        "responsePointers": [],
        "budgets": {
            "maxRequests": 10,
            "minDelayMs": 1000,
            "timeoutSeconds": 5,
            "maxResponseBytes": 65536,
        },
        "allowMutation": False,
    }


def _private_fields(request: dict) -> None:
    parsed = urlsplit(request["url"])
    if any(
        _SENSITIVE.search(name)
        for name, _ in parse_qsl(
            parsed.query, keep_blank_values=True, max_num_fields=100
        )
    ):
        raise ReportError("credential-like query fields require manual preparation")
    body = request["body"]
    if body is None:
        return
    media = next(
        (
            v.split(";", 1)[0].strip().lower()
            for k, v in request["headers"].items()
            if k.lower() == "content-type"
        ),
        "",
    )
    if media == "application/json" or media.endswith("+json"):
        value = parse_json(body.encode("utf-8"))

        def inspect(node, depth=0):
            if depth > 16:
                raise ReportError("prepared JSON depth limit exceeded")
            if isinstance(node, dict):
                for key, item in node.items():
                    if _SENSITIVE.search(key):
                        raise ReportError(
                            "credential-like body fields require manual preparation"
                        )
                    inspect(item, depth + 1)
            elif isinstance(node, list):
                for item in node:
                    inspect(item, depth + 1)

        inspect(value)
    elif media == "application/x-www-form-urlencoded":
        if any(
            _SENSITIVE.search(k)
            for k, _ in parse_qsl(body, keep_blank_values=True, max_num_fields=100)
        ):
            raise ReportError("credential-like form fields require manual preparation")
    else:
        raise ReportError(
            "capture preparation supports captured JSON or form text bodies"
        )


def prepare_capture(
    path: str,
    directory: str,
    project: str,
    *,
    index: int = 0,
    identity: str = "researcher",
    object_id: str = "object",
    operation: str = "operation",
    format_name: str = "har",
) -> dict:
    raw = read_bytes(Path(path))
    entries = capture_entries(raw, format_name)
    # Validate the whole archive before creating artifacts. No malformed entries are salvaged.
    checked = import_capture(path, project, format_name=format_name)
    if checked["provenance"]["captureSha256"] != hashlib.sha256(raw).hexdigest():
        raise ReportError("capture changed during preparation")
    if type(index) is not int or not 0 <= index < len(entries):
        raise ReportError("capture entry index out of range")
    captured = entries[index]["request"]
    headers, diagnostics, credentials, auth = {}, [], [], "none"
    seen = set()
    for header in captured.get("headers", []):
        name, value = header["name"].lower(), header.get("value")
        if not isinstance(value, str) or any(ord(c) < 32 for c in value):
            raise ReportError("invalid captured header value")
        if name in seen:
            raise ReportError("duplicate captured headers require manual preparation")
        seen.add(name)
        if name in {"authorization", "cookie"}:
            if auth != "none":
                raise ReportError(
                    "combined credential mechanisms require manual preparation"
                )
            if name == "authorization":
                if not value.lower().startswith("bearer ") or not value[7:].strip():
                    raise ReportError(
                        "only bearer and cookie credential references are supported"
                    )
                credentials.append(value[7:])
                auth = "bearer"
            else:
                auth = "cookie"
                credentials.extend(
                    part.partition("=")[2] for part in value.split(";") if "=" in part
                )
            diagnostics.append(
                {"code": "credential-reference-required", "header": name}
            )
        elif _SENSITIVE.search(name) or name.startswith("proxy-"):
            raise ReportError(
                "unsupported credential/proxy header requires manual preparation"
            )
        elif name in _TRANSPORT or name.startswith(":"):
            diagnostics.append({"code": "transport-header-omitted", "header": name})
        else:
            headers[header["name"]] = value
    posted = captured.get("postData")
    body = None
    if posted is not None:
        if (
            not isinstance(posted.get("text"), str)
            or posted.get("encoding") is not None
        ):
            raise ReportError(
                "captured request body is missing or encoded; manual preparation required"
            )
        body = posted["text"]
        if not any(k.lower() == "content-type" for k in headers) and posted.get(
            "mimeType"
        ):
            headers["Content-Type"] = posted["mimeType"]
    elif captured.get("bodySize", 0) not in (0, -1):
        raise ReportError("request body was not captured")
    request = prepared_request(
        {
            "schemaVersion": REQUEST_SCHEMA,
            "method": captured["method"],
            "url": captured["url"],
            "headers": headers,
            "body": body,
            "objectId": object_id,
            "operationId": operation,
        }
    )
    _private_fields(request)
    from .reports import canonical

    content = canonical(request).decode("utf-8")
    if any(secret and secret in content for secret in credentials):
        raise ReportError("captured credential also occurs in retained request data")
    draft = session_draft(request, project, identity, auth)
    receipt = seal(
        {
            "schemaVersion": "whitehat-preparation-v1",
            "ok": True,
            "projectId": project,
            "requestSha256": digest(request),
            "method": request["method"],
            "endpoint": endpoint(request["url"]),
            "source": {
                "captureSha256": checked["provenance"]["captureSha256"],
                "entryIndex": index,
            },
            "diagnostics": diagnostics,
            "files": ["request.json", "session.draft.json", "receipt.json"],
            "effects": {
                "network": False,
                "filesystemWrite": True,
                "sessionApproved": False,
            },
        }
    )
    _write_bundle(
        directory,
        {"request.json": request, "session.draft.json": draft, "receipt.json": receipt},
    )
    return receipt


def bind_request(plan_path: str, directory: str) -> dict:
    path = Path(plan_path)
    plan = fields(
        parse_json(read_bytes(path, 64 * 1024)),
        {
            "schemaVersion",
            "projectId",
            "source",
            "request",
            "pathSegment",
            "expectedSegment",
        },
        "binding plan",
    )
    if plan["schemaVersion"] != "whitehat-request-binding-v1":
        raise ReportError("unsupported binding plan")
    source = fields(
        plan["source"],
        {"path", "resultSha256", "evidenceSha256", "pointer", "identityId", "objectId"},
        "binding source",
    )
    target = fields(plan["request"], {"path", "requestSha256"}, "binding request")
    evidence = load_evidence(str(contained_path(path.parent, source["path"])))
    if evidence["resultSha256"] != sha256(source["resultSha256"]) or evidence[
        "projectId"
    ] != label(plan["projectId"], "project"):
        raise ReportError("binding source hash/project mismatch")
    matches = [
        e
        for e in evidence["exchanges"]
        if e["evidenceSha256"] == sha256(source["evidenceSha256"])
    ]
    if len(matches) != 1:
        raise ReportError("binding needs one exact source exchange")
    entry = matches[0]
    for name in ("identityId", "objectId"):
        if (
            entry["context"][name] != label(source[name], name)
            or source[name] == "unlabeled"
        ):
            raise ReportError("binding source identity/object mismatch")
    pointer = pointers([source["pointer"]])[0]
    response = entry["response"]
    if not response["bodyCaptured"] or not response["json"]["parsed"]:
        raise ReportError("binding requires a captured parsed response")
    value = response["json"]["values"].get(pointer)
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}", value
    ):
        raise ReportError("binding requires a selected ordinary string ID")
    request = prepared_request(
        parse_json(read_bytes(contained_path(path.parent, target["path"]), 128 * 1024))
    )
    if digest(request) != sha256(target["requestSha256"]):
        raise ReportError("binding request hash mismatch")
    parsed = urlsplit(request["url"])
    source_url = urlsplit(entry["context"]["endpoint"])
    if (parsed.scheme, parsed.netloc) != (source_url.scheme, source_url.netloc):
        raise ReportError("binding source and request origins differ")
    segments = parsed.path.split("/")
    slot = plan["pathSegment"]
    if (
        type(slot) is not int
        or not 1 <= slot < len(segments)
        or segments[slot] != plan["expectedSegment"]
    ):
        raise ReportError("binding segment index or expected content differs")
    label(plan["expectedSegment"], "expected segment")
    bound = copy.deepcopy(request)
    segments[slot] = value
    bound["url"] = urlunsplit(
        (parsed.scheme, parsed.netloc, "/".join(segments), parsed.query, "")
    )
    prepared_request(bound)
    receipt = seal(
        {
            "schemaVersion": "whitehat-preparation-v1",
            "ok": True,
            "projectId": plan["projectId"],
            "requestSha256": digest(bound),
            "method": bound["method"],
            "endpoint": endpoint(bound["url"]),
            "source": {
                "planSha256": digest(plan),
                "requestSha256": digest(request),
                "resultSha256": evidence["resultSha256"],
                "evidenceSha256": entry["evidenceSha256"],
                "pointer": pointer,
                "pathSegment": slot,
            },
            "diagnostics": [{"code": "new-request-needs-session-review"}],
            "files": ["request.json", "receipt.json"],
            "effects": {
                "network": False,
                "filesystemWrite": True,
                "sessionApproved": False,
            },
        }
    )
    _write_bundle(directory, {"request.json": bound, "receipt.json": receipt})
    return receipt
