from __future__ import annotations

import hashlib
import http.client
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .network_session import (
    NetworkSessionError,
    load_network_session_document,
    validate_network_session,
)


class NetworkExecutionError(Exception):
    """Owned-loopback execution could not satisfy the session boundary."""

    exit_code = 3
    error_code = "network-execution-failed"


class NetworkExecutionLimitError(NetworkExecutionError):
    exit_code = 4
    error_code = "limit-exceeded"


@dataclass(frozen=True)
class Reservation:
    sequence: int
    attempted_requests: int


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _utc_now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise NetworkExecutionError("network execution clock must include a timezone")
    return current.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _state_path(value: str | os.PathLike[str]) -> Path:
    path = Path(value)
    if path.is_symlink():
        raise NetworkExecutionError("network state path must not be a symbolic link")
    try:
        parent = path.parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise NetworkExecutionError(
            f"network state parent is unavailable: {exc}"
        ) from exc
    if not parent.is_dir():
        raise NetworkExecutionError("network state parent must be a directory")
    destination = parent / path.name
    if destination.exists() and not destination.is_file():
        raise NetworkExecutionError("network state must be a regular file")
    return destination


def _connect(path: Path) -> sqlite3.Connection:
    try:
        connection = sqlite3.connect(path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS session_state (
                session_sha256 TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                max_requests INTEGER NOT NULL,
                max_concurrency INTEGER NOT NULL,
                attempted_requests INTEGER NOT NULL DEFAULT 0,
                active_requests INTEGER NOT NULL DEFAULT 0,
                last_started_at TEXT,
                stopped INTEGER NOT NULL DEFAULT 0,
                stop_reason TEXT
            );
            CREATE TABLE IF NOT EXISTS requests (
                session_sha256 TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                method TEXT NOT NULL,
                target TEXT NOT NULL,
                path TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome TEXT,
                response_status INTEGER,
                response_bytes INTEGER,
                PRIMARY KEY (session_sha256, sequence),
                FOREIGN KEY (session_sha256) REFERENCES session_state(session_sha256)
            );
            """
        )
    except sqlite3.Error as exc:
        raise NetworkExecutionError(
            f"network state could not be initialized: {exc}"
        ) from exc
    return connection


def _ensure_state(
    connection: sqlite3.Connection,
    session_sha256: str,
    session: dict[str, Any],
) -> sqlite3.Row:
    budgets = session["budgets"]
    connection.execute(
        """
        INSERT OR IGNORE INTO session_state (
            session_sha256, session_id, max_requests, max_concurrency
        ) VALUES (?, ?, ?, ?)
        """,
        (
            session_sha256,
            session["sessionId"],
            budgets["maxRequests"],
            budgets["maxConcurrency"],
        ),
    )
    row = connection.execute(
        "SELECT * FROM session_state WHERE session_sha256 = ?",
        (session_sha256,),
    ).fetchone()
    if row is None:
        raise NetworkExecutionError("network session state is unavailable")
    if (
        row["session_id"] != session["sessionId"]
        or row["max_requests"] != budgets["maxRequests"]
        or row["max_concurrency"] != budgets["maxConcurrency"]
    ):
        raise NetworkExecutionError("network state does not match the session contract")
    return row


def _reserve_request(
    state: Path,
    session_sha256: str,
    session: dict[str, Any],
    method: str,
    target: str,
    path: str,
    now: datetime,
    *,
    batch_owner: str | None = None,
) -> Reservation:
    connection = _connect(state)
    try:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='fuzz_execution'"
        ).fetchone():
            claim = connection.execute(
                "SELECT owner, active FROM fuzz_execution WHERE id=1"
            ).fetchone()
            if claim and claim["active"] and claim["owner"] != batch_owner:
                raise NetworkExecutionError(
                    "a fuzz batch owns this ledger; independent replay cannot interleave"
                )
        row = _ensure_state(connection, session_sha256, session)
        budgets = session["budgets"]
        if row["stopped"]:
            raise NetworkExecutionError(
                f"network session is stopped: {row['stop_reason'] or 'unspecified'}"
            )
        if row["attempted_requests"] >= row["max_requests"]:
            raise NetworkExecutionLimitError("network request budget exhausted")
        if row["active_requests"] >= row["max_concurrency"]:
            raise NetworkExecutionLimitError("network concurrency budget exhausted")
        if row["last_started_at"]:
            last_started = datetime.fromisoformat(
                row["last_started_at"].replace("Z", "+00:00")
            )
            elapsed_ms = (now - last_started).total_seconds() * 1000
            if elapsed_ms < budgets["minDelayMs"]:
                raise NetworkExecutionLimitError(
                    "network inter-request delay is not satisfied"
                )
        sequence = row["attempted_requests"] + 1
        connection.execute(
            """
            INSERT INTO requests (
                session_sha256, sequence, method, target, path, status, started_at
            ) VALUES (?, ?, ?, ?, ?, 'reserved', ?)
            """,
            (session_sha256, sequence, method, target, path, _iso(now)),
        )
        connection.execute(
            """
            UPDATE session_state
            SET attempted_requests = ?, active_requests = active_requests + 1,
                last_started_at = ?
            WHERE session_sha256 = ?
            """,
            (sequence, _iso(now), session_sha256),
        )
        connection.execute("COMMIT")
        return Reservation(sequence=sequence, attempted_requests=sequence)
    except (NetworkExecutionError, NetworkExecutionLimitError):
        connection.execute("ROLLBACK")
        raise
    except (sqlite3.Error, ValueError) as exc:
        connection.execute("ROLLBACK")
        raise NetworkExecutionError(
            f"network request reservation failed: {exc}"
        ) from exc
    finally:
        connection.close()


def _complete_request(
    state: Path,
    session_sha256: str,
    sequence: int,
    now: datetime,
    outcome: str,
    response_status: int | None,
    response_bytes: int | None,
    stop_reason: str | None = None,
) -> dict[str, Any]:
    connection = _connect(state)
    try:
        connection.execute("BEGIN IMMEDIATE")
        updated = connection.execute(
            """
            UPDATE requests
            SET status = 'completed', completed_at = ?, outcome = ?,
                response_status = ?, response_bytes = ?
            WHERE session_sha256 = ? AND sequence = ? AND status = 'reserved'
            """,
            (
                _iso(now),
                outcome,
                response_status,
                response_bytes,
                session_sha256,
                sequence,
            ),
        )
        if updated.rowcount != 1:
            raise NetworkExecutionError("network request reservation is not active")
        connection.execute(
            """
            UPDATE session_state
            SET active_requests = active_requests - 1,
                stopped = CASE WHEN ? IS NULL THEN stopped ELSE 1 END,
                stop_reason = COALESCE(?, stop_reason)
            WHERE session_sha256 = ?
            """,
            (stop_reason, stop_reason, session_sha256),
        )
        row = connection.execute(
            "SELECT * FROM session_state WHERE session_sha256 = ?",
            (session_sha256,),
        ).fetchone()
        connection.execute("COMMIT")
    except NetworkExecutionError:
        connection.execute("ROLLBACK")
        raise
    except sqlite3.Error as exc:
        connection.execute("ROLLBACK")
        raise NetworkExecutionError(
            f"network request completion failed: {exc}"
        ) from exc
    finally:
        connection.close()
    if row is None:
        raise NetworkExecutionError("network session state disappeared")
    return {
        "attemptedRequests": row["attempted_requests"],
        "remainingRequests": row["max_requests"] - row["attempted_requests"],
        "activeRequests": row["active_requests"],
        "stopped": bool(row["stopped"]),
        "stopReason": row["stop_reason"],
    }


def _mark_transport_failure(
    state: Path,
    session_sha256: str,
    sequence: int,
    now: datetime,
) -> None:
    _complete_request(
        state,
        session_sha256,
        sequence,
        now,
        "transport-error",
        None,
        None,
    )


def _request_path(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or "\\" in value
        or "?" in value
        or "#" in value
        or any(ord(character) > 127 for character in value)
        or any(part == ".." for part in value.split("/"))
    ):
        raise NetworkExecutionError("loopback request path is invalid")
    return value


def _path_matches(path: str, prefix: str) -> bool:
    if prefix == "/":
        return True
    normalized = prefix.rstrip("/")
    return path == normalized or path.startswith(normalized + "/")


def _target_for_path(session: dict[str, Any], path: str) -> dict[str, Any]:
    matches = [
        target
        for target in session["targets"]
        if target["host"] == "127.0.0.1"
        and target["scheme"] == "http"
        and "GET" in target["methods"]
        and any(_path_matches(path, prefix) for prefix in target["pathPrefixes"])
    ]
    if len(matches) != 1:
        raise NetworkExecutionError(
            "loopback request path does not match one exact target"
        )
    return matches[0]


def _request_size(path: str, port: int) -> int:
    headers = {
        "Accept": "*/*",
        "Connection": "close",
        "Host": f"127.0.0.1:{port}",
        "User-Agent": "Whitehat/0.8 loopback-observer",
    }
    request = f"GET {path} HTTP/1.1\r\n" + "".join(
        f"{name}: {value}\r\n" for name, value in headers.items()
    )
    return len((request + "\r\n").encode("ascii"))


def _content_type(value: str | None) -> str | None:
    if value is None:
        return None
    sanitized = "".join(character for character in value if 32 <= ord(character) <= 126)
    return sanitized[:128]


def execute_loopback_observation(
    session_path: str | os.PathLike[str],
    state_path: str | os.PathLike[str],
    request_path: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = _utc_now(now)
    session = load_network_session_document(session_path)
    try:
        validation = validate_network_session(session, current)
    except NetworkSessionError as exc:
        raise NetworkExecutionError(str(exc)) from exc
    if session["mode"] != "owned-loopback":
        raise NetworkExecutionError(
            "network execution supports owned-loopback sessions only"
        )
    path = _request_path(request_path)
    target = _target_for_path(session, path)
    budgets = session["budgets"]
    if _request_size(path, target["port"]) > budgets["maxRequestBytes"]:
        raise NetworkExecutionLimitError("loopback request byte limit exceeded")
    valid_from = datetime.fromisoformat(session["validFrom"].replace("Z", "+00:00"))
    if (current - valid_from).total_seconds() > budgets["maxWallSeconds"]:
        raise NetworkExecutionLimitError("network session wall-time budget exhausted")

    state = _state_path(state_path)
    target_text = f"http://127.0.0.1:{target['port']}"
    reservation = _reserve_request(
        state,
        validation["sessionSha256"],
        session,
        "GET",
        target_text,
        path,
        current,
    )
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        target["port"],
        timeout=budgets["requestTimeoutSeconds"],
    )
    try:
        connection.request(
            "GET",
            path,
            body=None,
            headers={
                "Accept": "*/*",
                "Connection": "close",
                "User-Agent": "Whitehat/0.8 loopback-observer",
            },
        )
        response = connection.getresponse()
        raw = response.read(budgets["maxResponseBytes"] + 1)
        complete = len(raw) <= budgets["maxResponseBytes"]
        retained = raw[: budgets["maxResponseBytes"]]
        status = response.status
        if status == 429:
            outcome = "rate-limited"
            stop_reason = "rate-limited"
        elif 300 <= status < 400:
            outcome = "unexpected-redirect"
            stop_reason = "unexpected-redirect"
        elif complete:
            outcome = "complete"
            stop_reason = None
        else:
            outcome = "response-limit-exceeded"
            stop_reason = None
        ledger = _complete_request(
            state,
            validation["sessionSha256"],
            reservation.sequence,
            _utc_now(),
            outcome,
            status,
            len(retained),
            stop_reason,
        )
    except (OSError, http.client.HTTPException) as exc:
        _mark_transport_failure(
            state,
            validation["sessionSha256"],
            reservation.sequence,
            _utc_now(),
        )
        raise NetworkExecutionError(
            "owned-loopback request failed without retry"
        ) from exc
    finally:
        connection.close()

    result: dict[str, Any] = {
        "schemaVersion": "whitehat-loopback-observation-v1",
        "ok": True,
        "sessionId": session["sessionId"],
        "sessionSha256": validation["sessionSha256"],
        "request": {
            "sequence": reservation.sequence,
            "method": "GET",
            "origin": target_text,
            "path": path,
        },
        "response": {
            "status": status,
            "bytesRead": len(retained),
            "complete": complete,
            "bodySha256": hashlib.sha256(retained).hexdigest() if complete else None,
            "contentType": _content_type(response.getheader("Content-Type")),
            "outcome": outcome,
        },
        "ledger": ledger,
        "claims": {
            "externalNetworkAuthorized": False,
            "findingValidityEstablished": False,
            "impactEstablished": False,
            "legalAuthorityEstablished": False,
            "severityEstablished": False,
            "submissionAuthorized": False,
        },
        "effects": {
            "credentials": False,
            "externalNetwork": False,
            "loopbackNetwork": True,
            "network": True,
            "requestBodySent": False,
            "responseBodyRetained": False,
            "targetMutation": False,
        },
    }
    result["resultSha256"] = hashlib.sha256(_canonical_json(result)).hexdigest()
    return result


def stop_loopback_session(
    session_path: str | os.PathLike[str],
    state_path: str | os.PathLike[str],
    now: datetime | None = None,
) -> dict[str, Any]:
    current = _utc_now(now)
    session = load_network_session_document(session_path)
    try:
        validation = validate_network_session(session, current)
    except NetworkSessionError as exc:
        raise NetworkExecutionError(str(exc)) from exc
    if session["mode"] != "owned-loopback":
        raise NetworkExecutionError(
            "network stop supports owned-loopback sessions only"
        )
    state = _state_path(state_path)
    connection = _connect(state)
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = _ensure_state(connection, validation["sessionSha256"], session)
        connection.execute(
            """
            UPDATE session_state
            SET stopped = 1, stop_reason = 'user-stop'
            WHERE session_sha256 = ?
            """,
            (validation["sessionSha256"],),
        )
        connection.execute("COMMIT")
    except sqlite3.Error as exc:
        connection.execute("ROLLBACK")
        raise NetworkExecutionError(f"network stop failed: {exc}") from exc
    finally:
        connection.close()
    return {
        "schemaVersion": "whitehat-loopback-stop-v1",
        "ok": True,
        "sessionId": session["sessionId"],
        "sessionSha256": validation["sessionSha256"],
        "stopped": True,
        "stopReason": "user-stop",
        "attemptedRequests": row["attempted_requests"],
        "effects": {"network": False, "stateWrite": True},
    }
