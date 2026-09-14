import json
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator

from whitehat.network_engine import (
    NetworkExecutionError,
    NetworkExecutionLimitError,
    execute_loopback_observation,
    stop_loopback_session,
)
from whitehat.network_session import validate_network_session


ROOT = Path(__file__).resolve().parents[1]


class SyntheticHandler(BaseHTTPRequestHandler):
    body = b"owned loopback response"
    response_status = 200
    request_count = 0
    observed_paths: list[str] = []

    def do_GET(self) -> None:
        type(self).request_count += 1
        type(self).observed_paths.append(self.path)
        self.send_response(type(self).response_status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        if 300 <= type(self).response_status < 400:
            self.send_header("Location", "http://example.invalid/never-followed")
        self.end_headers()
        self.wfile.write(type(self).body)

    def log_message(self, _format: str, *_arguments: object) -> None:
        return


@contextmanager
def loopback_server(
    status: int = 200,
    body: bytes = b"owned loopback response",
) -> Iterator[ThreadingHTTPServer]:
    SyntheticHandler.response_status = status
    SyntheticHandler.body = body
    SyntheticHandler.request_count = 0
    SyntheticHandler.observed_paths = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), SyntheticHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def timestamp(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def session_document(
    port: int,
    now: datetime,
    *,
    max_requests: int = 2,
    min_delay_ms: int = 0,
    max_response_bytes: int = 1024,
) -> dict[str, object]:
    return {
        "schemaVersion": "whitehat-network-session-v1",
        "sessionId": "owned-loopback-test",
        "mode": "owned-loopback",
        "validFrom": timestamp(now - timedelta(minutes=1)),
        "expiresAt": timestamp(now + timedelta(hours=1)),
        "authority": {
            "policyUrl": "https://localhost.invalid/owned-loopback-policy",
            "policyReviewedAt": timestamp(now - timedelta(minutes=10)),
            "policyExpiresAt": timestamp(now + timedelta(hours=2)),
            "approverAssertion": "test-controller",
            "approvedAt": timestamp(now - timedelta(minutes=5)),
        },
        "capabilities": ["http.observe"],
        "targets": [
            {
                "scheme": "http",
                "host": "127.0.0.1",
                "port": port,
                "pathPrefixes": ["/observe"],
                "methods": ["GET"],
            }
        ],
        "budgets": {
            "maxRequests": max_requests,
            "maxConcurrency": 1,
            "minDelayMs": min_delay_ms,
            "maxRequestBytes": 8192,
            "maxResponseBytes": max_response_bytes,
            "requestTimeoutSeconds": 2,
            "maxWallSeconds": 1800,
        },
        "transport": {
            "allowRedirects": False,
            "allowProxyEnvironment": False,
            "requireTlsVerification": False,
            "dnsPolicy": "loopback-address-only",
        },
        "effects": {
            "credentials": False,
            "targetMutation": False,
            "thirdPartyData": False,
            "contact": False,
            "submission": False,
        },
        "stopConditions": [
            "user-stop",
            "session-expired",
            "policy-expired",
            "scope-mismatch",
            "budget-exhausted",
            "rate-limited",
            "unexpected-redirect",
            "unexpected-address",
        ],
    }


def write_session(root: Path, document: dict[str, object]) -> Path:
    path = root / "session.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


class NetworkEngineTests(unittest.TestCase):
    def test_cli_loopback_result_is_storable_and_reviewable(self) -> None:
        now = datetime.now(timezone.utc)
        with loopback_server() as server, tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            session = write_session(root, session_document(server.server_port, now))
            state = root / "state.sqlite3"
            result_path = root / "observation.json"
            review_path = root / "observation.review.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "whitehat",
                    "network",
                    "observe-loopback",
                    str(session),
                    "--state",
                    str(state),
                    "--path",
                    "/observe",
                    "--output",
                    str(result_path),
                    "--json",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(
                json.loads(result_path.read_text(encoding="utf-8")), result
            )
            reviewed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "whitehat",
                    "review",
                    str(result_path),
                    "--decision",
                    "accepted",
                    "--note",
                    "Owned-loopback transport proof reviewed.",
                    "--output",
                    str(review_path),
                    "--json",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(reviewed.returncode, 0, reviewed.stderr)
            review = json.loads(reviewed.stdout)
            self.assertEqual(review["reviewOf"]["resultSha256"], result["resultSha256"])

    def test_loopback_session_validation_reports_engine_only_for_loopback(self) -> None:
        now = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)
        result = validate_network_session(session_document(8000, now), now)
        self.assertTrue(result["claims"]["networkEngineImplemented"])
        self.assertFalse(result["claims"]["networkExecutionAuthorized"])

    def test_success_is_content_free_and_budget_survives_restart(self) -> None:
        now = datetime.now(timezone.utc)
        with loopback_server() as server, tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            session = write_session(
                root,
                session_document(server.server_port, now, max_requests=1),
            )
            state = root / "state.sqlite3"
            result = execute_loopback_observation(session, state, "/observe", now)
            with self.assertRaisesRegex(NetworkExecutionLimitError, "budget exhausted"):
                execute_loopback_observation(
                    session,
                    state,
                    "/observe",
                    now + timedelta(seconds=1),
                )

        self.assertEqual(SyntheticHandler.request_count, 1)
        self.assertEqual(result["response"]["status"], 200)
        self.assertTrue(result["response"]["complete"])
        self.assertIsNotNone(result["response"]["bodySha256"])
        self.assertNotIn("owned loopback response", json.dumps(result))
        self.assertTrue(result["effects"]["loopbackNetwork"])
        self.assertFalse(result["effects"]["externalNetwork"])
        self.assertFalse(any(result["claims"].values()))

    def test_scope_mismatch_stops_before_state_and_socket(self) -> None:
        now = datetime.now(timezone.utc)
        with loopback_server() as server, tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            session = write_session(root, session_document(server.server_port, now))
            state = root / "state.sqlite3"
            with self.assertRaisesRegex(NetworkExecutionError, "does not match"):
                execute_loopback_observation(session, state, "/outside", now)
            self.assertFalse(state.exists())
        self.assertEqual(SyntheticHandler.request_count, 0)

    def test_rate_limit_and_redirect_are_monotonic_stops(self) -> None:
        for status, reason in ((429, "rate-limited"), (302, "unexpected-redirect")):
            with self.subTest(status=status), loopback_server(status=status) as server:
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    now = datetime.now(timezone.utc)
                    session = write_session(
                        root, session_document(server.server_port, now)
                    )
                    state = root / "state.sqlite3"
                    result = execute_loopback_observation(
                        session, state, "/observe", now
                    )
                    self.assertTrue(result["ledger"]["stopped"])
                    self.assertEqual(result["ledger"]["stopReason"], reason)
                    with self.assertRaisesRegex(NetworkExecutionError, "is stopped"):
                        execute_loopback_observation(
                            session,
                            state,
                            "/observe",
                            now + timedelta(seconds=1),
                        )
            self.assertEqual(SyntheticHandler.request_count, 1)

    def test_response_overflow_returns_no_body_hash(self) -> None:
        now = datetime.now(timezone.utc)
        with loopback_server(body=b"0123456789") as server:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                session = write_session(
                    root,
                    session_document(server.server_port, now, max_response_bytes=4),
                )
                result = execute_loopback_observation(
                    session,
                    root / "state.sqlite3",
                    "/observe",
                    now,
                )
        self.assertFalse(result["response"]["complete"])
        self.assertEqual(result["response"]["bytesRead"], 4)
        self.assertIsNone(result["response"]["bodySha256"])
        self.assertEqual(result["response"]["outcome"], "response-limit-exceeded")

    def test_delay_and_user_stop_block_before_request(self) -> None:
        now = datetime.now(timezone.utc)
        with loopback_server() as server, tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            session = write_session(
                root,
                session_document(server.server_port, now, min_delay_ms=1_000),
            )
            state = root / "state.sqlite3"
            execute_loopback_observation(session, state, "/observe", now)
            with self.assertRaisesRegex(NetworkExecutionLimitError, "delay"):
                execute_loopback_observation(
                    session,
                    state,
                    "/observe",
                    now + timedelta(milliseconds=100),
                )
            stopped = stop_loopback_session(
                session,
                state,
                now + timedelta(seconds=2),
            )
            self.assertTrue(stopped["stopped"])
            with self.assertRaisesRegex(NetworkExecutionError, "is stopped"):
                execute_loopback_observation(
                    session,
                    state,
                    "/observe",
                    now + timedelta(seconds=3),
                )
        self.assertEqual(SyntheticHandler.request_count, 1)


if __name__ == "__main__":
    unittest.main()
