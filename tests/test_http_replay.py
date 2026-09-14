import copy
import json
import os
import ssl
import socket
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from whitehat.api_fixture import owned_api
from whitehat.http_evidence import digest
from whitehat.http_replay import (
    SESSION_SCHEMA,
    REQUEST_SCHEMA,
    _resolve,
    replay,
    stop_session,
    validate_session,
    run_scenario,
)
from whitehat.network_engine import NetworkExecutionLimitError
from whitehat.reports import ReportError


def session_for(origin, requests, *, maximum=10):
    now = datetime.now(timezone.utc).replace(microsecond=0)

    def stamp(t):
        return t.isoformat().replace("+00:00", "Z")

    return {
        "schemaVersion": SESSION_SCHEMA,
        "sessionId": "owned-session",
        "projectId": "owned-api",
        "origin": origin,
        "startsAt": stamp(now),
        "expiresAt": stamp(now + timedelta(minutes=5)),
        "authority": {
            "policy": "Owned fixture",
            "reviewedAt": stamp(now),
            "approved": True,
            "researcherControlled": True,
        },
        "requestSha256": [digest(r) for r in requests],
        "identities": [
            {
                "id": "alice",
                "auth": "bearer",
                "credentialEnv": "WHITEHAT_CREDENTIAL_ALICE",
            },
            {"id": "bob", "auth": "bearer", "credentialEnv": "WHITEHAT_CREDENTIAL_BOB"},
            {
                "id": "revoked",
                "auth": "bearer",
                "credentialEnv": "WHITEHAT_CREDENTIAL_REVOKED",
            },
        ],
        "responsePointers": ["/marker"],
        "budgets": {
            "maxRequests": maximum,
            "minDelayMs": 0,
            "timeoutSeconds": 2,
            "maxResponseBytes": 8192,
        },
        "allowMutation": False,
    }


def request_for(origin, path="/objects/private-a"):
    return {
        "schemaVersion": REQUEST_SCHEMA,
        "method": "GET",
        "url": origin + path,
        "headers": {},
        "body": None,
        "objectId": "private-a",
        "operationId": "read-object",
    }


class ReplayTests(unittest.TestCase):
    def test_https_pins_connection_address_but_verifies_original_hostname(self):
        try:
            import trustme
        except ImportError:
            self.skipTest("install the test-tls extra")
        authority = trustme.CA()
        certificate = authority.issue_cert("owned.example.invalid")
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        certificate.configure_cert(server_context)
        client_context = ssl.create_default_context()
        authority.configure_trust(client_context)
        original_connect = socket.create_connection
        with (
            owned_api(tls=server_context) as (local_origin, state),
            tempfile.TemporaryDirectory() as temporary,
            patch.dict(os.environ, {"WHITEHAT_CREDENTIAL_ALICE": "owned-alice"}),
        ):
            root = Path(temporary)
            local_port = int(local_origin.rsplit(":", 1)[1])

            def mapped_connection(address, timeout):
                self.assertEqual(address, ("93.184.216.34", local_port))
                return original_connect(("127.0.0.1", local_port), timeout=timeout)

            for hostname, accepted in (
                ("owned.example.invalid", True),
                ("wrong.example.invalid", False),
            ):
                remote_origin = f"https://{hostname}:{local_port}"
                request = request_for(remote_origin)
                session = session_for(remote_origin, [request])
                (root / "request.json").write_text(json.dumps(request))
                (root / "session.json").write_text(json.dumps(session))
                with (
                    patch(
                        "whitehat.http_replay._resolve", return_value="93.184.216.34"
                    ),
                    patch(
                        "whitehat.http_replay.socket.create_connection",
                        side_effect=mapped_connection,
                    ),
                    patch(
                        "whitehat.http_replay.ssl.create_default_context",
                        return_value=client_context,
                    ),
                ):
                    if accepted:
                        result = replay(
                            str(root / "session.json"),
                            str(root / "request.json"),
                            "alice",
                            str(root / (hostname + ".sqlite3")),
                        )
                        self.assertEqual(
                            result["exchanges"][0]["response"]["status"], 200
                        )
                    else:
                        with self.assertRaises(ReportError):
                            replay(
                                str(root / "session.json"),
                                str(root / "request.json"),
                                "alice",
                                str(root / (hostname + ".sqlite3")),
                            )
            self.assertEqual(state["requests"], 1)

    def test_actual_tls_certificate_verification_before_credentials(self):
        try:
            import trustme
        except ImportError:
            self.skipTest("install the test-tls extra")
        authority = trustme.CA()
        certificate = authority.issue_cert("127.0.0.1")
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        certificate.configure_cert(server_context)
        client_context = ssl.create_default_context()
        authority.configure_trust(client_context)
        with (
            owned_api(tls=server_context) as (origin, state),
            tempfile.TemporaryDirectory() as temp,
            patch.dict(os.environ, {"WHITEHAT_CREDENTIAL_ALICE": "owned-alice"}),
        ):
            root = Path(temp)
            request = request_for(origin)
            session = session_for(origin, [request])
            (root / "request.json").write_text(json.dumps(request))
            (root / "session.json").write_text(json.dumps(session))
            with self.assertRaises(ReportError):
                replay(
                    str(root / "session.json"),
                    str(root / "request.json"),
                    "alice",
                    str(root / "untrusted.sqlite3"),
                )
            self.assertEqual(state["requests"], 0)
            with patch(
                "whitehat.http_replay.ssl.create_default_context",
                return_value=client_context,
            ):
                result = replay(
                    str(root / "session.json"),
                    str(root / "request.json"),
                    "alice",
                    str(root / "trusted.sqlite3"),
                )
            self.assertEqual(result["exchanges"][0]["response"]["status"], 200)
            self.assertEqual(state["requests"], 1)

    def test_explicit_lifecycle_detects_broken_delete(self):
        for vulnerable in (False, True):
            with (
                owned_api(vulnerable=vulnerable) as (origin, _),
                tempfile.TemporaryDirectory() as temp,
                patch.dict(os.environ, {"WHITEHAT_CREDENTIAL_ALICE": "owned-alice"}),
            ):
                root = Path(temp)
                requests = []
                steps = []
                for i, (method, path, status, marker) in enumerate(
                    (
                        ("POST", "/items", 201, "owned-item"),
                        ("DELETE", "/items/demo", 200, None),
                        ("GET", "/items/demo", 404, None),
                    )
                ):
                    request = request_for(origin, path)
                    request.update(
                        method=method, operationId=f"step-{i}", objectId="owned-item"
                    )
                    requests.append(request)
                    (root / f"request-{i}.json").write_text(json.dumps(request))
                    steps.append(
                        {
                            "id": f"step-{i}",
                            "request": f"request-{i}.json",
                            "identityId": "alice",
                            "expect": {
                                "status": status,
                                "values": {"/marker": marker} if marker else {},
                                "absent": [] if marker else ["/marker"],
                            },
                        }
                    )
                session = session_for(origin, requests)
                session["allowMutation"] = True
                (root / "session.json").write_text(json.dumps(session))
                (root / "scenario.json").write_text(
                    json.dumps(
                        {
                            "schemaVersion": "whitehat-http-scenario-v1",
                            "projectId": "owned-api",
                            "steps": steps,
                        }
                    )
                )
                result = run_scenario(
                    str(root / "scenario.json"),
                    str(root / "session.json"),
                    str(root / "ledger.sqlite3"),
                )
                self.assertEqual(
                    result["provenance"]["evaluations"][-1]["outcome"],
                    "mismatch" if vulnerable else "consistent",
                )

    def test_actual_two_identity_and_revoked_controls_and_restart_budget(self):
        for vulnerable in (False, True):
            with (
                self.subTest(vulnerable=vulnerable),
                owned_api(vulnerable=vulnerable) as (origin, state),
                tempfile.TemporaryDirectory() as temp,
            ):
                root = Path(temp)
                request = request_for(origin)
                session = session_for(origin, [request], maximum=3)
                (root / "request.json").write_text(json.dumps(request))
                (root / "session.json").write_text(json.dumps(session))
                env = {
                    "WHITEHAT_CREDENTIAL_ALICE": "owned-alice",
                    "WHITEHAT_CREDENTIAL_BOB": "owned-bob",
                    "WHITEHAT_CREDENTIAL_REVOKED": "expired",
                }
                with patch.dict(os.environ, env):
                    results = [
                        replay(
                            str(root / "session.json"),
                            str(root / "request.json"),
                            identity,
                            str(root / "ledger.sqlite3"),
                        )
                        for identity in ("alice", "bob", "revoked")
                    ]
                    self.assertEqual(
                        [r["exchanges"][0]["response"]["status"] for r in results],
                        [200, 200 if vulnerable else 403, 401],
                    )
                    self.assertNotIn("owned-alice", json.dumps(results))
                    with self.assertRaises(NetworkExecutionLimitError):
                        replay(
                            str(root / "session.json"),
                            str(root / "request.json"),
                            "alice",
                            str(root / "ledger.sqlite3"),
                        )
                self.assertEqual(state["requests"], 3)

    def test_changed_request_rejected_before_state_or_transport(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            request = request_for("https://owned.example.invalid")
            session = session_for("https://owned.example.invalid", [request])
            request["url"] += "/different"
            (root / "request.json").write_text(json.dumps(request))
            (root / "session.json").write_text(json.dumps(session))
            with (
                patch("whitehat.http_replay._send") as send,
                self.assertRaises(ReportError),
            ):
                replay(
                    str(root / "session.json"),
                    str(root / "request.json"),
                    "alice",
                    str(root / "ledger.sqlite3"),
                )
            send.assert_not_called()
            self.assertFalse((root / "ledger.sqlite3").exists())

    def test_edit_cannot_reset_existing_ledger(self):
        with (
            owned_api() as (origin, _),
            tempfile.TemporaryDirectory() as temp,
            patch.dict(os.environ, {"WHITEHAT_CREDENTIAL_ALICE": "owned-alice"}),
        ):
            root = Path(temp)
            request = request_for(origin)
            session = session_for(origin, [request])
            (root / "request.json").write_text(json.dumps(request))
            (root / "session.json").write_text(json.dumps(session))
            replay(
                str(root / "session.json"),
                str(root / "request.json"),
                "alice",
                str(root / "ledger.sqlite3"),
            )
            session["budgets"]["maxRequests"] += 1
            (root / "session.json").write_text(json.dumps(session))
            with self.assertRaisesRegex(ReportError, "different session"):
                replay(
                    str(root / "session.json"),
                    str(root / "request.json"),
                    "alice",
                    str(root / "ledger.sqlite3"),
                )

    def test_nonpublic_addresses_expiry_and_credential_reference_fail_closed(self):
        with self.assertRaises(ReportError):
            _resolve("169.254.169.254", 443, 1)
        value = session_for(
            "https://owned.example.invalid",
            [request_for("https://owned.example.invalid")],
        )
        invalid = copy.deepcopy(value)
        invalid["identities"][0]["credentialEnv"] = "HOME"
        with self.assertRaises(ReportError):
            validate_session(invalid)
        invalid = copy.deepcopy(value)
        invalid["expiresAt"] = invalid["startsAt"]
        with self.assertRaises(ReportError):
            validate_session(invalid)

    def test_redirect_and_rate_limit_stop_without_followup(self):
        for path in ("/redirect", "/rate-limit"):
            with (
                owned_api() as (origin, state),
                tempfile.TemporaryDirectory() as temp,
                patch.dict(os.environ, {"WHITEHAT_CREDENTIAL_ALICE": "owned-alice"}),
            ):
                root = Path(temp)
                request = request_for(origin, path)
                session = session_for(origin, [request])
                (root / "request.json").write_text(json.dumps(request))
                (root / "session.json").write_text(json.dumps(session))
                result = replay(
                    str(root / "session.json"),
                    str(root / "request.json"),
                    "alice",
                    str(root / "ledger.sqlite3"),
                )
                self.assertIn(
                    result["provenance"]["outcome"],
                    {"redirect-rejected", "rate-limited"},
                )
                stop_session(str(root / "session.json"), str(root / "ledger.sqlite3"))
                self.assertEqual(state["requests"], 1)


if __name__ == "__main__":
    unittest.main()
