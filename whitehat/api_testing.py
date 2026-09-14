"""Owned Schemathesis profile and deterministic lifecycle regression proof."""

from __future__ import annotations

import hashlib
import importlib.metadata
import os
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .api_fixture import owned_api
from .http_evidence import digest
from .http_replay import REQUEST_SCHEMA, SESSION_SCHEMA, run_scenario
from .reports import ReportError, canonical, observation, parse_json, result_document
from .runner import ProcessLimits, execute_fixed_profile

SCHEMATHESIS_VERSION = "4.27.1"


def test_owned_api(vulnerable: bool = False) -> dict[str, Any]:
    try:
        distribution = importlib.metadata.distribution("schemathesis")
    except importlib.metadata.PackageNotFoundError as exc:
        raise ReportError(
            "install the api-test extra before running the owned API profile"
        ) from exc
    if distribution.version != SCHEMATHESIS_VERSION:
        raise ReportError(f"Schemathesis must be exactly {SCHEMATHESIS_VERSION}")
    record = distribution.read_text("RECORD")
    if not record:
        raise ReportError("Schemathesis distribution identity unavailable")
    with (
        owned_api(vulnerable=vulnerable) as (origin, state),
        tempfile.TemporaryDirectory(prefix="whitehat-api-proof-") as temporary,
    ):
        execution = execute_fixed_profile(
            profile="api.schemathesis.owned",
            executable=sys.executable,
            arguments=[
                "-I",
                "-B",
                str(Path(__file__).with_name("schemathesis_worker.py")),
            ],
            input_bytes=canonical({"origin": origin, "nonce": state["nonce"]}),
            limits=ProcessLimits(
                timeout_seconds=20,
                max_input_bytes=2048,
                max_stdout_bytes=4 * 1024 * 1024,
                max_stderr_bytes=65536,
            ),
        )
        generated = parse_json(execution.stdout)
        if (
            not isinstance(generated, dict)
            or generated.get("schemaVersion") != "whitehat-schemathesis-run-v1"
            or generated.get("toolVersion") != SCHEMATHESIS_VERSION
            or generated.get("complete") is not True
        ):
            raise ReportError("owned Schemathesis result is invalid")
        state["items"].clear()
        root = Path(temporary)
        requests, steps = [], []
        for index, (method, path, status, marker) in enumerate(
            (
                ("POST", "/items", 201, "owned-item"),
                ("GET", "/items/demo", 200, "owned-item"),
                ("DELETE", "/items/demo", 200, None),
                ("GET", "/items/demo", 404, None),
            )
        ):
            request = {
                "schemaVersion": REQUEST_SCHEMA,
                "method": method,
                "url": origin + path,
                "headers": {},
                "body": None,
                "objectId": "owned-item",
                "operationId": f"lifecycle-{index}",
            }
            requests.append(request)
            (root / f"request-{index}.json").write_bytes(canonical(request))
            steps.append(
                {
                    "id": f"step-{index}",
                    "request": f"request-{index}.json",
                    "identityId": "alice",
                    "expect": {
                        "status": status,
                        "values": {"/marker": marker} if marker else {},
                        "absent": [] if marker else ["/marker"],
                    },
                }
            )
        now = datetime.now(timezone.utc).replace(microsecond=0)

        def stamp(value):
            return value.isoformat().replace("+00:00", "Z")

        credential_name = "WHITEHAT_CREDENTIAL_FIXTURE_" + uuid.uuid4().hex.upper()
        session = {
            "schemaVersion": SESSION_SCHEMA,
            "sessionId": "owned-lifecycle",
            "projectId": "owned-api",
            "origin": origin,
            "startsAt": stamp(now),
            "expiresAt": stamp(now + timedelta(minutes=5)),
            "authority": {
                "policy": "Owned in-process fixture",
                "reviewedAt": stamp(now),
                "approved": True,
                "researcherControlled": True,
            },
            "requestSha256": [digest(r) for r in requests],
            "identities": [
                {"id": "alice", "auth": "bearer", "credentialEnv": credential_name}
            ],
            "responsePointers": ["/marker"],
            "budgets": {
                "maxRequests": 4,
                "minDelayMs": 0,
                "timeoutSeconds": 2,
                "maxResponseBytes": 8192,
            },
            "allowMutation": True,
        }
        (root / "session.json").write_bytes(canonical(session))
        (root / "scenario.json").write_bytes(
            canonical(
                {
                    "schemaVersion": "whitehat-http-scenario-v1",
                    "projectId": "owned-api",
                    "steps": steps,
                }
            )
        )
        os.environ[credential_name] = "owned-alice"
        try:
            lifecycle = run_scenario(
                str(root / "scenario.json"),
                str(root / "session.json"),
                str(root / "ledger.sqlite3"),
            )
        finally:
            os.environ.pop(credential_name, None)
        observations = []
        if any(
            e["outcome"] == "mismatch" for e in lifecycle["provenance"]["evaluations"]
        ):
            observations.append(
                observation(
                    "whitehat-owned-api",
                    "lifecycle-expectation-mismatch",
                    category="web-observation",
                    context={"projectId": "owned-api", "fixture": "lifecycle"},
                    explanation="The owned API violated the explicit create/read/delete/read expectation. This is a teaching-fixture result, not a real-target finding.",
                )
            )
        if generated["failureCount"]:
            observations.append(
                observation(
                    "schemathesis",
                    "owned-schema-check-failure",
                    category="web-observation",
                    context={
                        "projectId": "owned-api",
                        "reportedFailureCount": generated["failureCount"],
                    },
                    explanation="Schemathesis reported a check failure in the owned API fixture; inspect the generated evidence and explicit expectations.",
                )
            )
        request_count = state["requests"]
    return result_document(
        observations,
        {
            "kind": "owned-api-test",
            "projectId": "owned-api",
            "tool": "schemathesis",
            "toolVersion": SCHEMATHESIS_VERSION,
            "distributionRecordSha256": hashlib.sha256(record.encode()).hexdigest(),
            "process": execution.receipt(),
            "generated": generated,
            "lifecycle": lifecycle,
            "requestCount": request_count,
            "executionVerified": True,
            "osSandboxEnforced": False,
        },
        effects={
            "network": True,
            "ownedLoopbackOnly": True,
            "processCreation": True,
            "fixtureDisposed": True,
            "externalTargetRequests": False,
            "realCredentialsUsed": False,
        },
    )
