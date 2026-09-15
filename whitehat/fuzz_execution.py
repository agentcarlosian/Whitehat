"""Execute preflighted concrete cases through the existing replay ledger."""

from __future__ import annotations

import time
import tempfile
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from .fuzz_contracts import json_file, load_batch
from .http_evidence import digest, evidence_document
from .http_replay import (
    _bind,
    _budget_session,
    _credential,
    origin,
    replay,
    stop_session,
    validate_session,
)
from .network_engine import NetworkExecutionError, _connect, _ensure_state, _state_path
from .records import RecordError, write_json_document
from .relational import evaluate_assertions
from .reports import ReportError, observation, result_document


def _claim(state: Path, session: dict, batch: dict, requests: int) -> str:
    _bind(state, session)
    connection = _connect(state)
    owner = uuid.uuid4().hex
    try:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS fuzz_execution (id INTEGER PRIMARY KEY CHECK(id=1), owner TEXT NOT NULL, batch_sha256 TEXT NOT NULL, active INTEGER NOT NULL)"
        )
        connection.execute("BEGIN IMMEDIATE")
        row = _ensure_state(connection, digest(session), _budget_session(session))
        if (
            row["stopped"]
            or row["active_requests"]
            or row["max_requests"] - row["attempted_requests"] < requests
        ):
            raise ReportError(
                "session cannot fit the whole batch including reset, or is stopped/busy"
            )
        active = connection.execute(
            "SELECT active FROM fuzz_execution WHERE id=1"
        ).fetchone()
        if active and active[0]:
            raise ReportError(
                "a fuzz batch owns this ledger; inspect interrupted execution before recovery"
            )
        connection.execute(
            "INSERT INTO fuzz_execution VALUES (1, ?, ?, 1) ON CONFLICT(id) DO UPDATE SET owner=excluded.owner, batch_sha256=excluded.batch_sha256, active=1",
            (owner, digest(batch)),
        )
        connection.execute("COMMIT")
        return owner
    except Exception:
        connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def _release(state: Path, owner: str) -> None:
    connection = _connect(state)
    try:
        connection.execute(
            "UPDATE fuzz_execution SET active=0 WHERE id=1 AND owner=?", (owner,)
        )
    finally:
        connection.close()


def check_expectation(entry: dict, expected: dict) -> str:
    response = entry["response"]
    if response["status"] not in expected["statuses"]:
        return "mismatch"
    if not expected["values"] and not expected["absent"]:
        return "consistent"
    data = response["json"]
    if not response["bodyCaptured"] or not data["parsed"]:
        return "inconclusive"
    if not set(expected["values"]).union(expected["absent"]) <= set(
        data["selectedPointers"]
    ):
        return "inconclusive"
    matches = all(
        k in data["values"] and digest(data["values"][k]) == digest(v)
        for k, v in expected["values"].items()
    )
    matches = matches and all(k not in data["values"] for k in expected["absent"])
    return "consistent" if matches else "mismatch"


def run_batch(path: str, session_path: str, state_path: str) -> dict:
    batch, cases = load_batch(path)
    session = validate_session(json_file(Path(session_path)))
    if session["projectId"] != batch["projectId"]:
        raise ReportError("batch and session projects differ")
    profiles = {p["id"]: p for p in session["identities"]}
    total = 0
    for case, requests in cases:
        for phase in ("setup", "steps", "reset"):
            for step in case[phase]:
                request = requests[step["id"]]
                parsed = urlsplit(request["url"])
                if (
                    digest(request) not in session["requestSha256"]
                    or origin(f"{parsed.scheme}://{parsed.netloc}") != session["origin"]
                ):
                    raise ReportError(
                        "batch contains a request outside the approved session"
                    )
                if (
                    request["method"] in {"POST", "PUT", "PATCH", "DELETE"}
                    and not session["allowMutation"]
                ):
                    raise ReportError(
                        "batch contains a mutation not enabled by the session"
                    )
                if step["identityId"] not in profiles:
                    raise ReportError("batch identity is outside the session")
                _credential(profiles[step["identityId"]])
                required = set(step["expect"]["values"]) | set(step["expect"]["absent"])
                if not required <= set(session["responsePointers"]):
                    raise ReportError(
                        "batch expectation uses an unapproved response selector"
                    )
                total += 1
        for rule in case["assertions"]:
            for side in ("left", "right"):
                if (
                    rule[side]
                    and rule[side]["pointer"] not in session["responsePointers"]
                ):
                    raise ReportError("batch relational selector is not approved")
    state = _state_path(state_path)
    owner = _claim(state, session, batch, total)
    temporary = tempfile.TemporaryDirectory(prefix="whitehat-fuzz-requests-")
    snapshot = Path(temporary.name)
    records, receipts, outcomes, observations = [], [], [], []
    stopped = False
    try:
        for _, requests in cases:
            for request in requests.values():
                saved = snapshot / (digest(request) + ".json")
                if not saved.exists():
                    write_json_document(request, saved)
        for case, _ in cases:
            entries, evaluations = {}, []
            setup_ok = True
            blocked = False
            reset_ok = True
            for phase in ("setup", "steps", "reset"):
                if blocked or (phase == "steps" and not setup_ok):
                    continue
                for step in case[phase]:
                    if session["budgets"]["minDelayMs"]:
                        time.sleep(session["budgets"]["minDelayMs"] / 1000)
                    # Execute copied, hash-checked inputs, not mutable source paths.
                    request_path = snapshot / (step["requestSha256"] + ".json")
                    try:
                        result = replay(
                            session_path,
                            str(request_path),
                            step["identityId"],
                            state_path,
                            _batch_owner=owner,
                        )
                    except (ReportError, RecordError, NetworkExecutionError):
                        blocked = True
                        evaluations.append(
                            {
                                "stepId": step["id"],
                                "phase": phase,
                                "outcome": "blocked",
                                "evidenceSha256": None,
                            }
                        )
                        break
                    entry = result["exchanges"][0]
                    records.append(entry)
                    entries[step["id"]] = entry
                    receipts.append(
                        {
                            "caseId": case["id"],
                            "stepId": step["id"],
                            **result["provenance"],
                        }
                    )
                    outcome = check_expectation(entry, step["expect"])
                    if result["provenance"]["outcome"] != "completed":
                        blocked = True
                        outcome = "blocked"
                    evaluations.append(
                        {
                            "stepId": step["id"],
                            "phase": phase,
                            "outcome": outcome,
                            "evidenceSha256": entry["evidenceSha256"],
                        }
                    )
                    if phase == "setup" and outcome != "consistent":
                        setup_ok = False
                        break
                    if phase == "reset" and outcome != "consistent":
                        reset_ok = False
                    if blocked:
                        break
            relations = evaluate_assertions(case["assertions"], entries)
            failed = sorted(
                [
                    "step:"
                    + e["stepId"]
                    + ":status:"
                    + str(entries[e["stepId"]]["response"]["status"])
                    for e in evaluations
                    if e["outcome"] == "mismatch" and e["phase"] == "steps"
                ]
                + [
                    "assertion:" + e["assertionId"]
                    for e in relations
                    if e["outcome"] == "mismatch"
                ]
            )
            executed_resets = sum(e["phase"] == "reset" for e in evaluations)
            cleanup = (
                "not-required"
                if not case["reset"]
                else "verified"
                if reset_ok and executed_resets == len(case["reset"]) and not blocked
                else "incomplete"
            )
            inconclusive = not setup_ok or any(
                e["outcome"] == "inconclusive" for e in evaluations + relations
            )
            outcome = (
                "blocked"
                if blocked
                else "inconclusive"
                if inconclusive
                else "mismatch"
                if failed
                else "consistent"
            )
            result_case = {
                "caseId": case["id"],
                "caseSha256": digest(case),
                "outcome": outcome,
                "cleanup": cleanup,
                "failureKeys": failed,
                "evaluations": evaluations,
                "assertions": relations,
                "executedSteps": len(evaluations),
                "plannedSteps": sum(len(case[p]) for p in ("setup", "steps", "reset")),
            }
            outcomes.append(result_case)
            if failed:
                observations.append(
                    observation(
                        "whitehat-fuzz",
                        "expectation-mismatch",
                        category="web-observation",
                        context={
                            "projectId": batch["projectId"],
                            "caseId": case["id"],
                            "failureKeys": failed,
                        },
                        explanation="A prepared fuzz case violated explicit expectations. Inspect readback, setup/reset and controls before claiming a vulnerability.",
                    )
                )
            if blocked or cleanup == "incomplete" or not setup_ok:
                stopped = True
                stop_session(session_path, state_path)
                break
    except BaseException:
        stop_session(session_path, state_path)
        raise
    finally:
        _release(state, owner)
        temporary.cleanup()
    evidence = evidence_document(
        batch["projectId"],
        records,
        {
            "kind": "replay",
            "profile": "fuzz-batch",
            "batchSha256": digest(batch),
            "sessionSha256": digest(session),
            "receipts": receipts,
            "cases": outcomes,
            "executionVerified": True,
        },
    )
    return result_document(
        observations,
        {
            "kind": "fuzz-run",
            "projectId": batch["projectId"],
            "batchSha256": digest(batch),
            "sessionSha256": digest(session),
            "cases": outcomes,
            "httpEvidence": evidence,
            "complete": len(outcomes) == len(cases) and not stopped,
            "plannedCases": len(cases),
            "plannedRequests": total,
            "executionVerified": True,
        },
        effects={"network": True, "processCreation": False},
    )
