import copy
import json
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from whitehat.api_schema import coverage
from whitehat.candidates import candidate_history, initialize_candidate, record_decision
from whitehat.http_evidence import (
    assess_access,
    compare_http,
    digest,
    evidence_document,
    exchange,
    import_capture,
)
from whitehat.http_replay import prepared_request, validate_session
from whitehat.packets import check_packet, export_packet, initialize_packet
from whitehat.preparation import bind_request, prepare_capture
from whitehat.records import RecordError, save_result_document
from whitehat.reports import (
    ReportError,
    compare_results,
    observation,
    result_document,
    seal,
)

ROOT = Path(__file__).resolve().parents[1]


class WorkflowFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return str(path)

    def capture(self, body=None, status=200):
        request = {
            "method": "GET",
            "url": "https://owned.invalid/items",
            "headers": [
                {"name": "Authorization", "value": "Bearer owned-fixture-credential"},
                {"name": "Accept", "value": "application/json"},
                {"name": "Host", "value": "owned.invalid"},
            ],
        }
        if body is not None:
            request.update(
                method="POST", postData={"mimeType": "application/json", "text": body}
            )
        return {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "request": request,
                        "response": {
                            "status": status,
                            "content": {"text": '{"id":"owned-item","marker":"owned"}'},
                        },
                    }
                ],
            }
        }

    def http_result(
        self,
        filename="evidence.json",
        identity="alice",
        selected=None,
        value="owned-id",
        status=200,
    ):
        entry = exchange(
            "owned",
            {"method": "GET", "url": "https://owned.invalid/items"},
            {
                "status": status,
                "content": {"text": json.dumps({"id": value, "marker": "owned"})},
            },
            identity=identity,
            object_id="item",
            operation="read",
            selected=selected or ["/id"],
        )
        document = evidence_document(
            "owned",
            [entry],
            {"kind": "import", "format": "har", "executionVerified": False},
        )
        save_result_document(document, self.root / filename)
        return document


class CapturePreparationTests(WorkflowFixture):
    def test_mixed_har_missing_and_failed_entries_are_visible(self):
        capture = self.capture()
        failed = copy.deepcopy(capture["log"]["entries"][0])
        failed["response"] = {"status": 0, "_error": "DO-NOT-EXPORT raw diagnostic"}
        missing = copy.deepcopy(failed)
        del missing["response"]
        capture["log"]["entries"].extend([failed, missing])
        result = import_capture(self.write("capture.har", capture), "owned")
        self.assertEqual(len(result["exchanges"]), 1)
        self.assertEqual(
            [e["entryIndex"] for e in result["provenance"]["incompleteEntries"]], [1, 2]
        )
        self.assertEqual(result["provenance"]["entryIndexes"], [0])
        self.assertNotIn("DO-NOT-EXPORT", json.dumps(result))
        self.assertNotIn("owned-fixture-credential", json.dumps(result))

    def test_null_bodies_are_missing_not_empty_and_extensions_reported(self):
        capture = self.capture()
        entry = capture["log"]["entries"][0]
        entry["request"]["postData"] = {"text": None}
        entry["response"]["content"] = {"text": None}
        entry["_webSocketMessages"] = [{"data": "DO-NOT-EXPORT"}]
        result = import_capture(self.write("capture.har", capture), "owned")
        self.assertFalse(result["exchanges"][0]["request"]["bodyCaptured"])
        self.assertFalse(result["exchanges"][0]["response"]["bodyCaptured"])
        self.assertEqual(
            result["provenance"]["diagnostics"][0]["code"],
            "websocket-messages-not-imported",
        )
        self.assertNotIn("DO-NOT-EXPORT", json.dumps(result))

    def test_malformed_entry_is_not_silently_salvaged(self):
        for status in (True, "0", -1, 600):
            with self.subTest(status=status), self.assertRaises(ReportError):
                import_capture(
                    self.write("bad.har", self.capture(status=status)), "owned"
                )

    def test_prepare_json_and_form_preserves_semantics_without_credentials(self):
        capture = self.capture('{"name":"owned item"}')
        path = self.write("source.har", capture)
        with (
            patch("socket.socket", side_effect=AssertionError("network")),
            patch("subprocess.Popen", side_effect=AssertionError("process")),
        ):
            receipt = prepare_capture(
                path,
                str(self.root / "prepared"),
                "owned",
                identity="alice",
                object_id="item",
                operation="create",
            )
        request = json.loads((self.root / "prepared/request.json").read_text())
        self.assertEqual(request["body"], '{"name":"owned item"}')
        self.assertEqual(digest(prepared_request(request)), receipt["requestSha256"])
        self.assertNotIn(
            "owned-fixture-credential", json.dumps(receipt) + json.dumps(request)
        )
        draft = json.loads((self.root / "prepared/session.draft.json").read_text())
        self.assertFalse(draft["authority"]["approved"])
        self.assertFalse(draft["authority"]["researcherControlled"])
        self.assertEqual(draft["identities"][0]["auth"], "bearer")
        with self.assertRaises(ReportError):
            validate_session(draft)
        capture["log"]["entries"][0]["request"]["postData"] = {
            "mimeType": "application/x-www-form-urlencoded",
            "text": "name=owned+item&flag=",
        }
        prepare_capture(
            self.write("form.har", capture), str(self.root / "form"), "owned"
        )
        self.assertEqual(
            json.loads((self.root / "form/request.json").read_text())["body"],
            "name=owned+item&flag=",
        )
        with self.assertRaises(RecordError):
            prepare_capture(path, str(self.root / "prepared"), "owned")

    def test_preparation_rejects_missing_body_credentials_and_semantic_loss(self):
        variants = []
        for body in ('{"password":"owned"}', '{"nested":{"api_key":"owned"}}'):
            variants.append(self.capture(body))
        missing = self.capture("{}")
        missing["log"]["entries"][0]["request"]["postData"]["text"] = None
        variants.append(missing)
        query = self.capture()
        query["log"]["entries"][0]["request"]["url"] += "?access_token=owned"
        variants.append(query)
        duplicate = self.capture()
        duplicate["log"]["entries"][0]["request"]["headers"].append(
            {"name": "accept", "value": "text/plain"}
        )
        variants.append(duplicate)
        echoed = self.capture('{"name":"owned-fixture-credential"}')
        variants.append(echoed)
        for index, capture in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(ReportError):
                prepare_capture(
                    self.write("bad.har", capture), str(self.root / "out"), "owned"
                )
            self.assertFalse((self.root / "out").exists())


class BindingTests(WorkflowFixture):
    def plan(self, value=None):
        document = self.http_result(value=value or uuid.uuid4().hex)
        request = {
            "schemaVersion": "whitehat-prepared-request-v1",
            "method": "DELETE",
            "url": "https://owned.invalid/items/PLACEHOLDER?mode=owned",
            "headers": {},
            "body": None,
            "objectId": "item",
            "operationId": "delete",
        }
        self.write("request.json", request)
        plan = {
            "schemaVersion": "whitehat-request-binding-v1",
            "projectId": "owned",
            "source": {
                "path": "evidence.json",
                "resultSha256": document["resultSha256"],
                "evidenceSha256": document["exchanges"][0]["evidenceSha256"],
                "pointer": "/id",
                "identityId": "alice",
                "objectId": "item",
            },
            "request": {"path": "request.json", "requestSha256": digest(request)},
            "pathSegment": 2,
            "expectedSegment": "PLACEHOLDER",
        }
        return plan, request, document

    def test_random_id_binding_only_changes_declared_segment(self):
        plan, original, document = self.plan()
        with (
            patch("socket.socket", side_effect=AssertionError("network")),
            patch("subprocess.Popen", side_effect=AssertionError("process")),
        ):
            receipt = bind_request(
                self.write("binding.json", plan), str(self.root / "bound")
            )
        result = json.loads((self.root / "bound/request.json").read_text())
        expected = copy.deepcopy(original)
        expected["url"] = original["url"].replace(
            "PLACEHOLDER", document["exchanges"][0]["response"]["json"]["values"]["/id"]
        )
        self.assertEqual(result, expected)
        self.assertEqual(receipt["source"]["requestSha256"], digest(original))
        self.assertFalse((self.root / "bound/session.draft.json").exists())
        self.assertEqual(json.loads((self.root / "request.json").read_text()), original)

    def test_binding_rejects_unsafe_values_and_changed_identity_or_hash(self):
        plan, _, _ = self.plan("../outside")
        with self.assertRaises(ReportError):
            bind_request(self.write("binding.json", plan), str(self.root / "out"))
        (self.root / "evidence.json").unlink()
        plan, _, _ = self.plan()
        for key, value in (
            ("identityId", "bob"),
            ("resultSha256", "0" * 64),
            ("path", "../outside.json"),
            ("pointer", "/token"),
        ):
            altered = copy.deepcopy(plan)
            altered["source"][key] = value
            with self.subTest(key=key), self.assertRaises((ReportError, RecordError)):
                bind_request(
                    self.write("binding.json", altered), str(self.root / "out")
                )
        self.assertFalse((self.root / "out").exists())


class PacketTests(WorkflowFixture):
    def packet(self):
        self.http_result("before.json")
        self.http_result("after.json", status=403)
        comparison = compare_http(
            str(self.root / "before.json"), str(self.root / "after.json")
        )
        save_result_document(comparison, self.root / "comparison.json")
        initialize_packet(
            str(self.root / "packet.json"),
            "owned",
            "Owned review",
            [
                str(self.root / p)
                for p in ("before.json", "after.json", "comparison.json")
            ],
        )
        return json.loads((self.root / "packet.json").read_text())

    def test_draft_can_export_and_completed_packet_links_comparison(self):
        manifest = self.packet()
        draft = check_packet(str(self.root / "packet.json"))
        self.assertFalse(draft["contentComplete"])
        export_packet(str(self.root / "packet.json"), str(self.root / "draft.md"))
        for key in ("prerequisites", "impact", "limitations", "negativeControl"):
            manifest[key] = "Owned fixture statement."
        manifest["steps"][0].update(
            action="Read as Alice then Bob",
            expected="Bob is denied",
            actual="403 after change",
        )
        self.write("packet.json", manifest)
        result = check_packet(str(self.root / "packet.json"))
        self.assertTrue(result["contentComplete"], result)
        export_packet(
            str(self.root / "packet.json"), str(self.root / "review.md"), "hackerone"
        )
        rendered = (self.root / "review.md").read_text()
        self.assertIn("Before status: 200", rendered)
        self.assertIn("After status: 403", rendered)
        self.assertIn("alice / item / read", rendered)
        self.assertNotIn(str(self.root), rendered)

    def test_changed_or_missing_evidence_never_embedded_as_verified(self):
        manifest = self.packet()
        (self.root / "before.json").unlink()
        altered = json.loads((self.root / "after.json").read_text())
        altered["projectId"] = "changed"
        altered = seal({k: v for k, v in altered.items() if k != "resultSha256"})
        self.write("after.json", altered)
        result = check_packet(str(self.root / "packet.json"))
        self.assertFalse(result["contentComplete"])
        self.assertNotIn("evidence-1", result["verifiedEvidence"])
        export_packet(str(self.root / "packet.json"), str(self.root / "draft.md"))
        self.assertIn("content was not embedded", (self.root / "draft.md").read_text())
        manifest["evidence"][0]["path"] = "../outside.json"
        with self.assertRaises(ReportError):
            check_packet(self.write("packet.json", manifest))

    def test_selected_material_and_markdown_escaping(self):
        document = self.http_result()
        other = copy.deepcopy(document["exchanges"][0])
        other["response"]["json"]["values"]["/id"] = "UNSELECTED"
        other["evidenceSha256"] = digest(
            {k: v for k, v in other.items() if k != "evidenceSha256"}
        )
        document = evidence_document(
            "owned", [document["exchanges"][0], other], {"kind": "import"}
        )
        self.write("evidence.json", document)
        initialize_packet(
            str(self.root / "packet.json"),
            "owned",
            "![payload](https://untrusted.invalid)",
            [str(self.root / "evidence.json")],
        )
        manifest = json.loads((self.root / "packet.json").read_text())
        manifest["evidence"][0]["select"] = [document["exchanges"][0]["evidenceSha256"]]
        self.write("packet.json", manifest)
        export_packet(
            str(self.root / "packet.json"), str(self.root / "draft.md"), "bugcrowd"
        )
        content = (self.root / "draft.md").read_text()
        self.assertNotIn("UNSELECTED", content)
        self.assertNotIn("![payload]", content)
        self.assertIn("Walkthrough and proof of concept", content)


class CandidateCoverageTests(WorkflowFixture):
    def test_severity_change_is_visible_and_profile_differences_not_comparable(self):
        for name, severity in (("before", "low"), ("after", "high")):
            result = result_document(
                [
                    observation(
                        "owned-tool", "owned-rule", path="a.py", severity=severity
                    )
                ],
                {"kind": "import", "tool": "owned-tool"},
            )
            save_result_document(result, self.root / (name + ".json"))
        compared = compare_results(
            str(self.root / "before.json"), str(self.root / "after.json")
        )
        self.assertEqual(compared["summary"]["metadataChanged"], 1)
        self.assertEqual(compared["summary"]["unchanged"], 0)
        result["provenance"]["toolVersion"] = "different"
        self.write(
            "after.json", seal({k: v for k, v in result.items() if k != "resultSha256"})
        )
        self.assertEqual(
            compare_results(
                str(self.root / "before.json"), str(self.root / "after.json")
            )["comparisonSuitability"],
            "not-comparable",
        )

    def test_candidate_retest_history_preserves_recurring_and_conflicting_evidence(
        self,
    ):
        before = self.http_result("before.json")
        after = self.http_result("after.json", status=403)
        different = self.http_result("different.json", identity="bob")
        directory = str(self.root / "candidate")
        initialize_candidate(directory, "owned-1", "owned", "Owned access candidate")
        first = record_decision(
            directory,
            str(self.root / "before.json"),
            [before["exchanges"][0]["evidenceSha256"]],
            "reproduced",
            "Owned baseline",
        )
        fixed = record_decision(
            directory,
            str(self.root / "after.json"),
            [after["exchanges"][0]["evidenceSha256"]],
            "not-reproduced",
            "Denied under same conditions",
            1,
        )
        self.assertTrue(fixed["comparisonSuitable"])
        recurrence = record_decision(
            directory,
            str(self.root / "before.json"),
            [before["exchanges"][0]["evidenceSha256"]],
            "reproduced",
            "Later recurrence",
            2,
        )
        self.assertEqual(recurrence["previousSha256"], fixed["resultSha256"])
        noncomparable = record_decision(
            directory,
            str(self.root / "different.json"),
            [different["exchanges"][0]["evidenceSha256"]],
            "not-reproduced",
            "Different identity",
            1,
        )
        self.assertEqual(noncomparable["decision"], "not-comparable")
        self.assertEqual(noncomparable["requestedDecision"], "not-reproduced")
        self.assertEqual(len(candidate_history(directory)["decisions"]), 4)
        path = self.root / "candidate/decisions/000001.json"
        value = json.loads(path.read_text())
        value["note"] = "tampered"
        path.write_text(json.dumps(value))
        with self.assertRaises(ReportError):
            candidate_history(directory)
        self.assertEqual(first["sequence"], 1)

    def test_access_coverage_keeps_untested_identities_visible(self):
        document = self.http_result()
        matrix = {
            "schemaVersion": "whitehat-access-matrix-v1",
            "projectId": "owned",
            "rows": [],
        }
        for identity in ("alice", "bob"):
            matrix["rows"].append(
                {
                    "id": identity,
                    "identityId": identity,
                    "objectId": "item",
                    "operationId": "read",
                    "method": "GET",
                    "endpoint": "https://owned.invalid/items",
                    "expect": "allow" if identity == "alice" else "deny",
                    "proof": {"pointer": "/id", "equals": "owned-id"},
                }
            )
        schema = {
            "openapi": "3.0.3",
            "info": {"title": "Owned", "version": "1"},
            "paths": {
                "/items": {"get": {"responses": {"200": {"description": "Owned"}}}}
            },
        }
        result = coverage(
            self.write("schema.json", schema),
            str(self.root / "evidence.json"),
            "owned",
            self.write("matrix.json", matrix),
        )
        self.assertEqual(len(result["observedOperations"]), 1)
        self.assertEqual(
            [r["outcome"] for r in result["accessCases"]], ["consistent", "not-tested"]
        )
        self.assertIn(document["resultSha256"], result["evidenceResults"])

    def test_stopped_scenario_keeps_later_steps_and_transitions_untested(self):
        document = self.http_result()
        request = {
            "schemaVersion": "whitehat-prepared-request-v1",
            "method": "GET",
            "url": "https://owned.invalid/items",
            "headers": {},
            "body": None,
            "objectId": "item",
            "operationId": "read",
        }
        self.write("request.json", request)
        plan = {
            "schemaVersion": "whitehat-http-scenario-v1",
            "projectId": "owned",
            "steps": [
                {
                    "id": name,
                    "request": "request.json",
                    "identityId": "alice",
                    "expect": {
                        "status": 200,
                        "values": {"/id": "owned-id"},
                        "absent": [],
                    },
                }
                for name in ("first", "second", "third")
            ],
        }
        provenance = {
            "kind": "replay",
            "profile": "explicit-scenario",
            "scenarioSha256": digest(plan),
            "plannedSteps": 3,
            "executedSteps": 1,
            "evaluations": [
                {
                    "stepId": "first",
                    "outcome": "mismatch",
                    "evidenceSha256": document["exchanges"][0]["evidenceSha256"],
                }
            ],
        }
        self.write(
            "scenario-result.json",
            evidence_document("owned", document["exchanges"], provenance),
        )
        schema = {
            "openapi": "3.0.3",
            "info": {"title": "Owned", "version": "1"},
            "paths": {
                "/items": {"get": {"responses": {"200": {"description": "Owned"}}}}
            },
        }
        result = coverage(
            self.write("schema.json", schema),
            str(self.root / "scenario-result.json"),
            "owned",
            scenario_paths=[self.write("scenario.json", plan)],
        )
        self.assertEqual(
            [s["outcome"] for s in result["scenarios"][0]["steps"]],
            ["mismatch", "not-tested", "not-tested"],
        )
        self.assertTrue(
            all(
                t["outcome"] == "not-tested"
                for t in result["scenarios"][0]["transitions"]
            )
        )

    def test_packet_access_assessment_links_owned_controls(self):
        paths = []
        for name in ("vulnerable", "fixed"):
            document = import_capture(
                str(ROOT / f"examples/http/{name}.har"),
                "owned-api",
                selected=["/marker"],
            )
            save_result_document(document, self.root / f"{name}.json")
            paths.append(str(self.root / f"{name}.json"))
        assessed = assess_access(
            str(ROOT / "examples/http/access-matrix.json"), [paths[0]]
        )
        save_result_document(assessed, self.root / "assessment.json")
        initialize_packet(
            str(self.root / "packet.json"),
            "owned-api",
            "Owned access",
            [*paths, str(self.root / "assessment.json")],
        )
        export_packet(str(self.root / "packet.json"), str(self.root / "packet.md"))
        rendered = (self.root / "packet.md").read_text()
        self.assertIn(assessed["provenance"]["matrixSha256"], rendered)
        self.assertIn("mismatch", rendered)

    def test_cli_preparation_packet_candidate_errors_and_readable_output(self):
        def run(*args):
            completed = subprocess.run(
                [sys.executable, "-B", "-m", "whitehat", *args],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(
                completed.returncode, 0, completed.stdout + completed.stderr
            )
            return completed.stdout

        path = self.write("source.har", self.capture())
        receipt = json.loads(
            run(
                "http",
                "prepare",
                path,
                "--project",
                "owned",
                "--output-dir",
                str(self.root / "prepared"),
                "--json",
            )
        )
        self.assertFalse(receipt["effects"]["network"])
        document = self.http_result()
        run(
            "packet",
            "init",
            "--project",
            "owned",
            "--evidence",
            str(self.root / "evidence.json"),
            "--output",
            str(self.root / "packet.json"),
        )
        self.assertIn(
            "missing-content", run("packet", "check", str(self.root / "packet.json"))
        )
        run(
            "packet",
            "export",
            str(self.root / "packet.json"),
            "--output",
            str(self.root / "packet.md"),
        )
        directory = str(self.root / "candidate")
        run(
            "candidate",
            "init",
            directory,
            "--id",
            "owned-1",
            "--project",
            "owned",
            "--title",
            "Owned candidate",
        )
        run(
            "candidate",
            "record",
            directory,
            "--evidence",
            str(self.root / "evidence.json"),
            "--select",
            document["exchanges"][0]["evidenceSha256"],
            "--decision",
            "needs-work",
            "--note",
            "Investigate owned control",
        )
        self.assertIn("needs-work", run("candidate", "history", directory))


class WorkflowEdgeTests(WorkflowFixture):
    def test_real_owned_scenario_packet_and_changed_request_coverage(self):
        import os
        from whitehat.api_fixture import owned_api
        from whitehat.http_replay import run_scenario
        from whitehat.preparation import session_draft

        with owned_api() as (origin, state):
            request = {
                "schemaVersion": "whitehat-prepared-request-v1",
                "method": "GET",
                "url": origin + "/objects/private-a",
                "headers": {},
                "body": None,
                "objectId": "private-a",
                "operationId": "read",
            }
            request_path = self.write("request.json", request)
            session = session_draft(request, "owned-api", "alice", "bearer")
            session["authority"].update(
                approved=True, researcherControlled=True, policy="Owned disposable API"
            )
            session["identities"] = [
                {
                    "id": identity,
                    "auth": "bearer",
                    "credentialEnv": "WHITEHAT_CREDENTIAL_" + identity.upper(),
                }
                for identity in ("alice", "bob")
            ]
            session["responsePointers"] = ["/marker"]
            session["budgets"]["minDelayMs"] = 0
            plan = {
                "schemaVersion": "whitehat-http-scenario-v1",
                "projectId": "owned-api",
                "steps": [
                    {
                        "id": f"step-{i}",
                        "request": "request.json",
                        "identityId": identity,
                        "expect": {
                            "status": 200,
                            "values": {"/marker": "owned-private-a"},
                            "absent": [],
                        },
                    }
                    for i, identity in enumerate(("alice", "bob", "alice"), 1)
                ],
            }
            plan_path = self.write("scenario.json", plan)
            with patch.dict(
                os.environ,
                {
                    "WHITEHAT_CREDENTIAL_ALICE": "owned-alice",
                    "WHITEHAT_CREDENTIAL_BOB": "owned-bob",
                },
            ):
                result = run_scenario(
                    plan_path,
                    self.write("session.json", session),
                    str(self.root / "ledger.sqlite3"),
                )
            self.assertEqual(state["requests"], 2)
        result_path = self.write("scenario-result.json", result)
        initialize_packet(
            str(self.root / "packet.json"),
            "owned-api",
            "Owned stopped scenario",
            [result_path],
        )
        checked = check_packet(str(self.root / "packet.json"))
        self.assertIn("incomplete-scenario", {i["code"] for i in checked["issues"]})
        export_packet(str(self.root / "packet.json"), str(self.root / "scenario.md"))
        self.assertIn("Executed steps: 2", (self.root / "scenario.md").read_text())
        schema = {
            "openapi": "3.0.3",
            "info": {"title": "Owned", "version": "1"},
            "paths": {
                "/objects/private-a": {
                    "get": {"responses": {"200": {"description": "Owned"}}}
                }
            },
        }
        schema_path = self.write("schema.json", schema)
        covered = coverage(
            schema_path, result_path, "owned-api", scenario_paths=[plan_path]
        )
        self.assertEqual(
            [s["outcome"] for s in covered["scenarios"][0]["steps"]],
            ["consistent", "mismatch", "not-tested"],
        )
        self.assertEqual(
            [s["outcome"] for s in covered["scenarios"][0]["transitions"]],
            ["observed", "not-tested"],
        )
        request["url"] = origin + "/objects/shared"
        Path(request_path).write_text(json.dumps(request))
        changed = coverage(
            schema_path, result_path, "owned-api", scenario_paths=[plan_path]
        )
        self.assertEqual(
            changed["scenarios"][0]["notComparableResults"], [result["resultSha256"]]
        )
        self.assertTrue(
            all(s["outcome"] == "not-tested" for s in changed["scenarios"][0]["steps"])
        )

    def test_retests_with_changed_request_or_missing_body_are_not_comparable(self):
        baseline = self.http_result()
        directory = str(self.root / "candidate")
        initialize_candidate(directory, "owned-1", "owned", "Owned")
        record_decision(
            directory,
            str(self.root / "evidence.json"),
            [baseline["exchanges"][0]["evidenceSha256"]],
            "reproduced",
            "Owned baseline",
        )
        for index, variant in enumerate(("request", "body", "selectors")):
            document = copy.deepcopy(baseline)
            entry = document["exchanges"][0]
            if variant == "request":
                entry["request"]["urlSha256"] = "a" * 64
            elif variant == "body":
                entry["response"].update(bodyCaptured=False)
                entry["response"]["json"].update(parsed=False, values={})
            else:
                entry["response"]["json"].update(selectedPointers=[], values={})
            entry["evidenceSha256"] = digest(
                {k: v for k, v in entry.items() if k != "evidenceSha256"}
            )
            document = seal({k: v for k, v in document.items() if k != "resultSha256"})
            path = self.write(f"different-{index}.json", document)
            result = record_decision(
                directory,
                path,
                [entry["evidenceSha256"]],
                "not-reproduced",
                "Changed conditions",
                1,
            )
            self.assertEqual(result["decision"], "not-comparable")

    def test_concurrent_candidate_appends_do_not_overwrite(self):
        import threading
        from concurrent.futures import ThreadPoolExecutor
        from whitehat.candidates import _history

        document = self.http_result()
        directory = str(self.root / "candidate")
        initialize_candidate(directory, "owned-1", "owned", "Owned")
        barrier = threading.Barrier(2)

        def snapshot(path):
            result = _history(path)
            barrier.wait(timeout=5)
            return result

        def append():
            try:
                record_decision(
                    directory,
                    str(self.root / "evidence.json"),
                    [document["exchanges"][0]["evidenceSha256"]],
                    "needs-work",
                    "Concurrent owned note",
                )
                return "written"
            except RecordError:
                return "collision"

        with (
            patch("whitehat.candidates._history", side_effect=snapshot),
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
            futures = [pool.submit(append) for _ in range(2)]
            results = [f.result(timeout=10) for f in futures]
        self.assertEqual(sorted(results), ["collision", "written"])
        self.assertEqual(len(candidate_history(directory)["decisions"]), 1)

    def test_history_gap_and_rehashed_malformed_record_rejected(self):
        document = self.http_result()
        directory = str(self.root / "candidate")
        initialize_candidate(directory, "owned-1", "owned", "Owned")
        record_decision(
            directory,
            str(self.root / "evidence.json"),
            [document["exchanges"][0]["evidenceSha256"]],
            "needs-work",
            "Owned note",
        )
        path = self.root / "candidate/decisions/000001.json"
        value = json.loads(path.read_text())
        value["decision"] = {}
        path.write_text(
            json.dumps(seal({k: v for k, v in value.items() if k != "resultSha256"}))
        )
        with self.assertRaises(ReportError):
            candidate_history(directory)
        path.rename(path.with_name("000002.json"))
        with self.assertRaisesRegex(ReportError, "gap"):
            candidate_history(directory)

    def test_unselected_and_tampered_comparison_cannot_escape_packet_validation(self):
        self.http_result("before.json")
        self.http_result("after.json", status=403)
        result = compare_http(
            str(self.root / "before.json"), str(self.root / "after.json")
        )
        self.write("comparison.json", result)
        initialize_packet(
            str(self.root / "packet.json"),
            "owned",
            "Owned",
            [str(self.root / "comparison.json")],
        )
        checked = check_packet(str(self.root / "packet.json"))
        self.assertTrue(
            any(i["code"] == "missing-linked-exchange" for i in checked["issues"])
        )
        result["contexts"] = "malformed"
        self.write(
            "comparison.json",
            seal({k: v for k, v in result.items() if k != "resultSha256"}),
        )
        checked = check_packet(str(self.root / "packet.json"))
        self.assertEqual(checked["verifiedEvidence"], [])

    def test_invalid_output_parent_produces_json_error_without_traceback(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "whitehat",
                "http",
                "prepare",
                self.write("source.har", self.capture()),
                "--project",
                "owned",
                "--output-dir",
                str(self.root / "missing/output"),
                "--json",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 3)
        self.assertEqual(json.loads(result.stdout)["error"]["code"], "invalid-input")
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
