import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from whitehat.fuzz_contracts import CASE_SCHEMA, load_batch, load_case
from whitehat.fuzz_corpus import (
    add_corpus,
    corpus_batch,
    extract_http,
    initialize_corpus,
    minimize_batch,
    reduce_case,
    regress_corpus,
)
from whitehat.fuzz_execution import run_batch
from whitehat.fuzz_fixture import owned_fuzz_api
from whitehat.fuzz_generation import generate_plan, initialize_plan, write_batch
from whitehat.fuzz_stateful import generate_stateful
from whitehat.graphql_tools import (
    graphql_inventory,
    graphql_mutation_plan,
    import_graphql_capture,
    inspect_operation,
)
from whitehat.http_evidence import digest, exchange
from whitehat.http_replay import replay
from whitehat.network_engine import NetworkExecutionError
from whitehat.records import save_result_document
from whitehat.relational import evaluate_assertions
from whitehat.reports import ReportError, canonical

ROOT = Path(__file__).resolve().parents[1]


def request(origin, method="GET", path="/state", body=None):
    return {
        "schemaVersion": "whitehat-prepared-request-v1",
        "method": method,
        "url": origin + path,
        "headers": {"Content-Type": "application/json"},
        "body": canonical(body).decode() if body is not None else None,
        "objectId": "owned-item",
        "operationId": "owned-operation",
    }


def step(name, value, identity="alice", statuses=None, values=None):
    return {
        "id": name,
        "request": value,
        "identityId": identity,
        "expect": {"statuses": statuses or [200], "values": values or {}, "absent": []},
    }


def assertion(name="owner-unchanged"):
    return {
        "id": name,
        "relation": "unchanged",
        "left": {
            "stepId": "before",
            "pointer": "/owner",
            "identityId": "alice",
            "objectId": "owned-item",
        },
        "right": {
            "stepId": "after",
            "pointer": "/owner",
            "identityId": "alice",
            "objectId": "owned-item",
        },
        "value": None,
    }


class FuzzTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.environment = patch.dict(
            os.environ,
            {
                "WHITEHAT_CREDENTIAL_ALICE": "owned-alice",
                "WHITEHAT_CREDENTIAL_BOB": "owned-bob",
            },
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical(value))
        return str(path)

    def authorize(self, directory, suffix=""):
        draft = json.loads((Path(directory) / "session.draft.json").read_text())
        draft["authority"].update(
            approved=True,
            researcherControlled=True,
            policy="Owned disposable fuzz fixture",
        )
        draft["sessionId"] = "owned-fuzz" + suffix
        draft["allowMutation"] = True
        draft["budgets"]["minDelayMs"] = 0
        for profile in draft["identities"]:
            profile.update(
                auth="bearer",
                credentialEnv="WHITEHAT_CREDENTIAL_" + profile["id"].upper(),
            )
        path = Path(directory) / "session.json"
        path.write_bytes(canonical(draft))
        return str(path), str(Path(directory) / "ledger.sqlite3")

    def property_case(self, origin):
        return {
            "schemaVersion": CASE_SCHEMA,
            "projectId": "owned",
            "id": "property-case",
            "setup": [
                step("setup-reset", request(origin, "POST", "/reset")),
                step("before", request(origin), values={"/owner": "alice"}),
            ],
            "steps": [
                step(
                    "change",
                    request(
                        origin,
                        "PATCH",
                        "/item",
                        {
                            "owner": "bob",
                            "quantity": 1,
                            "noise": "a long irrelevant value",
                        },
                    ),
                    "bob",
                ),
                step("after", request(origin)),
            ],
            "reset": [
                step("cleanup", request(origin, "POST", "/reset")),
                step(
                    "cleanup-check",
                    request(origin),
                    values={"/owner": "alice", "/quantity": 1, "/phase": "draft"},
                ),
            ],
            "assertions": [assertion()],
            "lineage": {"seed": 1, "engine": "owned-case"},
        }

    def run_cases(self, origin, cases, name="batch"):
        directory = self.root / name
        write_batch(str(directory), "owned", cases, {"kind": "owned-evaluation"})
        session, ledger = self.authorize(directory, name)
        result = run_batch(str(directory / "batch.json"), session, ledger)
        save_result_document(result, directory / "run.json")
        return directory, result

    def test_deterministic_capture_and_openapi_mutations_are_concrete(self):
        source = self.write(
            "request.json",
            request("https://owned.invalid", "PATCH", "/item", {"quantity": 1}),
        )
        schema = {
            "openapi": "3.0.3",
            "info": {"title": "Owned", "version": "1"},
            "paths": {
                "/item": {
                    "patch": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "quantity": {
                                                "type": "integer",
                                                "minimum": 0,
                                                "maximum": 10,
                                            }
                                        },
                                    }
                                }
                            }
                        },
                        "responses": {"200": {"description": "Owned"}},
                    }
                }
            },
        }
        initialize_plan(
            source,
            str(self.root / "plan.json"),
            "owned",
            "alice",
            schema_path=self.write("schema.json", schema),
        )
        with patch("socket.socket", side_effect=AssertionError("unexpected network")):
            first = generate_plan(
                str(self.root / "plan.json"), str(self.root / "first")
            )
            second = generate_plan(
                str(self.root / "plan.json"), str(self.root / "second")
            )
        self.assertEqual(first["batchSha256"], second["batchSha256"])
        _, cases = load_batch(str(self.root / "first/batch.json"))
        quantities = [
            json.loads(requests["test"]["body"])["quantity"] for _, requests in cases
        ]
        self.assertIn(-1, quantities)
        self.assertIn(11, quantities)
        self.assertTrue(
            any(case["lineage"]["dataMode"] == "negative" for case, _ in cases)
        )
        draft = json.loads((self.root / "first/session.draft.json").read_text())
        self.assertFalse(draft["authority"]["approved"])
        self.assertTrue(
            all(
                r["url"] == "https://owned.invalid/item"
                for _, rs in cases
                for r in rs.values()
            )
        )

    def test_missing_extra_keywords_and_credential_slots_are_rejected(self):
        source = self.write(
            "request.json",
            request("https://owned.invalid", "PATCH", "/item", {"quantity": 1}),
        )
        initialize_plan(source, str(self.root / "plan.json"), "owned", "alice")
        plan = json.loads((self.root / "plan.json").read_text())
        for pointer, unsupported in (("/password", []), ("/quantity", ["multipleOf"])):
            value = copy.deepcopy(plan)
            value["mutations"][0].update(
                pointer=pointer, unsupportedSchemaKeywords=unsupported
            )
            with self.assertRaises(ReportError):
                generate_plan(self.write("bad.json", value), str(self.root / "bad"))
            self.assertFalse((self.root / "bad").exists())

    def test_query_types_are_classified_after_wire_serialization(self):
        value = request("https://owned.invalid", path="/state?quantity=1")
        initialize_plan(
            self.write("request.json", value),
            str(self.root / "plan.json"),
            "owned",
            "alice",
        )
        plan = json.loads((self.root / "plan.json").read_text())
        plan["mutations"][0].update(
            schema={"type": "integer", "minimum": 0, "maximum": 10},
            values=["2"],
            omit=False,
        )
        generate_plan(self.write("plan.json", plan), str(self.root / "batch"))
        _, cases = load_batch(str(self.root / "batch/batch.json"))
        from urllib.parse import parse_qs, urlsplit

        generated = [
            (
                parse_qs(urlsplit(rs["test"]["url"]).query, keep_blank_values=True)[
                    "quantity"
                ][0],
                case["lineage"]["dataMode"],
            )
            for case, rs in cases
        ]
        self.assertIn(("0", "positive"), generated)
        self.assertIn(("true", "negative"), generated)
        plan["request"]["url"] = "https://owned.invalid/state?quantity=not-an-integer"
        with self.assertRaisesRegex(ReportError, "baseline"):
            generate_plan(self.write("bad.json", plan), str(self.root / "bad"))

    def test_readback_oracle_finds_hidden_change_and_reset_is_verified(self):
        for broken in (False, True):
            with owned_fuzz_api(vulnerable=broken) as (origin, state):
                _, result = self.run_cases(
                    origin,
                    [self.property_case(origin)],
                    "broken" if broken else "fixed",
                )
                case = result["provenance"]["cases"][0]
                self.assertEqual(
                    case["outcome"], "mismatch" if broken else "consistent"
                )
                self.assertEqual(case["cleanup"], "verified")
                self.assertEqual(state["owner"], "alice")
                self.assertEqual(state["requests"], 6)
                self.assertEqual(result["summary"]["observations"], 1 if broken else 0)
                self.assertNotIn("owned-alice", json.dumps(result))

    def test_all_requests_preflight_before_any_socket_and_no_budget_reset(self):
        with owned_fuzz_api() as (origin, state):
            directory = self.root / "batch"
            write_batch(str(directory), "owned", [self.property_case(origin)], {})
            session, ledger = self.authorize(directory)
            value = json.loads(Path(session).read_text())
            value["requestSha256"].pop()
            Path(session).write_bytes(canonical(value))
            with self.assertRaises(ReportError):
                run_batch(str(directory / "batch.json"), session, ledger)
            self.assertEqual(state["requests"], 0)
            self.assertFalse(Path(ledger).exists())
        with owned_fuzz_api() as (origin, state):
            directory, _ = self.run_cases(origin, [self.property_case(origin)], "valid")
            with self.assertRaises(ReportError):
                run_batch(
                    str(directory / "batch.json"),
                    str(directory / "session.json"),
                    str(directory / "ledger.sqlite3"),
                )
            self.assertEqual(state["requests"], 6)

    def test_ledger_claim_blocks_interleaving_and_snapshot_survives_source_edits(self):
        from whitehat.fuzz_execution import replay as actual_replay

        with owned_fuzz_api() as (origin, state):
            directory = self.root / "batch"
            write_batch(str(directory), "owned", [self.property_case(origin)], {})
            session, ledger = self.authorize(directory)
            batch, cases = load_batch(str(directory / "batch.json"))
            case = cases[0][0]
            original_path = directory / case["steps"][0]["request"]
            first = True

            def intercept(*args, **kwargs):
                nonlocal first
                if first:
                    first = False
                    with self.assertRaises(NetworkExecutionError):
                        replay(session, args[1], "alice", ledger)
                    original_path.write_text("{}")
                return actual_replay(*args, **kwargs)

            with patch("whitehat.fuzz_execution.replay", side_effect=intercept):
                result = run_batch(str(directory / "batch.json"), session, ledger)
            self.assertEqual(result["provenance"]["cases"][0]["cleanup"], "verified")
            self.assertEqual(state["requests"], 6)
            self.assertEqual(result["provenance"]["batchSha256"], digest(batch))

    def test_failed_reset_stops_later_cases(self):
        with owned_fuzz_api(vulnerable=True) as (origin, state):
            case = self.property_case(origin)
            case["reset"][-1]["expect"]["values"]["/owner"] = "bob"
            other = copy.deepcopy(case)
            other["id"] = "second"
            _, result = self.run_cases(origin, [case, other])
            self.assertFalse(result["provenance"]["complete"])
            self.assertEqual(len(result["provenance"]["cases"]), 1)
            self.assertEqual(result["provenance"]["cases"][0]["cleanup"], "incomplete")
            self.assertEqual(state["requests"], 6)

    def test_relational_missing_and_cross_object_evidence_stays_inconclusive(self):
        entries = {}
        for step_id, value in (("before", "alice"), ("after", "bob")):
            entries[step_id] = exchange(
                "owned",
                {"method": "GET", "url": "https://owned.invalid/state"},
                {"status": 200, "content": {"text": json.dumps({"owner": value})}},
                identity="alice",
                object_id="owned-item",
                operation="read",
                selected=["/owner"],
            )
        self.assertEqual(
            evaluate_assertions([assertion()], entries)[0]["outcome"], "mismatch"
        )
        entries["after"]["context"]["objectId"] = "different"
        self.assertEqual(
            evaluate_assertions([assertion()], entries)[0]["outcome"], "inconclusive"
        )
        del entries["after"]
        self.assertEqual(
            evaluate_assertions([assertion()], entries)[0]["outcome"], "inconclusive"
        )

    def test_reduction_minimization_corpus_dedup_and_regression(self):
        with owned_fuzz_api(vulnerable=True) as (origin, state):
            directory, original_run = self.run_cases(
                origin, [self.property_case(origin)]
            )
            case_path = str(directory / "case-property-case.json")
            reduction = self.root / "reduction"
            reduce_case(
                case_path,
                str(directory / "run.json"),
                str(reduction),
                "assertion:owner-unchanged",
            )
            session, ledger = self.authorize(reduction, "reduction")
            reduced_run = run_batch(str(reduction / "batch.json"), session, ledger)
            save_result_document(reduced_run, reduction / "run.json")
            minimized = minimize_batch(
                str(reduction / "batch.json"),
                str(reduction / "run.json"),
                str(self.root / "minimized"),
            )
            self.assertFalse(minimized["globalMinimumProven"])
            _, minimized_requests = load_case(self.root / "minimized/case.json")
            self.assertNotIn("noise", json.loads(minimized_requests["change"]["body"]))
            corpus = str(self.root / "corpus")
            initialize_corpus(corpus, "owned")
            first = add_corpus(
                corpus,
                str(self.root / "minimized/case.json"),
                str(reduction / "run.json"),
                "assertion:owner-unchanged",
            )
            duplicate = add_corpus(
                corpus,
                str(self.root / "minimized/case.json"),
                str(reduction / "run.json"),
                "assertion:owner-unchanged",
            )
            self.assertFalse(first["duplicate"])
            self.assertTrue(duplicate["duplicate"])
            regression = self.root / "regression"
            corpus_batch(corpus, str(regression))
            session, ledger = self.authorize(regression, "regression")
            tested = run_batch(str(regression / "batch.json"), session, ledger)
            save_result_document(tested, regression / "run.json")
            checked = regress_corpus(
                corpus, str(regression / "batch.json"), str(regression / "run.json")
            )
            self.assertEqual(checked["entries"][0]["outcome"], "reproduced")
            state["vulnerable"] = False
            fixed_directory = self.root / "fixed-regression"
            corpus_batch(corpus, str(fixed_directory))
            fixed_session, fixed_ledger = self.authorize(
                fixed_directory, "fixed-regression"
            )
            fixed_run = run_batch(
                str(fixed_directory / "batch.json"), fixed_session, fixed_ledger
            )
            save_result_document(fixed_run, fixed_directory / "run.json")
            fixed_checked = regress_corpus(
                corpus,
                str(fixed_directory / "batch.json"),
                str(fixed_directory / "run.json"),
            )
            self.assertEqual(fixed_checked["entries"][0]["outcome"], "not-observed")
            self.assertFalse(any(fixed_checked["claims"].values()))
            self.assertEqual(
                extract_http(str(directory / "run.json"))["resultSha256"],
                original_run["provenance"]["httpEvidence"]["resultSha256"],
            )

    def model(self, origin):
        return {
            "schemaVersion": "whitehat-stateful-model-v1",
            "projectId": "owned",
            "seed": 7,
            "maxCases": 4,
            "maxSteps": 3,
            "states": ["draft", "approved", "published"],
            "initialState": "draft",
            "setup": [step("setup", request(origin, "POST", "/reset"))],
            "readback": [step("after", request(origin))],
            "reset": [
                step("reset", request(origin, "POST", "/reset")),
                step("verified", request(origin), values={"/phase": "draft"}),
            ],
            "assertions": [],
            "actions": [
                {
                    "id": name,
                    "from": [before],
                    "to": after,
                    "step": step(name, request(origin, "POST", "/" + name)),
                    "invalidStatuses": [409],
                }
                for name, before, after in (
                    ("approve", "draft", "approved"),
                    ("publish", "approved", "published"),
                )
            ],
        }

    def test_stateful_sequences_detect_skipped_precondition_and_restore_state(self):
        for broken in (False, True):
            with owned_fuzz_api(vulnerable=broken) as (origin, state):
                model = self.write("model.json", self.model(origin))
                directory = self.root / ("broken" if broken else "fixed")
                generate_stateful(model, str(directory))
                session, ledger = self.authorize(directory, directory.name)
                result = run_batch(str(directory / "batch.json"), session, ledger)
                self.assertTrue(result["provenance"]["complete"])
                self.assertTrue(
                    all(
                        c["cleanup"] == "verified"
                        for c in result["provenance"]["cases"]
                    )
                )
                self.assertEqual(state["phase"], "draft")
                self.assertEqual(result["summary"]["observations"] > 0, broken)

    def test_graphql_operations_fragments_and_variable_plans(self):
        schema_path = self.root / "schema.graphql"
        schema_path.write_text(
            "type Item { id: ID! owner: String! } type Query { item(id: ID!): Item count(limit: Int): Int }"
        )
        self.assertEqual(
            len(graphql_inventory(str(schema_path), "owned")["operations"]), 2
        )
        query = "query Read($id: ID!) { alias: item(id: $id) { ...Fields } } fragment Fields on Item { id owner }"
        document_path = self.root / "query.graphql"
        document_path.write_text(query)
        inspected = inspect_operation(str(schema_path), str(document_path), "owned")
        self.assertEqual(inspected["operation"]["variables"], {"id": "ID!"})
        self.assertTrue(
            any(
                f["fieldPath"] == "/item/owner"
                for f in inspected["operation"]["fields"]
            )
        )
        document_path.write_text(query.replace("id owner", "id"))
        self.assertNotEqual(
            inspected["operation"]["operationId"],
            inspect_operation(str(schema_path), str(document_path), "owned")[
                "operation"
            ]["operationId"],
        )
        value = request(
            "https://owned.invalid",
            "POST",
            "/graphql",
            {"query": query, "variables": {"id": "owned-value"}},
        )
        source = self.write("request.json", value)
        graphql_mutation_plan(
            str(schema_path), source, str(self.root / "plan.json"), "owned", "alice"
        )
        generate_plan(str(self.root / "plan.json"), str(self.root / "generated"))
        _, cases = load_batch(str(self.root / "generated/batch.json"))
        self.assertTrue(
            all(
                c["assertions"][0]["left"]["pointer"] == "/errors/0/message"
                for c, _ in cases
            )
        )
        numeric = [
            c
            for c, rs in cases
            if json.loads(rs["test"]["body"]).get("variables", {}).get("id") == 0
            and type(json.loads(rs["test"]["body"]).get("variables", {}).get("id"))
            is int
        ]
        self.assertTrue(numeric)
        self.assertEqual(numeric[0]["lineage"]["dataMode"], "positive")

    def test_graphql_capture_distinguishes_operations_without_exporting_values(self):
        schema_path = self.root / "schema.graphql"
        schema_path.write_text(
            "type Query { count(limit: Int): Int echo(text: String): String }"
        )
        entries = []
        for query in (
            "query A($limit:Int){count(limit:$limit)}",
            "query B($text:String){echo(text:$text)}",
        ):
            entries.append(
                {
                    "request": {
                        "method": "POST",
                        "url": "https://owned.invalid/graphql",
                        "postData": {
                            "text": json.dumps(
                                {
                                    "query": query,
                                    "variables": {"text": "PRIVATE-VARIABLE-VALUE"},
                                }
                            )
                        },
                    },
                    "response": {
                        "status": 200,
                        "content": {
                            "text": '{"data":{"count":1},"errors":[{"message":"owned error"}]}'
                        },
                    },
                }
            )
        result = import_graphql_capture(
            str(schema_path),
            self.write("capture.har", {"log": {"version": "1.2", "entries": entries}}),
            "owned",
            ["/errors/0/message"],
            "alice",
            "owned-item",
        )
        self.assertNotEqual(
            result["exchanges"][0]["observationId"],
            result["exchanges"][1]["observationId"],
        )
        self.assertNotIn("PRIVATE-VARIABLE-VALUE", json.dumps(result))
        self.assertEqual(
            result["exchanges"][0]["response"]["json"]["values"]["/errors/0/message"],
            "owned error",
        )

    def test_cli_generation_and_invalid_source_profile_are_structured(self):
        def command(*args):
            return subprocess.run(
                [sys.executable, "-B", "-m", "whitehat", *args, "--json"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30,
            )

        path = self.write(
            "request.json",
            request("https://owned.invalid", "PATCH", "/item", {"quantity": 1}),
        )
        planned = command(
            "fuzz",
            "plan",
            path,
            "--project",
            "owned",
            "--identity",
            "alice",
            "--output",
            str(self.root / "plan.json"),
        )
        self.assertEqual(planned.returncode, 0, planned.stdout + planned.stderr)
        self.assertFalse(json.loads(planned.stdout)["effects"]["network"])
        generated = command(
            "fuzz",
            "generate",
            str(self.root / "plan.json"),
            "--output-dir",
            str(self.root / "generated"),
        )
        self.assertEqual(generated.returncode, 0, generated.stdout + generated.stderr)
        duplicate = command(
            "fuzz",
            "generate",
            str(self.root / "plan.json"),
            "--output-dir",
            str(self.root / "generated"),
        )
        self.assertEqual(duplicate.returncode, 3)
        self.assertFalse(json.loads(duplicate.stdout)["ok"])

    def test_source_worker_result_framing_rejects_missing_or_duplicate_records(self):
        from whitehat.fuzz_source import _worker_result
        expected = {"schemaVersion": "owned-worker"}
        framed = b"libFuzzer output\nWHITEHAT_RESULT=" + canonical(expected) + b"\nmore tool output\n"
        self.assertEqual(_worker_result(framed), expected)
        for raw in (b"tool output only", framed + b"WHITEHAT_RESULT={}\n"):
            with self.assertRaises(ReportError):
                _worker_result(raw)

    def test_graphql_rejects_cycles_subscriptions_and_ambiguous_operations(self):
        schema = self.root / "schema.graphql"
        schema.write_text(
            "type Item { child: Item } type Query { item: Item } type Subscription { changed: Int }"
        )
        for query in (
            "query { item { ...A } } fragment A on Item { ...A }",
            "query A { item { __typename } } query B { item { __typename } }",
            "subscription { changed }",
        ):
            path = self.root / "query.graphql"
            path.write_text(query)
            with self.assertRaises(ReportError):
                inspect_operation(str(schema), str(path), "owned")

    def test_relational_types_and_error_presence_do_not_conflate_values(self):
        rule = {
            "id": "equal",
            "relation": "equals",
            "left": {
                "stepId": "left",
                "pointer": "/value",
                "identityId": "alice",
                "objectId": "owned-item",
            },
            "right": {
                "stepId": "right",
                "pointer": "/value",
                "identityId": "alice",
                "objectId": "owned-item",
            },
            "value": None,
        }
        entries = {
            name: exchange(
                "owned",
                {"method": "GET", "url": "https://owned.invalid/state"},
                {"status": 200, "content": {"text": json.dumps({"value": value})}},
                identity="alice",
                object_id="owned-item",
                operation="read",
                selected=["/value"],
            )
            for name, value in (("left", True), ("right", 1))
        }
        self.assertEqual(evaluate_assertions([rule], entries)[0]["outcome"], "mismatch")
        rule.update(relation="delta", value=0)
        self.assertEqual(
            evaluate_assertions([rule], entries)[0]["outcome"], "inconclusive"
        )
        error = exchange(
            "owned",
            {"method": "POST", "url": "https://owned.invalid/graphql"},
            {
                "status": 400,
                "content": {"text": '{"errors":[{"message":"owned error"}]}'},
            },
            identity="alice",
            object_id="owned-item",
            operation="read",
            selected=["/errors/0/message"],
        )
        rule.update(
            relation="present",
            value=None,
            right=None,
            left={
                "stepId": "error",
                "pointer": "/errors/0/message",
                "identityId": "alice",
                "objectId": "owned-item",
            },
        )
        self.assertEqual(
            evaluate_assertions([rule], {"error": error})[0]["outcome"], "consistent"
        )

    def test_fuzz_output_collision_is_rejected_before_execution(self):
        with owned_fuzz_api() as (origin, state):
            directory = self.root / "batch"
            write_batch(str(directory), "owned", [self.property_case(origin)], {})
            session, ledger = self.authorize(directory)
            output = self.write("already.json", {})
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "whitehat",
                    "fuzz",
                    "run",
                    str(directory / "batch.json"),
                    "--session",
                    session,
                    "--state",
                    ledger,
                    "--output",
                    output,
                    "--json",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(completed.returncode, 3)
            self.assertFalse(json.loads(completed.stdout)["ok"])
            self.assertEqual(state["requests"], 0)
            self.assertFalse(Path(ledger).exists())

    @unittest.skipUnless(
        sys.platform == "linux"
        and sys.version_info >= (3, 12)
        and __import__("importlib.util", fromlist=["find_spec"]).find_spec("atheris"),
        "optional Linux Atheris profile",
    )
    def test_actual_atheris_owned_twins_and_parser_profile(self):
        from whitehat.fuzz_source import source_fuzz

        fixed = source_fuzz("owned-fixed", str(self.root / "source-fixed"), runs=100)
        broken = source_fuzz("owned-broken", str(self.root / "source-broken"), runs=100)
        parser = source_fuzz(
            "capture-parser", str(self.root / "source-parser"), runs=100
        )
        self.assertIsNone(fixed["failureInputSha256"])
        self.assertEqual(broken["failureClass"], "AssertionError")
        self.assertTrue((self.root / "source-broken/source-case.json").is_file())
        self.assertIsNone(parser["failureInputSha256"])
        self.assertTrue(
            all(
                v["callbacks"] > 0 and not v["effects"]["network"]
                for v in (fixed, broken, parser)
            )
        )


if __name__ == "__main__":
    unittest.main()
