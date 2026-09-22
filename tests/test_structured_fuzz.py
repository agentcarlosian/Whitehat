import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from whitehat.fuzz_contracts import load_batch
from whitehat.fuzz_execution import run_batch
from whitehat.fuzz_fixture import owned_fuzz_api
from whitehat.fuzz_generation import (
    generate_plan,
    initialize_plan,
    mutation_schema,
    valid_input,
)
from whitehat.graphql_tools import graphql_module, graphql_mutation_plan
from whitehat.reports import ReportError, canonical


class StructuredFuzzTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, value):
        path = self.root / name
        path.write_bytes(canonical(value))
        return str(path)

    def request(self, body, origin="https://owned.invalid", path="/array-check"):
        return {
            "schemaVersion": "whitehat-prepared-request-v1",
            "method": "POST",
            "url": origin + path,
            "headers": {"Content-Type": "application/json"},
            "body": canonical(body).decode(),
            "objectId": "owned-item",
            "operationId": "check",
        }

    def plan(self, required=True, origin="https://owned.invalid"):
        spec = {
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 3,
                    "uniqueItems": True,
                    "items": {"type": "integer", "minimum": 0, "maximum": 10},
                }
            },
            "required": ["items"] if required else [],
        }
        schema = {
            "openapi": "3.0.3",
            "info": {"title": "Owned arrays", "version": "1"},
            "paths": {
                "/array-check": {
                    "post": {
                        "requestBody": {
                            "content": {"application/json": {"schema": spec}}
                        },
                        "responses": {"200": {"description": "Owned"}},
                    }
                }
            },
        }
        initialize_plan(
            self.write("request.json", self.request({"items": [1]}, origin)),
            str(self.root / "plan.json"),
            "owned",
            "alice",
            schema_path=self.write("schema.json", schema),
        )
        plan = json.loads((self.root / "plan.json").read_text())
        plan.update(maxCases=32, samplesPerField=4)
        self.write("plan.json", plan)
        return plan

    def generate(self, plan, name="batch"):
        path = self.write("generate-plan.json", plan)
        receipt = generate_plan(path, str(self.root / name))
        _, cases = load_batch(str(self.root / name / "batch.json"))
        return receipt, cases

    def test_array_boundaries_deterministic_and_classified(self):
        plan = self.plan()
        with patch("socket.socket", side_effect=AssertionError("unexpected network")):
            receipt, cases = self.generate(plan)
            other, _ = self.generate(plan, "second")
        self.assertEqual(receipt["batchSha256"], other["batchSha256"])
        generated = [
            (json.loads(rs["test"]["body"]), c["lineage"]["dataMode"])
            for c, rs in cases
        ]
        self.assertIn(({}, "negative"), generated)
        self.assertIn(({"items": []}, "negative"), generated)
        values = [body["items"] for body, _ in generated if "items" in body]
        self.assertTrue(any(isinstance(v, list) and len(v) == 4 for v in values))
        self.assertTrue(
            any(isinstance(v, list) and len(v) == 2 and v[0] == v[1] for v in values)
        )
        self.assertTrue(
            any(
                isinstance(v, list) and any(type(x) is not int for x in v)
                for v in values
            )
        )
        for body, mode in generated:
            items = body.get("items")
            valid = (
                isinstance(items, list)
                and 1 <= len(items) <= 3
                and all(type(v) is int and 0 <= v <= 10 for v in items)
            )
            if valid:
                valid = len(set(items)) == len(items)
            self.assertEqual(mode, "positive" if valid else "negative")
        draft = json.loads((self.root / "batch/session.draft.json").read_text())
        self.assertFalse(draft["authority"]["approved"])

    def test_optional_omission_and_no_hypothesis_requirement(self):
        plan = self.plan(required=False)
        plan["samplesPerField"] = 0
        with patch(
            "whitehat.fuzz_generation.importlib.metadata.version",
            side_effect=AssertionError("optional dependency queried"),
        ):
            _, cases = self.generate(plan)
        self.assertTrue(
            any(
                json.loads(rs["test"]["body"]) == {}
                and c["lineage"]["dataMode"] == "positive"
                for c, rs in cases
            )
        )

    def test_unsupported_items_keywords_invalid_bounds_and_query_arrays_reject(self):
        plan = self.plan()
        variants = []
        for spec in (
            {"type": "array", "items": {"type": "object"}},
            {"type": "array", "items": {"type": "integer"}, "maxItems": 33},
            {
                "type": "array",
                "items": {"type": "integer"},
                "minItems": 3,
                "maxItems": 1,
            },
        ):
            value = copy.deepcopy(plan)
            value["mutations"][0]["schema"] = spec
            variants.append(value)
        value = copy.deepcopy(plan)
        value["mutations"][0]["unsupportedSchemaKeywords"] = ["items.multipleOf"]
        variants.append(value)
        value = copy.deepcopy(plan)
        value["mutations"][0]["location"] = "query"
        variants.append(value)
        for value in variants:
            with self.assertRaises(ReportError):
                self.generate(value)
            self.assertFalse((self.root / "batch").exists())

    def test_openapi_item_constraints_are_not_silently_dropped(self):
        self.plan()
        schema = json.loads((self.root / "schema.json").read_text())
        item = schema["paths"]["/array-check"]["post"]["requestBody"]["content"][
            "application/json"
        ]["schema"]["properties"]["items"]["items"]
        item["multipleOf"] = 2
        initialize_plan(
            str(self.root / "request.json"),
            str(self.root / "unsupported.json"),
            "owned",
            "alice",
            schema_path=self.write("schema.json", schema),
        )
        plan = json.loads((self.root / "unsupported.json").read_text())
        self.assertEqual(
            plan["mutations"][0]["unsupportedSchemaKeywords"], ["items.multipleOf"]
        )
        with self.assertRaises(ReportError):
            self.generate(plan)

    def test_array_twins_through_real_reviewed_replay(self):
        for broken in (False, True):
            # A POST validation endpoint with no persistent mutation.
            with owned_fuzz_api(vulnerable=broken) as (origin, state):
                plan_path = self.root / "plan.json"
                if plan_path.exists():
                    plan_path.unlink()
                plan = self.plan(origin=origin)
                self.generate(plan, str(broken))
                directory = self.root / str(broken)
                session = json.loads((directory / "session.draft.json").read_text())
                session["authority"].update(
                    approved=True,
                    researcherControlled=True,
                    policy="Owned array fixture",
                )
                session["allowMutation"] = True
                session["budgets"]["minDelayMs"] = 0
                session["identities"][0].update(
                    auth="bearer", credentialEnv="WHITEHAT_CREDENTIAL_ALICE"
                )
                session_path = self.write("session.json", session)
                with patch.dict(
                    os.environ, {"WHITEHAT_CREDENTIAL_ALICE": "owned-alice"}
                ):
                    run = run_batch(
                        str(directory / "batch.json"),
                        session_path,
                        str(directory / "ledger.sqlite3"),
                    )
                self.assertTrue(run["provenance"]["complete"])
                self.assertEqual(run["summary"]["observations"] > 0, broken)
                self.assertGreater(state["requests"], 1)

    def test_graphql_inputs_match_actual_variable_coercion(self):
        gql = graphql_module()
        source = """enum Color { RED BLUE }
            input Child { id: ID! count: Int! = 3 }
            input Filter { child: Child! colors: [Color!]! enabled: Boolean }
            type Query { check(filter: Filter!, ids: [ID!], optional: Filter): Boolean }
        """
        query = "query Check($f: Filter!, $ids: [ID!], $optional: Filter) { check(filter: $f, ids: $ids, optional: $optional) }"
        body = {
            "query": query,
            "variables": {
                "f": {"child": {"id": 7}, "colors": ["RED"]},
                "ids": [3],
                "optional": None,
            },
        }
        schema_path = self.root / "schema.graphql"
        schema_path.write_text(source, encoding="utf-8")
        graphql_mutation_plan(
            str(schema_path),
            self.write("graphql-request.json", self.request(body, path="/graphql")),
            str(self.root / "graphql-plan.json"),
            "owned",
            "alice",
        )
        plan = json.loads((self.root / "graphql-plan.json").read_text())
        plan.update(maxCases=32, samplesPerField=2)
        _, cases = self.generate(plan)
        document = gql.parse(query)
        definitions = gql.get_operation_ast(document).variable_definitions
        schema = gql.build_schema(source)
        for case, requests in cases:
            variables = json.loads(requests["test"]["body"])["variables"]
            coerced = gql.get_variable_values(schema, definitions, variables)
            self.assertEqual(
                case["lineage"]["dataMode"],
                "negative" if isinstance(coerced, list) else "positive",
                variables,
            )

    def test_graphql_recursive_custom_and_credential_fields_reject(self):
        for type_source in (
            "input Filter { child: Filter }",
            "scalar Custom\ninput Filter { child: Custom }",
            "input Filter { password: String }",
            "input Filter { child: [[Int]] }",
        ):
            (self.root / "schema.graphql").write_text(
                type_source + "\ntype Query { check(f: Filter): Boolean }",
                encoding="utf-8",
            )
            body = {
                "query": "query($f: Filter) { check(f: $f) }",
                "variables": {"f": {}},
            }
            with self.assertRaises(ReportError):
                graphql_mutation_plan(
                    str(self.root / "schema.graphql"),
                    self.write("request.json", self.request(body, path="/graphql")),
                    str(self.root / "bad.json"),
                    "owned",
                    "alice",
                )
            self.assertFalse((self.root / "bad.json").exists())

    def test_array_boolean_integer_distinction_and_typed_uniqueness(self):
        spec = mutation_schema(
            {"type": "array", "items": {"type": "integer"}, "uniqueItems": True}
        )
        self.assertFalse(valid_input([True], spec))
        self.assertFalse(valid_input([1, 1], spec))
        self.assertTrue(valid_input([1, 2], spec))
        numbers = mutation_schema(
            {"type": "array", "items": {"type": "number"}, "uniqueItems": True}
        )
        self.assertFalse(valid_input([1, 1.0], numbers))
        self.assertFalse(
            valid_input(10**400, {"type": "number", "graphqlType": "Float"})
        )

    def test_authored_input_schema_node_budget(self):
        leaf = {
            "type": "object",
            "graphqlType": "input",
            "required": [],
            "properties": {"field" + str(n): {"type": "string"} for n in range(16)},
        }
        root = {
            "type": "object",
            "graphqlType": "input",
            "required": [],
            "properties": {"left": leaf, "right": leaf},
        }
        with self.assertRaises(ReportError):
            mutation_schema(root)


if __name__ == "__main__":
    unittest.main()
