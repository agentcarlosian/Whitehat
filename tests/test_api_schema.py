import json
import tempfile
import unittest
from pathlib import Path

from whitehat.api_schema import (
    inventory_schema,
    compare_schema,
    load_schema,
    inventory_value,
)
from whitehat.native_tools import TOOLS, platform_key
from whitehat.reports import ReportError

ROOT = Path(__file__).resolve().parents[1]


def oasdiff_path():
    try:
        return (
            ROOT
            / ".whitehat/tools/oasdiff"
            / TOOLS["oasdiff"]["platforms"][platform_key()]["executable"]
        )
    except ReportError:
        return ROOT / ".whitehat/unsupported"


class ApiSchemaTests(unittest.TestCase):
    def test_security_override_and_or_and_semantics(self):
        schema = load_schema(str(ROOT / "examples/api/before.json"))
        schema["security"] = [{"key": [], "oauth": ["read"]}, {"alternative": []}]
        first = inventory_value(schema, "owned")["operations"][0]
        self.assertEqual(len(first["securityAlternatives"]), 2)
        self.assertFalse(first["anonymousDeclared"])
        schema["paths"]["/items"]["get"]["security"] = []
        second = inventory_value(schema, "owned")["operations"][0]
        self.assertTrue(second["anonymousDeclared"])

    def test_external_refs_and_duplicate_json_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "schema.json")
            schema = {
                "openapi": "3.0.3",
                "paths": {},
                "components": {
                    "schemas": {"leak": {"$ref": "https://unapproved.invalid/schema"}}
                },
            }
            path.write_text(json.dumps(schema))
            with self.assertRaisesRegex(ReportError, "external"):
                load_schema(str(path))
            path.write_text('{"openapi":"3.0.3","paths":{},"paths":{}}')
            with self.assertRaises(ReportError):
                load_schema(str(path))

    def test_inventory_reports_response_fields(self):
        result = inventory_schema(str(ROOT / "examples/api/after.json"), "owned")
        self.assertEqual(
            result["operations"][0]["responseProperties"]["200"], ["id", "internalFlag"]
        )

    @unittest.skipUnless(oasdiff_path().is_file(), "explicit oasdiff setup required")
    def test_actual_oasdiff_and_effective_authentication_change(self):
        result = compare_schema(
            str(ROOT / "examples/api/before.json"),
            str(ROOT / "examples/api/after.json"),
            "owned",
            str(oasdiff_path()),
        )
        codes = {item["ruleId"] for item in result["observations"]}
        self.assertIn("response-optional-property-added", codes)
        self.assertIn("effective-security-changed", codes)
        self.assertFalse(result["effects"]["network"])


if __name__ == "__main__":
    unittest.main()
