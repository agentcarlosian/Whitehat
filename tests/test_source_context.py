import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from whitehat.packets import export_packet, initialize_packet
from whitehat.records import save_result_document
from whitehat.reports import (
    ReportError,
    ReportLimitError,
    canonical,
    checked_research_result,
    compare_results,
    import_report,
    normalize,
    seal,
)
from whitehat.research import export_markdown
from whitehat.source_context import opengrep_context, validate_context

ROOT = Path(__file__).resolve().parents[1]


class SourceContextTests(unittest.TestCase):
    def test_cached_thread_locations_require_matching_properties_and_self_index(self):
        value = self.fixture()
        value["runs"][0]["threadFlowLocations"][0]["index"] = 0
        self.assertTrue(
            normalize(canonical(value), "sarif")[0]["sourceContext"][
                "representationComplete"
            ]
        )
        step = self.result(value)["codeFlows"][0]["threadFlows"][0]["locations"][0]
        step["executionOrder"] = 42
        with self.assertRaises(ReportError):
            normalize(canonical(value), "sarif")
        del step["executionOrder"]
        value["runs"][0]["threadFlowLocations"][0]["index"] = 1
        with self.assertRaises(ReportError):
            normalize(canonical(value), "sarif")

    def fixture(self):
        return json.loads((ROOT / "examples/reports/source-flow.sarif").read_text())

    def result(self, value):
        return value["runs"][0]["results"][0]

    def test_sarif_secondary_locations_and_indexed_flows_are_inert_redacted(self):
        with (
            patch("socket.socket", side_effect=AssertionError("unexpected network")),
            patch("builtins.open", side_effect=AssertionError("source file opened")),
        ):
            records = normalize(canonical(self.fixture()), "sarif")
        context = records[0]["sourceContext"]
        self.assertEqual(
            [v["path"] for v in context["relatedLocations"]],
            ["src/app.ts", "src/guards.ts"],
        )
        steps = context["flows"][0]["steps"]
        self.assertEqual(
            [s["kinds"] for s in steps], [["source"], ["condition"], ["sink"]]
        )
        self.assertEqual([s["executionOrder"] for s in steps], [1, 2, 3])
        self.assertTrue(context["representationComplete"])
        self.assertEqual(context["validation"], "unverified")
        for secret in (
            "synthetic-private-value",
            "untrusted analyzer text",
            "snippet",
            "state",
        ):
            self.assertNotIn(secret, json.dumps(records))

    def test_added_flow_context_preserves_fingerprint_and_reports_metadata_change(self):
        value = self.fixture()
        plain = copy.deepcopy(value)
        del self.result(plain)["codeFlows"]
        del self.result(plain)["relatedLocations"]
        self.result(plain)["locations"] = self.result(plain)["locations"][:1]
        self.assertEqual(
            normalize(canonical(value), "sarif")[0]["fingerprint"],
            normalize(canonical(plain), "sarif")[0]["fingerprint"],
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, report in (("before", plain), ("after", value)):
                raw = root / (name + ".sarif")
                raw.write_bytes(canonical(report))
                save_result_document(
                    import_report(str(raw), "sarif"), root / (name + ".json")
                )
            compared = compare_results(
                str(root / "before.json"), str(root / "after.json")
            )
        self.assertEqual(compared["summary"]["metadataChanged"], 1)
        self.assertEqual(compared["summary"]["introduced"], 0)
        self.assertTrue(compared["sameAnalysisProfile"])

    def test_secondary_and_flow_path_escape_rejects(self):
        for path in (
            "../private",
            "/etc/private",
            "https://owned.invalid/x",
            "src/%2e%2e/private",
            "C:/private.txt",
        ):
            for field in ("related", "flow"):
                value = self.fixture()
                location = (
                    self.result(value)["relatedLocations"][0]
                    if field == "related"
                    else self.result(value)["codeFlows"][0]["threadFlows"][0][
                        "locations"
                    ][1]["location"]
                )
                location["physicalLocation"]["artifactLocation"] = {"uri": path}
                with (
                    self.subTest(path=path, field=field),
                    self.assertRaises(ReportError),
                ):
                    normalize(canonical(value), "sarif")

    def test_partial_flow_is_visible_and_unknown_labels_are_not_retained(self):
        value = self.fixture()
        steps = self.result(value)["codeFlows"][0]["threadFlows"][0]["locations"]
        steps[0]["index"] = 100
        steps[1]["location"]["physicalLocation"]["artifactLocation"]["uriBaseId"] = (
            "PRIVATE_BASE"
        )
        steps[1]["kinds"].append("synthetic-private-value")
        context = normalize(canonical(value), "sarif")[0]["sourceContext"]
        self.assertFalse(context["representationComplete"])
        self.assertEqual(len(context["flows"][0]["steps"]), 3)
        self.assertIn("unresolved-thread-location", context["diagnostics"])
        self.assertIn("unresolved-uri-base", context["diagnostics"])
        self.assertNotIn("PRIVATE_BASE", json.dumps(context))
        self.assertNotIn("synthetic-private-value", json.dumps(context))

    def test_flow_counts_and_malformed_coordinates_reject(self):
        for count in (65,):
            value = self.fixture()
            thread = self.result(value)["codeFlows"][0]["threadFlows"][0]
            thread["locations"] = [thread["locations"][0]] * count
            with self.assertRaises(ReportLimitError):
                normalize(canonical(value), "sarif")
        for bad in (True, -1, "3"):
            value = self.fixture()
            self.result(value)["relatedLocations"][0]["physicalLocation"]["region"][
                "startLine"
            ] = bad
            with self.assertRaises(ReportError):
                normalize(canonical(value), "sarif")
        value = self.fixture()
        value["runs"][0]["results"] *= 2001
        with self.assertRaises(ReportLimitError):
            normalize(canonical(value), "sarif")

    def test_native_flow_snippets_omitted_and_call_trace_marked_partial(self):
        loc = {
            "path": "src/app.ts",
            "start": {"line": 3, "col": 4},
            "end": {"line": 3, "col": 10},
        }
        trace = {
            "taint_source": ["CliLoc", [loc, "synthetic-private-value"]],
            "intermediate_vars": [
                {"location": loc, "content": "synthetic-private-value"}
            ],
            "taint_sink": ["CliLoc", [loc, "synthetic-private-value"]],
        }
        context = opengrep_context(trace)
        self.assertEqual(len(context["flows"][0]["steps"]), 3)
        self.assertNotIn("synthetic-private-value", json.dumps(context))
        trace["taint_source"] = ["CliCall", {"content": "synthetic-private-value"}]
        self.assertFalse(opengrep_context(trace)["representationComplete"])
        trace["taint_sink"][1][0]["path"] = "../outside"
        with self.assertRaises(ReportError):
            opengrep_context(trace)

    def test_rehashed_metadata_cannot_assert_verified_or_smuggle_fields(self):
        original = normalize(canonical(self.fixture()), "sarif")[0]["sourceContext"]
        with self.assertRaises(ReportError):
            validate_context(None)
        for field, content in (
            ("validation", "verified"),
            ("extra", "synthetic-private-value"),
            ("representationComplete", False),
        ):
            context = copy.deepcopy(original)
            context[field] = content
            with self.assertRaises(ReportError):
                validate_context(context)
        with tempfile.TemporaryDirectory() as temp:
            result = import_report(
                str(ROOT / "examples/reports/source-flow.sarif"), "sarif"
            )
            result["observations"][0]["sourceContext"]["validation"] = "verified"
            del result["resultSha256"]
            path = Path(temp, "result.json")
            save_result_document(seal(result), path)
            with self.assertRaises(ReportError):
                checked_research_result(str(path))

    def test_markdown_and_packet_include_locations_not_untrusted_text(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = import_report(
                str(ROOT / "examples/reports/source-flow.sarif"), "sarif"
            )
            save_result_document(result, root / "result.json")
            export_markdown(str(root / "result.json"), str(root / "review.md"))
            initialize_packet(
                str(root / "packet.json"),
                "owned",
                "Owned source review",
                [str(root / "result.json")],
            )
            export_packet(str(root / "packet.json"), str(root / "packet.md"))
            for name in ("review.md", "packet.md"):
                content = (root / name).read_text()
                self.assertIn("src/app", content)
                self.assertIn("condition", content)
                self.assertIn("unverified", content)
                self.assertNotIn("synthetic-private-value", content)
                self.assertNotIn("untrusted analyzer text", content)


if __name__ == "__main__":
    unittest.main()
