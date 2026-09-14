import copy
import json
import tempfile
import unittest
from pathlib import Path

from whitehat.records import save_result_document
from whitehat.reports import (
    ReportError, ReportLimitError, canonical, compare_results, endpoint,
    import_report, normalize, parse_json, read_bytes, relative_path, seal,
)

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "examples" / "reports"


class ReportTests(unittest.TestCase):
    def test_all_documented_imports_are_inert_and_redact_values(self):
        for format_name, filename in [("osv", "osv.json"), ("sarif", "source.sarif"),
                                      ("zap", "zap.json"), ("nuclei", "nuclei.jsonl"),
                                      ("betterleaks", "secrets.json"), ("gitleaks", "secrets.json")]:
            with self.subTest(format=format_name):
                result = import_report(str(REPORTS / filename), format_name)
                self.assertEqual(result["summary"]["observations"], 1)
                self.assertFalse(any(result["effects"].values()))
                self.assertFalse(any(result["claims"].values()))
                self.assertFalse(result["provenance"]["executionVerified"])
                rendered = json.dumps(result)
                for private in ("synthetic-private-value", "omitted identity", "omitted evidence", "must not be retained", "untrusted analyzer text"):
                    self.assertNotIn(private, rendered)

    def test_duplicate_keys_nonfinite_and_nonobjects_are_rejected(self):
        for raw in (b'{"site":[],"site":[]}', b'{"a":NaN}', b'{"a":Infinity}', b'[]', b'null'):
            with self.subTest(raw=raw), self.assertRaises(ReportError):
                normalize(raw, "zap")

    def test_oversized_report_is_rejected_before_parsing(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "input.json")
            path.write_bytes(b"[]xxxx")
            with self.assertRaises(ReportLimitError):
                read_bytes(path, 3)

    def test_relative_paths_and_explicit_absolute_prefix(self):
        self.assertEqual(relative_path("C:\\source\\app.py", "C:\\source"), "app.py")
        self.assertEqual(relative_path("file:///workspace/src/app.py", "/workspace/src"), "app.py")
        for value in ("../x", "/etc/passwd", "C:/private/x", "x/%2e%2e/y", "x/..\\y", "https://bad.invalid/x", "a\n.py"):
            with self.subTest(path=value), self.assertRaises(ReportError):
                relative_path(value)

    def test_endpoint_values_and_credentials(self):
        self.assertEqual(endpoint("https://demo.invalid/a?secret=private#private"), "https://demo.invalid/a")
        for value in ("https://u:p@demo.invalid/a", "file:///tmp/a", "https://demo.invalid:invalid/a"):
            with self.assertRaises(ReportError):
                endpoint(value)

    def test_sarif_rule_index_and_missing_location(self):
        value = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL", "rules": [{"id": "test-rule"}]}}, "results": [{"ruleIndex": 0}]}]}
        result = normalize(canonical(value), "sarif")
        self.assertEqual(result[0]["ruleId"], "test-rule")
        self.assertIsNone(result[0]["path"])
        value["runs"][0]["results"][0]["ruleIndex"] = True
        with self.assertRaises(ReportError):
            normalize(canonical(value), "sarif")

    def test_empty_valid_report_differs_from_malformed_report(self):
        self.assertEqual(normalize(b'{"results":[]}', "osv"), [])
        self.assertEqual(normalize(b'null', "betterleaks"), [])
        with self.assertRaises(ReportError):
            normalize(b'{}', "osv")

    def test_osv_fix_references_are_bound_to_exact_package(self):
        value = parse_json((REPORTS / "osv.json").read_bytes())
        vuln = value["results"][0]["packages"][0]["vulnerabilities"][0]
        unrelated = copy.deepcopy(vuln["affected"][0])
        unrelated["package"]["name"] = "different-package"
        unrelated["ranges"][0]["events"] = [{"fixed": "99.0.0"}]
        vuln["affected"].append(unrelated)
        result = normalize(canonical(value), "osv")[0]
        self.assertEqual(result["context"]["fixedVersionsReported"], ["1.0.1"])
        self.assertEqual(result["context"]["reachability"], "unverified")

    def test_opengrep_errors_and_empty_scan(self):
        with self.assertRaises(ReportError):
            normalize(b'{"results":[],"errors":[{"message":"parse error"}]}', "opengrep")
        self.assertEqual(normalize(b'{"results":[],"errors":[]}', "opengrep"), [])

    def test_duplicate_observations_and_comparison(self):
        with tempfile.TemporaryDirectory() as temp:
            repeated = Path(temp, "input.jsonl")
            repeated.write_bytes((REPORTS / "nuclei.jsonl").read_bytes() * 2)
            baseline = import_report(str(repeated), "nuclei")
            self.assertEqual(baseline["summary"]["duplicatesRemoved"], 1)
            before, after = Path(temp, "before.json"), Path(temp, "after.json")
            save_result_document(baseline, before)
            repeated.write_bytes(b"")
            save_result_document(import_report(str(repeated), "nuclei"), after)
            comparison = compare_results(str(before), str(after))
            self.assertEqual(comparison["summary"], {"introduced": 0, "absent": 1, "unchanged": 0})
            self.assertIn("not proof", comparison["interpretation"])
            self.assertFalse(any(comparison["claims"].values()))

    def test_rehashed_malformed_result_cannot_crash_comparison(self):
        with tempfile.TemporaryDirectory() as temp:
            result = import_report(str(REPORTS / "source.sarif"), "sarif")
            result["observations"][0]["path"] = "../escape"
            del result["resultSha256"]
            seal(result)
            path = Path(temp, "result.json")
            save_result_document(result, path)
            with self.assertRaises(ReportError):
                compare_results(str(path), str(path))


if __name__ == "__main__":
    unittest.main()
