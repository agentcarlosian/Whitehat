import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from whitehat.records import RecordError, create_review_document, save_result_document, write_json_document
from whitehat.reports import import_report
from whitehat.research import export_markdown, initialize_workspace, validate_case

ROOT = Path(__file__).resolve().parents[1]


class ResearchWorkflowTests(unittest.TestCase):
    def test_workspace_report_and_matching_review_end_to_end(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "research")
            initialize_workspace(str(root), "Owned package review")
            result = import_report(str(ROOT / "examples/reports/osv.json"), "osv")
            result_path = root / "results/advisories.json"
            save_result_document(result, result_path)
            review = create_review_document(result, "needs-work", "Verify reachability.")
            review_path = root / "notes/review.json"
            write_json_document(review, review_path)
            output = root / "exports/review.md"
            export_markdown(str(result_path), str(output), case_path=str(root / "case.json"), review_path=str(review_path))
            content = output.read_text()
            self.assertIn("Verify reachability", content)
            self.assertIn("1\\.0\\.1", content)
            self.assertIn(result["resultSha256"], content)
            self.assertNotIn(str(root), content)
            with self.assertRaises(RecordError):
                initialize_workspace(str(root), "Do not overwrite")
            with self.assertRaises(RecordError):
                export_markdown(str(result_path), str(output))

    def test_case_markdown_and_references_are_data(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "case")
            initialize_workspace(str(root), "![payload](https://untrusted.invalid)")
            case_path = root / "case.json"
            case = json.loads(case_path.read_text())
            case["hypothesis"] = "<script>untrusted</script>"
            case["evidenceReferences"] = ["inputs/missing.txt"]
            case_path.write_text(json.dumps(case))
            result = import_report(str(ROOT / "examples/reports/source.sarif"), "sarif")
            result_path = root / "results/scan.json"
            save_result_document(result, result_path)
            output = root / "exports/review.md"
            export_markdown(str(result_path), str(output), case_path=str(case_path))
            content = output.read_text()
            self.assertNotIn("![payload]", content)
            self.assertNotIn("<script>", content)
            self.assertIn("inputs/missing", content)
            case["evidenceReferences"] = ["../outside"]
            with self.assertRaises(RecordError):
                validate_case(case)

    def test_review_tamper_and_wrong_result_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = import_report(str(ROOT / "examples/reports/osv.json"), "osv")
            other = import_report(str(ROOT / "examples/reports/source.sarif"), "sarif")
            save_result_document(result, root / "result.json")
            review = create_review_document(other, "dismissed", "Different result.")
            write_json_document(review, root / "wrong.json")
            with self.assertRaisesRegex(RecordError, "different result"):
                export_markdown(str(root / "result.json"), str(root / "out.md"), review_path=str(root / "wrong.json"))
            review["note"] = "Tampered"
            write_json_document(review, root / "tampered.json")
            with self.assertRaisesRegex(RecordError, "hash mismatch"):
                export_markdown(str(root / "result.json"), str(root / "out.md"), review_path=str(root / "tampered.json"))
            self.assertFalse((root / "out.md").exists())

    def test_cli_import_compare_report_and_error_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def run(*args):
                return subprocess.run([sys.executable, "-B", "-m", "whitehat", *args], cwd=ROOT, capture_output=True, text=True, timeout=30)
            imported = run("import", "examples/reports/source.sarif", "--format", "sarif", "--output", str(root / "scan.json"), "--json")
            self.assertEqual(imported.returncode, 0, imported.stdout + imported.stderr)
            self.assertEqual(json.loads(imported.stdout)["summary"]["observations"], 1)
            compared = run("compare", str(root / "scan.json"), str(root / "scan.json"), "--json")
            self.assertEqual(json.loads(compared.stdout)["summary"]["unchanged"], 1)
            exported = run("report", str(root / "scan.json"), "--output", str(root / "scan.md"), "--json")
            self.assertEqual(exported.returncode, 0, exported.stdout + exported.stderr)
            repeated = run("report", str(root / "scan.json"), "--output", str(root / "scan.md"), "--json")
            self.assertEqual(repeated.returncode, 3)
            self.assertFalse(json.loads(repeated.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
