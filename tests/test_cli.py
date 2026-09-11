import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from whitehat.scanner import RUFF_VERSION


ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def _run(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", "-m", "whitehat", *arguments],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_doctor_json(self) -> None:
        completed = self._run("doctor", "--json")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertTrue(result["ok"])
        self.assertFalse(result["capabilities"]["network"])

    def test_diff_json(self) -> None:
        completed = self._run(
            "analyze",
            "diff",
            str(ROOT / "examples" / "before"),
            str(ROOT / "examples" / "after"),
            "--json",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(
            result["summary"],
            {"added": 1, "deleted": 0, "modified": 1, "unchanged": 1},
        )

    def test_inventory_json(self) -> None:
        completed = self._run(
            "analyze",
            "inventory",
            str(ROOT / "examples" / "before"),
            "--json",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["summary"], {"files": 2, "bytes": 31})
        self.assertEqual(
            [record["path"] for record in result["files"]],
            ["changed.txt", "common.txt"],
        )

    def test_dependency_comparison_json(self) -> None:
        completed = self._run(
            "analyze",
            "dependencies",
            str(ROOT / "examples" / "dependencies" / "before" / "pyproject.toml"),
            str(ROOT / "examples" / "dependencies" / "after" / "pyproject.toml"),
            "--json",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(
            result["summary"],
            {"added": 1, "removed": 1, "changed": 1, "unchanged": 1},
        )

    def test_optional_output_and_local_review(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result_path = Path(temporary, "inventory.json")
            review_path = Path(temporary, "review.json")
            completed = self._run(
                "analyze",
                "inventory",
                str(ROOT / "examples" / "before"),
                "--output",
                str(result_path),
                "--json",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(
                json.loads(result_path.read_text(encoding="utf-8")), result
            )

            reviewed = self._run(
                "review",
                str(result_path),
                "--decision",
                "needs-work",
                "--note",
                "Add a controlled comparison.",
                "--author",
                "Carlos",
                "--output",
                str(review_path),
                "--json",
            )
            self.assertEqual(reviewed.returncode, 0, reviewed.stderr)
            review = json.loads(reviewed.stdout)
            self.assertEqual(
                json.loads(review_path.read_text(encoding="utf-8")), review
            )
            self.assertEqual(review["reviewOf"]["resultSha256"], result["resultSha256"])
            self.assertEqual(review["decision"], "needs-work")

            overwrite = self._run(
                "review",
                str(result_path),
                "--decision",
                "accepted",
                "--note",
                "Reviewed.",
                "--output",
                str(review_path),
                "--json",
            )
            self.assertEqual(overwrite.returncode, 3)
            self.assertEqual(
                json.loads(overwrite.stdout)["error"]["code"],
                "invalid-input",
            )

    def test_synthetic_runner_can_be_saved_and_reviewed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace_root = Path(temporary, "workspaces")
            workspace_root.mkdir()
            result_path = Path(temporary, "run.json")
            review_path = Path(temporary, "run.review.json")
            completed = self._run(
                "run",
                "synthetic",
                "--message",
                "owned fixture",
                "--repeat",
                "2",
                "--workspace-root",
                str(workspace_root),
                "--output",
                str(result_path),
                "--json",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertTrue(result["effects"]["workspaceCleaned"])
            self.assertEqual(list(workspace_root.iterdir()), [])
            self.assertEqual(
                json.loads(result_path.read_text(encoding="utf-8")), result
            )

            reviewed = self._run(
                "review",
                str(result_path),
                "--decision",
                "accepted",
                "--note",
                "Synthetic boundary reviewed.",
                "--output",
                str(review_path),
                "--json",
            )
            self.assertEqual(reviewed.returncode, 0, reviewed.stderr)
            review = json.loads(reviewed.stdout)
            self.assertEqual(review["reviewOf"]["resultSha256"], result["resultSha256"])

    def test_ruff_scanner_can_be_saved_and_reviewed(self) -> None:
        executable = shutil.which("ruff")
        if executable is None:
            self.skipTest(f"Ruff {RUFF_VERSION} is unavailable")
        version = subprocess.run(
            [executable, "--version"],
            check=False,
            capture_output=True,
            text=True,
        )
        if version.stdout.strip() != f"ruff {RUFF_VERSION}":
            self.skipTest(f"Ruff {RUFF_VERSION} is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            result_path = Path(temporary, "ruff.json")
            review_path = Path(temporary, "ruff.review.json")
            completed = self._run(
                "scan",
                "ruff",
                str(ROOT / "examples" / "scanner" / "problem"),
                "--output",
                str(result_path),
                "--json",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result["summary"]["codes"], {"F401": 1, "F841": 1})
            self.assertEqual(
                json.loads(result_path.read_text(encoding="utf-8")), result
            )
            reviewed = self._run(
                "review",
                str(result_path),
                "--decision",
                "needs-work",
                "--note",
                "Review the normalized observations.",
                "--output",
                str(review_path),
                "--json",
            )
            self.assertEqual(reviewed.returncode, 0, reviewed.stderr)
            review = json.loads(reviewed.stdout)
            self.assertEqual(review["reviewOf"]["resultSha256"], result["resultSha256"])

    def test_network_session_validation_is_local_and_reviewable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result_path = Path(temporary, "session-validation.json")
            review_path = Path(temporary, "session-validation.review.json")
            completed = self._run(
                "session",
                "validate",
                str(ROOT / "examples" / "network-session.synthetic.json"),
                "--evaluation-time",
                "2026-09-11T01:30:00Z",
                "--output",
                str(result_path),
                "--json",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertFalse(result["claims"]["networkEngineImplemented"])
            self.assertFalse(result["claims"]["networkExecutionAuthorized"])
            self.assertFalse(result["effects"]["network"])
            reviewed = self._run(
                "review",
                str(result_path),
                "--decision",
                "accepted",
                "--note",
                "Design contract reviewed; no network execution.",
                "--output",
                str(review_path),
                "--json",
            )
            self.assertEqual(reviewed.returncode, 0, reviewed.stderr)
            review = json.loads(reviewed.stdout)
            self.assertEqual(review["reviewOf"]["resultSha256"], result["resultSha256"])

    def test_offline_analysis_does_not_require_network_session(self) -> None:
        completed = self._run(
            "analyze",
            "inventory",
            str(ROOT / "examples" / "before"),
            "--json",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(json.loads(completed.stdout)["ok"])

    def test_invalid_input_is_structured(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary, "missing")
            existing = Path(temporary, "existing")
            existing.mkdir()
            completed = self._run(
                "analyze", "diff", str(missing), str(existing), "--json"
            )
        self.assertEqual(completed.returncode, 3)
        result = json.loads(completed.stdout)
        self.assertEqual(result["error"]["code"], "invalid-input")


if __name__ == "__main__":
    unittest.main()
