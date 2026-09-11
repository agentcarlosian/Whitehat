import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


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

    def test_invalid_input_is_structured(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary, "missing")
            existing = Path(temporary, "existing")
            existing.mkdir()
            completed = self._run("analyze", "diff", str(missing), str(existing), "--json")
        self.assertEqual(completed.returncode, 3)
        result = json.loads(completed.stdout)
        self.assertEqual(result["error"]["code"], "invalid-input")


if __name__ == "__main__":
    unittest.main()
