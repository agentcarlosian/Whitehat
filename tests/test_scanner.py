import json
import importlib.metadata
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from whitehat.scanner import (
    RUFF_VERSION,
    ScannerError,
    ScannerLimitError,
    ScannerLimits,
    normalize_ruff_output,
    scan_with_ruff,
)


ROOT = Path(__file__).resolve().parents[1]


def ruff_is_available() -> bool:
    try:
        version = importlib.metadata.version("ruff")
    except importlib.metadata.PackageNotFoundError:
        return False
    return version == RUFF_VERSION


class ScannerTests(unittest.TestCase):
    @unittest.skipUnless(ruff_is_available(), f"Ruff {RUFF_VERSION} is unavailable")
    def test_pinned_ruff_adapter_normalizes_and_cleans(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace_root = Path(temporary)
            result = scan_with_ruff(
                ROOT / "examples" / "scanner" / "problem",
                workspace_root=workspace_root,
            )
            remaining = list(workspace_root.iterdir())

        self.assertEqual(remaining, [])
        self.assertEqual(result["adapter"]["toolVersion"], RUFF_VERSION)
        self.assertEqual(result["summary"]["codes"], {"F401": 1, "F841": 1})
        self.assertEqual(
            [(item["code"], item["path"]) for item in result["observations"]],
            [("F401", "problem.py"), ("F841", "problem.py")],
        )
        serialized = json.dumps(result)
        self.assertNotIn("import os", serialized)
        self.assertNotIn("docs.astral.sh", serialized)
        self.assertNotIn(str(workspace_root), serialized)
        self.assertFalse(any(result["claims"].values()))
        self.assertTrue(result["effects"]["sourceCopied"])
        self.assertFalse(result["effects"]["sourceExecuted"])
        self.assertTrue(result["effects"]["workspaceCleaned"])

    @unittest.skipUnless(ruff_is_available(), f"Ruff {RUFF_VERSION} is unavailable")
    def test_clean_twin_has_no_observations(self) -> None:
        result = scan_with_ruff(ROOT / "examples" / "scanner" / "clean")
        self.assertEqual(result["summary"], {"observations": 0, "codes": {}})
        self.assertEqual(result["observations"], [])
        self.assertEqual(result["process"]["exitCode"], 0)

    def test_normalizer_rejects_path_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary, "source")
            root.mkdir()
            outside = Path(temporary, "outside.py")
            outside.write_text("pass\n", encoding="utf-8")
            raw = json.dumps(
                [
                    {
                        "code": "F401",
                        "filename": str(outside),
                        "location": {"row": 1, "column": 1},
                        "end_location": {"row": 1, "column": 2},
                        "fix": None,
                    }
                ]
            ).encode("utf-8")
            with self.assertRaisesRegex(ScannerError, "escaped"):
                normalize_ruff_output(raw, root, 10)

    def test_normalizer_rejects_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary, "source")
            root.mkdir()
            source = root / "file.py"
            source.write_text("pass\n", encoding="utf-8")
            observation = {
                "code": "F401",
                "filename": str(source),
                "location": {"row": 1, "column": 1},
                "end_location": {"row": 1, "column": 2},
                "fix": None,
            }
            raw = json.dumps([observation, observation]).encode("utf-8")
            with self.assertRaisesRegex(ScannerError, "duplicate"):
                normalize_ruff_output(raw, root, 10)

    def test_normalizer_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary, "source")
            root.mkdir()
            source = root / "file.py"
            source.write_text("pass\n", encoding="utf-8")
            filename = json.dumps(str(source))
            raw = (
                '[{"code":"F401","code":"F841",'
                f'"filename":{filename},'
                '"location":{"row":1,"column":1},'
                '"end_location":{"row":1,"column":2},"fix":null}]'
            ).encode("utf-8")
            with self.assertRaisesRegex(ScannerError, "duplicate JSON key"):
                normalize_ruff_output(raw, root, 10)

    def test_rejects_wrong_tool_identity_before_source_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source_root = Path(temporary, "source")
            workspace_root = Path(temporary, "workspaces")
            source_root.mkdir()
            workspace_root.mkdir()
            (source_root / "file.py").write_text("pass\n", encoding="utf-8")
            with patch(
                "whitehat.scanner.importlib.metadata.distribution"
            ) as distribution:
                distribution.return_value.version = "999.0.0"
                with self.assertRaisesRegex(ScannerError, "version must be exactly"):
                    scan_with_ruff(source_root, workspace_root=workspace_root)
            self.assertEqual(list(workspace_root.iterdir()), [])

    def test_source_file_limit_fails_and_cleans(self) -> None:
        if not ruff_is_available():
            self.skipTest(f"Ruff {RUFF_VERSION} is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            source_root = Path(temporary, "source")
            workspace_root = Path(temporary, "workspaces")
            source_root.mkdir()
            workspace_root.mkdir()
            (source_root / "a.py").write_text("pass\n", encoding="utf-8")
            (source_root / "b.py").write_text("pass\n", encoding="utf-8")
            limits = ScannerLimits(max_source_files=1)
            with self.assertRaisesRegex(ScannerLimitError, "file limit"):
                scan_with_ruff(source_root, limits, workspace_root)
            self.assertEqual(list(workspace_root.iterdir()), [])

    def test_rejects_source_links(self) -> None:
        if not ruff_is_available():
            self.skipTest(f"Ruff {RUFF_VERSION} is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            source_root = Path(temporary, "source")
            source_root.mkdir()
            target = source_root / "target.py"
            target.write_text("pass\n", encoding="utf-8")
            try:
                os.symlink(target, source_root / "link.py")
            except OSError as exc:
                self.skipTest(f"symbolic links unavailable: {exc}")
            with self.assertRaisesRegex(ScannerError, "link is unsupported"):
                scan_with_ruff(source_root)


if __name__ == "__main__":
    unittest.main()
