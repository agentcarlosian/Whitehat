import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from whitehat.native_tools import TOOLS, copy_inputs, platform_key, scan_native
from whitehat.reports import ReportError, ReportLimitError, canonical
from whitehat.scanner import ScannerLimits

ROOT = Path(__file__).resolve().parents[1]


def native_path(tool):
    try:
        return ROOT / ".whitehat/tools" / tool / TOOLS[tool]["platforms"][platform_key()]["executable"]
    except ReportError:
        return ROOT / ".whitehat/tools/unsupported"


class NativeToolTests(unittest.TestCase):
    def test_unknown_executable_never_starts_a_process(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "fake.exe")
            path.write_bytes(b"not executable")
            with patch("whitehat.native_tools.execute_fixed_profile") as run:
                with self.assertRaises(ReportError):
                    scan_native(str(ROOT / "examples/research/vulnerable"), "opengrep", str(path))
                run.assert_not_called()

    def test_source_count_and_byte_limits(self):
        with tempfile.TemporaryDirectory() as temp:
            root, output = Path(temp, "input"), Path(temp, "output")
            root.mkdir()
            output.mkdir()
            (root / "a.py").write_text("x=1\n")
            (root / "b.py").write_text("x=2\n")
            with self.assertRaises(ReportLimitError):
                copy_inputs(root, output, "opengrep", ScannerLimits(max_source_files=1))

    def test_unsupported_sources_and_ignored_dependencies(self):
        with tempfile.TemporaryDirectory() as temp:
            root, output = Path(temp, "input"), Path(temp, "output")
            root.mkdir()
            output.mkdir()
            (root / "node_modules").mkdir()
            (root / "node_modules/dep.py").write_text("eval(x)\n")
            (root / "app.py").write_text("x=1\n")
            (root / "image.png").write_bytes(b"ignored")
            records = copy_inputs(root, output, "opengrep", ScannerLimits())
            self.assertEqual([r["path"] for r in records], ["app.py"])

    @unittest.skipUnless(native_path("opengrep").is_file(), "explicit Opengrep setup required")
    def test_actual_security_rules_and_fixed_and_text_controls(self):
        path = str(native_path("opengrep"))
        for name, expected in (("vulnerable", 5), ("fixed", 0), ("negative", 0)):
            with self.subTest(fixture=name):
                result = scan_native(str(ROOT / "examples/research" / name), "opengrep", path)
                self.assertEqual(result["summary"]["observations"], expected)
                self.assertTrue(result["effects"]["workspaceCleaned"])
                self.assertFalse(any(result["claims"].values()))
                self.assertNotIn(str(ROOT).encode(), canonical(result))

    @unittest.skipUnless(native_path("opengrep").is_file(), "explicit Opengrep setup required")
    def test_express_typescript_profile_and_rejecting_controls(self):
        for name, expected in (("vulnerable", 6), ("fixed", 0), ("negative", 0)):
            result = scan_native(str(ROOT / "examples/research/express" / name), "opengrep", str(native_path("opengrep")), profile="express-typescript")
            self.assertEqual(result["summary"]["observations"], expected)
            self.assertEqual(result["provenance"]["sourceSuffixes"], [".js", ".ts"])
            self.assertEqual(result["provenance"]["analysisProfile"], "express-typescript-v1")
            self.assertTrue(result["effects"]["workspaceCleaned"])
            self.assertFalse(result["effects"]["sourceExecuted"])
            for item in result["observations"]:
                context = item["sourceContext"]
                self.assertTrue(context["representationComplete"])
                self.assertEqual(context["validation"], "unverified")
                self.assertEqual(context["flows"][0]["steps"][0]["kinds"], ["source"])
                self.assertEqual(context["flows"][0]["steps"][-1]["kinds"], ["sink"])
            self.assertNotIn(str(ROOT).encode(), canonical(result))

    def test_unreviewed_profile_rejected_before_process(self):
        with patch("whitehat.native_tools.execute_fixed_profile") as run:
            with self.assertRaises(ReportError):
                scan_native(str(ROOT), "opengrep", profile="caller-rules.json")
            run.assert_not_called()

    @unittest.skipUnless(native_path("betterleaks").is_file(), "explicit Betterleaks setup required")
    def test_actual_secret_canary_and_clean_control(self):
        path = str(native_path("betterleaks"))
        result = scan_native(str(ROOT / "examples/research/secrets"), "betterleaks", path)
        self.assertEqual(result["summary"]["observations"], 1)
        self.assertFalse(result["effects"]["credentialValidation"])
        self.assertNotIn(b"a1b2c3d4e5f6g7h8i9j0k1l2", canonical(result))
        clean = scan_native(str(ROOT / "examples/research/negative"), "betterleaks", path)
        self.assertEqual(clean["summary"]["observations"], 0)


if __name__ == "__main__":
    unittest.main()
