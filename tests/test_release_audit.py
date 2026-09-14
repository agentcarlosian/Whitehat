import tempfile
import unittest
from pathlib import Path

from whitehat.release_audit import (
    APACHE_2_LICENSE_SHA256,
    ReleaseAuditError,
    _archive_path,
    _release_inventory,
    _scan_content_for_secrets,
    _sha256,
)


ROOT = Path(__file__).resolve().parents[1]


class ReleaseAuditTests(unittest.TestCase):
    def test_release_inventory_exactly_covers_package_source(self) -> None:
        inventory = _release_inventory(ROOT)
        package_files = [value for value in inventory if value.startswith("whitehat/")]
        actual = sorted(
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "whitehat").rglob("*.py")
        )
        self.assertEqual(package_files, actual)
        self.assertIn("PROVENANCE.md", inventory)
        self.assertIn("THIRD_PARTY.md", inventory)

    def test_apache_license_matches_canonical_hash(self) -> None:
        self.assertEqual(
            _sha256((ROOT / "LICENSE").read_bytes()), APACHE_2_LICENSE_SHA256
        )

    def test_secret_patterns_fail_closed(self) -> None:
        examples = {
            "private-key": b"-----BEGIN " + b"PRIVATE KEY-----\nnot-real",
            "github-token": b"ghp_" + b"a" * 30,
            "openai-key": b"sk-" + b"a" * 30,
            "aws-access-key": b"AKIA" + b"A" * 16,
            "slack-token": b"xoxb-" + b"a" * 30,
            "pypi-token": b"pypi-" + b"a" * 30,
        }
        for pattern_id, content in examples.items():
            with self.subTest(pattern_id=pattern_id):
                with self.assertRaisesRegex(ReleaseAuditError, pattern_id):
                    _scan_content_for_secrets("synthetic", content)

    def test_archive_path_rejects_escape(self) -> None:
        with self.assertRaisesRegex(ReleaseAuditError, "unsafe path"):
            _archive_path("../escape")
        with self.assertRaisesRegex(ReleaseAuditError, "unsafe path"):
            _archive_path("/absolute")

    def test_inventory_rejects_missing_package_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "whitehat").mkdir()
            (root / "whitehat" / "module.py").write_text("pass\n", encoding="utf-8")
            (root / "release-files.txt").write_text(
                "release-files.txt\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ReleaseAuditError, "exactly cover"):
                _release_inventory(root)


if __name__ == "__main__":
    unittest.main()
