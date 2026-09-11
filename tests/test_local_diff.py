import json
import os
import tempfile
import unittest
from pathlib import Path

from whitehat.local_diff import DiffError, DiffLimitError, DiffLimits, compare_directories


class LocalDiffTests(unittest.TestCase):
    def _roots(self, temporary: str) -> tuple[Path, Path]:
        before = Path(temporary, "before")
        after = Path(temporary, "after")
        before.mkdir()
        after.mkdir()
        return before, after

    def test_reports_added_deleted_modified_and_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            before, after = self._roots(temporary)
            (before / "same.txt").write_text("same", encoding="utf-8")
            (after / "same.txt").write_text("same", encoding="utf-8")
            (before / "changed.txt").write_text("before", encoding="utf-8")
            (after / "changed.txt").write_text("after", encoding="utf-8")
            (before / "deleted.txt").write_text("gone", encoding="utf-8")
            (after / "added.txt").write_text("new", encoding="utf-8")

            result = compare_directories(before, after)

        self.assertEqual(
            result["summary"],
            {"added": 1, "deleted": 1, "modified": 1, "unchanged": 1},
        )
        self.assertEqual(
            [(item["kind"], item["path"]) for item in result["changes"]],
            [("added", "added.txt"), ("modified", "changed.txt"), ("deleted", "deleted.txt")],
        )
        self.assertNotIn("same.txt", json.dumps(result["changes"]))
        self.assertEqual(
            result["effects"],
            {"filesystemWrite": False, "network": False, "processCreation": False},
        )

    def test_result_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            before, after = self._roots(temporary)
            (before / "a.txt").write_text("a", encoding="utf-8")
            (after / "a.txt").write_text("b", encoding="utf-8")
            first = compare_directories(before, after)
            second = compare_directories(before, after)
        self.assertEqual(first, second)

    def test_rejects_same_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(DiffError, "must be different"):
                compare_directories(root, root)

    def test_enforces_file_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            before, after = self._roots(temporary)
            (before / "a.txt").write_text("a", encoding="utf-8")
            (after / "a.txt").write_text("a", encoding="utf-8")
            (after / "b.txt").write_text("b", encoding="utf-8")
            limits = DiffLimits(max_entries=10, max_files=1, max_file_bytes=10, max_total_bytes=10)
            with self.assertRaisesRegex(DiffLimitError, "file count"):
                compare_directories(before, after, limits)

    def test_rejects_symbolic_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            before, after = self._roots(temporary)
            target = before / "target.txt"
            target.write_text("target", encoding="utf-8")
            try:
                os.symlink(target, after / "link.txt")
            except OSError as exc:
                self.skipTest(f"symbolic links unavailable: {exc}")
            with self.assertRaisesRegex(DiffError, "symbolic links"):
                compare_directories(before, after)


if __name__ == "__main__":
    unittest.main()
