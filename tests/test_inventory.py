import tempfile
import unittest
from pathlib import Path

from whitehat.local_diff import DiffLimits, inventory_directory


class InventoryTests(unittest.TestCase):
    def test_inventory_is_sorted_content_free_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "nested").mkdir()
            (root / "z.txt").write_text("z", encoding="utf-8")
            (root / "nested" / "a.txt").write_text("alpha", encoding="utf-8")
            first = inventory_directory(root)
            second = inventory_directory(root)

        self.assertEqual(first, second)
        self.assertEqual(first["summary"], {"files": 2, "bytes": 6})
        self.assertEqual(
            [record["path"] for record in first["files"]],
            ["nested/a.txt", "z.txt"],
        )
        self.assertNotIn("alpha", str(first))
        self.assertEqual(
            first["effects"],
            {"filesystemWrite": False, "network": False, "processCreation": False},
        )

    def test_inventory_uses_existing_file_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "a.txt").write_text("a", encoding="utf-8")
            result = inventory_directory(
                root,
                DiffLimits(
                    max_entries=1, max_files=1, max_file_bytes=1, max_total_bytes=1
                ),
            )
        self.assertEqual(result["summary"], {"files": 1, "bytes": 1})


if __name__ == "__main__":
    unittest.main()
