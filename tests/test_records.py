import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from whitehat.local_diff import inventory_directory
from whitehat.records import (
    RecordError,
    RecordLimitError,
    create_review_document,
    load_result_document,
    save_result_document,
    write_json_document,
)


class RecordTests(unittest.TestCase):
    def test_saves_and_loads_exact_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary, "input")
            root.mkdir()
            (root / "a.txt").write_text("alpha", encoding="utf-8")
            result = inventory_directory(root)
            output = Path(temporary, "result.json")

            saved = save_result_document(result, output)
            stored_text = output.read_text(encoding="utf-8")
            loaded = load_result_document(saved)

        self.assertEqual(loaded, result)
        self.assertEqual(stored_text, output_text(result) + "\n")

    def test_refuses_overwrite_without_changing_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary, "input")
            root.mkdir()
            result = inventory_directory(root)
            output = Path(temporary, "result.json")
            output.write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(RecordError, "already exists"):
                save_result_document(result, output)
            self.assertEqual(output.read_text(encoding="utf-8"), "keep")

    def test_rejects_result_hash_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary, "input")
            root.mkdir()
            result = inventory_directory(root)
            result["summary"]["files"] = 99
            path = Path(temporary, "result.json")
            path.write_text(json.dumps(result), encoding="utf-8")
            with self.assertRaisesRegex(RecordError, "hash does not match"):
                load_result_document(path)

    def test_enforces_result_read_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary, "input")
            root.mkdir()
            result = inventory_directory(root)
            path = Path(temporary, "result.json")
            save_result_document(result, path)
            with self.assertRaisesRegex(RecordLimitError, "byte limit"):
                load_result_document(path, max_bytes=1)

    def test_creates_hash_bound_non_authorizing_review(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary, "input")
            root.mkdir()
            result = inventory_directory(root)
            review = create_review_document(
                result,
                "needs-work",
                "Add one controlled comparison.",
                "Carlos",
                datetime(2026, 9, 11, 18, 30, tzinfo=timezone.utc),
            )
        self.assertEqual(review["createdAt"], "2026-09-11T18:30:00Z")
        self.assertEqual(review["authorAssertion"], "Carlos")
        self.assertFalse(any(review["claims"].values()))
        self.assertTrue(review["effects"]["localRecordWrite"])
        self.assertFalse(review["effects"]["network"])
        expected = dict(review)
        digest = expected.pop("reviewSha256")
        canonical = json.dumps(
            expected,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self.assertEqual(digest, hashlib.sha256(canonical).hexdigest())

    def test_rejects_invalid_review_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary, "input")
            root.mkdir()
            result = inventory_directory(root)
            with self.assertRaisesRegex(RecordError, "review decision"):
                create_review_document(result, "approved", "note")
            with self.assertRaisesRegex(RecordLimitError, "character limit"):
                create_review_document(result, "accepted", "x" * 4_001)

    def test_requires_existing_output_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(RecordError, "parent is unavailable"):
                write_json_document(
                    {"schemaVersion": "synthetic"},
                    Path(temporary, "missing", "result.json"),
                )


def output_text(document: dict[str, object]) -> str:
    return json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


if __name__ == "__main__":
    unittest.main()
