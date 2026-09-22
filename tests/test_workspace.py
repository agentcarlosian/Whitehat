import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from whitehat.candidates import initialize_candidate, record_decision
from whitehat.cli import main
from whitehat.packets import initialize_packet
from whitehat.records import RecordError, save_result_document
from whitehat.reports import ReportError, compare_results, import_report, seal
from whitehat.workspace import index_workspace, workspace_status

ROOT = Path(__file__).resolve().parents[1]


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "input.json").write_bytes(
            (ROOT / "examples/reports/osv.json").read_bytes()
        )
        for name in ("before.json", "after.json"):
            save_result_document(
                import_report(str(self.root / "input.json"), "osv"), self.root / name
            )
        save_result_document(
            compare_results(
                str(self.root / "before.json"), str(self.root / "after.json")
            ),
            self.root / "comparison.json",
        )

    def index(self, **extra):
        artifacts = {
            "input": ["input.json"],
            "result": ["before.json", "after.json", "comparison.json"],
            **extra,
        }
        return index_workspace(
            str(self.root),
            str(self.root / "workspace.json"),
            "owned",
            artifacts,
            ["before.json=input.json", "after.json=input.json"],
        )

    def status(self):
        return workspace_status(str(self.root / "workspace.json"))

    def test_offline_determinism_and_transitive_staleness(self):
        with patch("socket.socket", side_effect=AssertionError("unexpected network")):
            self.index()
            first = self.status()
            self.assertEqual(first, self.status())
            self.assertTrue(first["consistent"])
            (self.root / "input.json").write_text("changed input", encoding="utf-8")
            second = self.status()
        rows = {r["path"]: r for r in second["artifacts"]}
        self.assertEqual(rows["input.json"]["status"], "changed")
        self.assertEqual(rows["before.json"]["status"], "stale")
        self.assertEqual(rows["comparison.json"]["status"], "stale")
        self.assertEqual(
            rows["comparison.json"]["staleBecause"], ["after.json", "before.json"]
        )
        self.assertNotIn("changed input", json.dumps(second))

    def test_missing_and_corrupt_results_remain_visible(self):
        self.index()
        (self.root / "before.json").unlink()
        (self.root / "after.json").write_text("{}", encoding="utf-8")
        rows = {r["path"]: r for r in self.status()["artifacts"]}
        self.assertEqual(rows["before.json"]["status"], "missing")
        self.assertEqual(rows["after.json"]["status"], "invalid")
        self.assertEqual(rows["comparison.json"]["status"], "stale")

    def test_packet_content_separate_from_integrity_and_propagated_input_drift(self):
        initialize_packet(
            str(self.root / "packet.json"),
            "owned",
            "Owned review",
            [str(self.root / "before.json")],
        )
        self.index(packet=["packet.json"])
        result = self.status()
        packet = next(r for r in result["artifacts"] if r["kind"] == "packet")
        self.assertTrue(result["consistent"])
        self.assertFalse(packet["contentComplete"])
        (self.root / "input.json").write_text("changed", encoding="utf-8")
        packet = next(r for r in self.status()["artifacts"] if r["kind"] == "packet")
        self.assertEqual(packet["status"], "stale")

    def test_unregistered_packet_evidence_is_not_opened(self):
        initialize_packet(
            str(self.root / "packet.json"),
            "owned",
            "Owned review",
            [str(self.root / "before.json")],
        )
        index_workspace(
            str(self.root),
            str(self.root / "workspace.json"),
            "owned",
            {"packet": ["packet.json"]},
            [],
        )
        with patch(
            "whitehat.workspace.check_packet",
            side_effect=AssertionError("unregistered evidence read"),
        ):
            status = self.status()
        self.assertFalse(status["consistent"])
        self.assertEqual(
            status["artifacts"][0]["issues"][0]["code"], "unregistered-packet-evidence"
        )

    def test_candidate_history_and_evidence_links(self):
        initialize_candidate(
            str(self.root / "candidate"), "lead", "owned", "Owned lead"
        )
        result = json.loads((self.root / "before.json").read_text())
        record_decision(
            str(self.root / "candidate"),
            str(self.root / "before.json"),
            [result["observations"][0]["fingerprint"]],
            "needs-work",
            "Inspect reachability.",
        )
        self.index(candidate=["candidate"])
        row = next(r for r in self.status()["artifacts"] if r["kind"] == "candidate")
        self.assertEqual(row["decision"], "needs-work")
        self.assertIn("before.json", row["dependsOn"])
        decision = self.root / "candidate/decisions/000001.json"
        decision.write_text("{}", encoding="utf-8")
        row = next(r for r in self.status()["artifacts"] if r["kind"] == "candidate")
        self.assertEqual(row["status"], "invalid")

    def test_cycles_duplicate_paths_and_escaping_paths_reject(self):
        for artifacts, links in (
            ({"input": ["../escape"]}, []),
            ({"input": ["input.json", "input.json"]}, []),
            (
                {"input": ["input.json", "before.json"]},
                ["input.json=before.json", "before.json=input.json"],
            ),
        ):
            with self.subTest(artifacts=artifacts), self.assertRaises(ReportError):
                index_workspace(
                    str(self.root),
                    str(self.root / "workspace.json"),
                    "owned",
                    artifacts,
                    links,
                )
            self.assertFalse((self.root / "workspace.json").exists())

    def test_symlink_and_budget_rejection(self):
        self.index()
        with patch("whitehat.workspace.MAX_BYTES", 1), self.assertRaises(ReportError):
            self.status()
        with (
            patch.object(Path, "is_symlink", return_value=True),
            self.assertRaises(ReportError),
        ):
            self.status()

    def test_cli_check_exit_and_output_do_not_overwrite(self):
        self.index()
        (self.root / "input.json").write_text("changed", encoding="utf-8")
        for command, expected in (("status", 0), ("check", 3)):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                code = main(
                    ["workspace", command, str(self.root / "workspace.json"), "--json"]
                )
            self.assertEqual(code, expected)
            self.assertFalse(json.loads(output.getvalue())["consistent"])
        with self.assertRaises(RecordError):
            self.index()

    def test_malformed_registered_comparison_is_reported_without_traceback(self):
        self.index()
        path = self.root / "comparison.json"
        malformed = {
            "schemaVersion": "whitehat-research-comparison-v1",
            "ok": True,
            "provenance": [],
        }
        path.write_text(json.dumps(seal(malformed)), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = main(
                ["workspace", "check", str(self.root / "workspace.json"), "--json"]
            )
        self.assertEqual(code, 3)
        result = json.loads(output.getvalue())
        row = next(r for r in result["artifacts"] if r["path"] == "comparison.json")
        self.assertEqual(row["status"], "invalid")


if __name__ == "__main__":
    unittest.main()
