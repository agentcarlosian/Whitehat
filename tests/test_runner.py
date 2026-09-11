import json
import os
import tempfile
import unittest
from pathlib import Path

from whitehat.runner import (
    ProcessLimits,
    RunnerError,
    RunnerLimitError,
    _sanitized_environment,
    _validated_child_environment_keys,
    run_synthetic,
)


class RunnerTests(unittest.TestCase):
    def test_fixed_synthetic_profile_cleans_workspace_and_hides_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace_root = Path(temporary)
            original = os.environ.get("WHITEHAT_SECRET_CANARY")
            os.environ["WHITEHAT_SECRET_CANARY"] = "do-not-forward"
            try:
                result = run_synthetic(
                    "owned synthetic text", repeat=3, workspace_root=workspace_root
                )
            finally:
                if original is None:
                    del os.environ["WHITEHAT_SECRET_CANARY"]
                else:
                    os.environ["WHITEHAT_SECRET_CANARY"] = original
            remaining = list(workspace_root.iterdir())

        self.assertEqual(remaining, [])
        self.assertTrue(result["effects"]["processCreation"])
        self.assertTrue(result["effects"]["filesystemWrite"])
        self.assertTrue(result["effects"]["workspaceCleaned"])
        self.assertFalse(result["effects"]["network"])
        self.assertFalse(result["effects"]["arbitraryCommand"])
        self.assertEqual(result["process"]["exitCode"], 0)
        self.assertEqual(result["process"]["stderrBytes"], 0)
        self.assertNotIn("owned synthetic text", json.dumps(result))
        self.assertNotIn("WHITEHAT_SECRET_CANARY", result["output"]["environmentKeys"])

    def test_timeout_cleans_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace_root = Path(temporary)
            limits = ProcessLimits(timeout_seconds=0.05)
            with self.assertRaisesRegex(RunnerLimitError, "timeout"):
                run_synthetic(
                    "slow",
                    delay_ms=500,
                    limits=limits,
                    workspace_root=workspace_root,
                )
            self.assertEqual(list(workspace_root.iterdir()), [])

    def test_stdout_overflow_cleans_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace_root = Path(temporary)
            limits = ProcessLimits(max_stdout_bytes=128)
            with self.assertRaisesRegex(RunnerLimitError, "stdout limit"):
                run_synthetic(
                    "x" * 1_000,
                    repeat=100,
                    limits=limits,
                    workspace_root=workspace_root,
                )
            self.assertEqual(list(workspace_root.iterdir()), [])

    def test_input_limit_fails_before_workspace_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace_root = Path(temporary)
            limits = ProcessLimits(max_input_bytes=10)
            with self.assertRaisesRegex(RunnerLimitError, "input limit"):
                run_synthetic(
                    "too much input", limits=limits, workspace_root=workspace_root
                )
            self.assertEqual(list(workspace_root.iterdir()), [])

    def test_environment_validation_allows_only_known_runtime_addition(self) -> None:
        required = sorted(_sanitized_environment(Path(".")).keys())
        self.assertEqual(_validated_child_environment_keys(required), required)
        with_runtime_locale = sorted([*required, "LC_CTYPE"])
        self.assertEqual(
            _validated_child_environment_keys(with_runtime_locale),
            with_runtime_locale,
        )
        with self.assertRaisesRegex(RunnerError, "unexpected environment key"):
            _validated_child_environment_keys(sorted([*required, "SECRET_CANARY"]))


if __name__ == "__main__":
    unittest.main()
