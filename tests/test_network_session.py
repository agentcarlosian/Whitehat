import json
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from whitehat.network_session import (
    NetworkSessionError,
    NetworkSessionLimitError,
    load_and_validate_network_session,
    validate_network_session,
)


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "network-session.synthetic.json"
EVALUATION_TIME = datetime(2026, 9, 11, 1, 30, tzinfo=timezone.utc)


def example_document() -> dict[str, object]:
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


class NetworkSessionTests(unittest.TestCase):
    def test_validates_design_without_authorizing_network(self) -> None:
        result = load_and_validate_network_session(EXAMPLE, EVALUATION_TIME)
        self.assertEqual(result["status"], "valid-design-contract")
        self.assertFalse(result["claims"]["legalAuthorityEstablished"])
        self.assertFalse(result["claims"]["networkEngineImplemented"])
        self.assertFalse(result["claims"]["networkExecutionAuthorized"])
        self.assertFalse(result["claims"]["networkExecutionPerformed"])
        self.assertEqual(
            result["effects"],
            {"filesystemWrite": False, "network": False, "processCreation": False},
        )

    def test_rejects_expired_session(self) -> None:
        with self.assertRaisesRegex(NetworkSessionError, "not active"):
            validate_network_session(
                example_document(),
                datetime(2026, 9, 11, 3, 0, tzinfo=timezone.utc),
            )

    def test_rejects_session_longer_than_eight_hours(self) -> None:
        document = example_document()
        document["expiresAt"] = "2026-09-11T10:00:01Z"
        document["authority"]["policyExpiresAt"] = "2026-09-12T00:00:00Z"
        with self.assertRaisesRegex(NetworkSessionLimitError, "at most 8 hours"):
            validate_network_session(document, EVALUATION_TIME)

    def test_rejects_policy_expiry_before_session(self) -> None:
        document = example_document()
        document["authority"]["policyExpiresAt"] = "2026-09-11T02:00:00Z"
        with self.assertRaisesRegex(NetworkSessionError, "policy expiry"):
            validate_network_session(document, EVALUATION_TIME)

    def test_rejects_wildcard_target(self) -> None:
        document = example_document()
        document["targets"][0]["host"] = "*.example.invalid"
        with self.assertRaisesRegex(NetworkSessionError, "exact lowercase DNS"):
            validate_network_session(document, EVALUATION_TIME)

    def test_rejects_non_ascii_path_prefix(self) -> None:
        document = example_document()
        document["targets"][0]["pathPrefixes"] = ["/café"]
        with self.assertRaisesRegex(NetworkSessionError, "invalid path prefix"):
            validate_network_session(document, EVALUATION_TIME)

    def test_rejects_mutating_method_and_effect(self) -> None:
        document = example_document()
        document["targets"][0]["methods"] = ["POST"]
        with self.assertRaisesRegex(NetworkSessionError, "GET and HEAD"):
            validate_network_session(document, EVALUATION_TIME)
        changed_effect = example_document()
        changed_effect["effects"]["targetMutation"] = True
        with self.assertRaisesRegex(NetworkSessionError, "effects must be false"):
            validate_network_session(changed_effect, EVALUATION_TIME)

    def test_rejects_missing_stop_condition(self) -> None:
        document = example_document()
        document["stopConditions"].remove("user-stop")
        with self.assertRaisesRegex(NetworkSessionError, "missing a required boundary"):
            validate_network_session(document, EVALUATION_TIME)

    def test_rejects_budget_wider_than_session(self) -> None:
        document = example_document()
        document["budgets"]["maxWallSeconds"] = 7_201
        with self.assertRaisesRegex(NetworkSessionLimitError, "session duration"):
            validate_network_session(document, EVALUATION_TIME)

    def test_rejects_unknown_fields(self) -> None:
        document = deepcopy(example_document())
        document["execute"] = True
        with self.assertRaisesRegex(NetworkSessionError, "unexpected"):
            validate_network_session(document, EVALUATION_TIME)

    def test_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary, "session.json")
            path.write_text(
                '{"schemaVersion":"whitehat-network-session-v1",'
                '"schemaVersion":"changed"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(NetworkSessionError, "duplicate JSON key"):
                load_and_validate_network_session(path, EVALUATION_TIME)


if __name__ == "__main__":
    unittest.main()
