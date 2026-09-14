import json
import tempfile
import unittest
from pathlib import Path

from whitehat.http_evidence import (
    assess_access,
    compare_http,
    exchange,
    import_capture,
    json_summary,
    pointers,
)
from whitehat.records import save_result_document
from whitehat.reports import ReportError, canonical, normalize, result_document

ROOT = Path(__file__).resolve().parents[1]


class HttpEvidenceTests(unittest.TestCase):
    def test_request_value_changes_alter_evidence_without_exporting_values(self):
        response = {"status": 200, "content": {"text": '{"ok":true}'}}
        request = {
            "method": "POST",
            "url": "https://owned.invalid/items?id=first-private-value",
            "postData": {"text": '{"name":"first-private-value"}'},
        }
        a = exchange(
            "owned",
            request,
            response,
            identity="alice",
            object_id="item",
            operation="write",
            selected=[],
        )
        request["url"] = "https://owned.invalid/items?id=second-private-value"
        request["postData"]["text"] = '{"name":"second-private-value"}'
        b = exchange(
            "owned",
            request,
            response,
            identity="alice",
            object_id="item",
            operation="write",
            selected=[],
        )
        self.assertEqual(a["observationId"], b["observationId"])
        self.assertNotEqual(a["evidenceSha256"], b["evidenceSha256"])
        self.assertEqual(a["context"]["bodyParameters"], ["/name"])
        self.assertNotIn("first-private-value", json.dumps(a))

    def test_zap_method_instances_do_not_collapse(self):
        value = {
            "site": [
                {
                    "alerts": [
                        {
                            "alertRef": "test",
                            "instances": [
                                {"uri": "https://owned.invalid/items", "method": "GET"},
                                {
                                    "uri": "https://owned.invalid/items",
                                    "method": "POST",
                                },
                            ],
                        }
                    ]
                }
            ]
        }
        result = result_document(normalize(canonical(value), "zap"), {})
        self.assertEqual(result["summary"]["observations"], 2)

    def test_identity_is_project_method_principal_and_object_bound(self):
        request = {"method": "GET", "url": "https://owned.invalid/items?token=private"}
        response = {
            "status": 200,
            "content": {"text": '{"marker":"owned-a","timestamp":1}'},
        }
        a = exchange(
            "project-a",
            request,
            response,
            identity="alice",
            object_id="a",
            operation="read",
            selected=["/marker"],
        )
        response["content"]["text"] = '{"marker":"owned-a","timestamp":2}'
        b = exchange(
            "project-a",
            request,
            response,
            identity="alice",
            object_id="a",
            operation="read",
            selected=["/marker"],
        )
        self.assertEqual(a["observationId"], b["observationId"])
        self.assertNotEqual(a["evidenceSha256"], b["evidenceSha256"])
        c = exchange(
            "project-b",
            request,
            response,
            identity="alice",
            object_id="a",
            operation="read",
            selected=["/marker"],
        )
        self.assertNotEqual(a["observationId"], c["observationId"])
        self.assertNotIn("private", json.dumps(a))
        self.assertNotIn("timestamp", json.dumps(a["response"]["json"]["values"]))

    def test_sensitive_and_container_selectors_are_rejected(self):
        for pointer in ("/password", "/access_token", "bad", "/a~3b"):
            with self.assertRaises(ReportError):
                pointers([pointer])
        with self.assertRaises(ReportError):
            json_summary(b'{"a": {"b":1}}', ["/a"])

    def test_owned_har_controls_and_access_assessment(self):
        with tempfile.TemporaryDirectory() as temp:
            paths = []
            for name in ("vulnerable", "fixed"):
                evidence = import_capture(
                    str(ROOT / f"examples/http/{name}.har"),
                    "owned-api",
                    selected=["/marker"],
                )
                path = Path(temp, name + ".json")
                save_result_document(evidence, path)
                paths.append(str(path))
            matrix = str(ROOT / "examples/http/access-matrix.json")
            bad = assess_access(matrix, [paths[0]])
            good = assess_access(matrix, [paths[1]])
            self.assertEqual(bad["summary"]["observations"], 1)
            self.assertEqual(good["summary"]["observations"], 0)
            self.assertTrue(
                all(
                    r["outcome"] == "consistent"
                    for r in good["provenance"]["evaluations"]
                )
            )
            comparison = compare_http(paths[0], paths[1], 1, 1)
            self.assertEqual(comparison["status"], {"before": 200, "after": 403})
            self.assertFalse(any(comparison["claims"].values()))

    def test_unselected_proof_and_misleading_200_are_inconclusive(self):
        with tempfile.TemporaryDirectory() as temp:
            evidence = import_capture(
                str(ROOT / "examples/http/vulnerable.har"), "owned-api"
            )
            path = Path(temp, "evidence.json")
            save_result_document(evidence, path)
            assessed = assess_access(
                str(ROOT / "examples/http/access-matrix.json"), [str(path)]
            )
            self.assertTrue(
                all(
                    r["outcome"] == "inconclusive"
                    for r in assessed["provenance"]["evaluations"]
                )
            )


if __name__ == "__main__":
    unittest.main()
