"""Evaluate HTTP evidence, access controls, native API diffs, and owned stateful tests."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from whitehat.api_schema import compare_schema  # noqa: E402
from whitehat.api_testing import test_owned_api  # noqa: E402
from whitehat.http_evidence import import_capture, assess_access, compare_http  # noqa: E402
from whitehat.records import save_result_document  # noqa: E402
from whitehat.research import export_markdown  # noqa: E402


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="whitehat-web-eval-") as temporary:
        root = Path(temporary)
        results = {}
        for name in ("vulnerable", "fixed"):
            imported = import_capture(
                str(ROOT / f"examples/http/{name}.har"),
                "owned-api",
                selected=["/marker"],
            )
            path = root / f"{name}.json"
            save_result_document(imported, path)
            assessment = assess_access(
                str(ROOT / "examples/http/access-matrix.json"), [str(path)]
            )
            results[name] = assessment["summary"]["observations"]
            save_result_document(assessment, root / f"{name}-assessment.json")
        if results != {"vulnerable": 1, "fixed": 0}:
            raise RuntimeError("access controls did not match expected fixture results")
        compared = compare_http(
            str(root / "vulnerable.json"), str(root / "fixed.json"), 1, 1
        )
        if compared["status"] != {"before": 200, "after": 403}:
            raise RuntimeError("HTTP comparison failed")
        export_markdown(
            str(root / "vulnerable-assessment.json"), str(root / "review.md")
        )
    api_diff = compare_schema(
        str(ROOT / "examples/api/before.json"),
        str(ROOT / "examples/api/after.json"),
        "owned-api",
    )
    if not {"response-optional-property-added", "effective-security-changed"} <= {
        v["ruleId"] for v in api_diff["observations"]
    }:
        raise RuntimeError("API diff failed")
    lifecycle = {}
    for broken in (False, True):
        result = test_owned_api(broken)
        outcome = result["provenance"]["lifecycle"]["provenance"]["evaluations"][-1][
            "outcome"
        ]
        if outcome != ("mismatch" if broken else "consistent"):
            raise RuntimeError("lifecycle control failed")
        lifecycle["vulnerable" if broken else "fixed"] = outcome
    print(
        json.dumps(
            {
                "ok": True,
                "accessFixtures": results,
                "apiChanges": api_diff["summary"]["observations"],
                "lifecycle": lifecycle,
                "reportExport": True,
                "externalTargetsTested": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
