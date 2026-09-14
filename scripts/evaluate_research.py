"""End-to-end evaluation using actual reviewed engines and owned controls."""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from whitehat.native_tools import TOOLS, platform_key, scan_native  # noqa: E402
from whitehat.records import create_review_document, save_result_document, write_json_document  # noqa: E402
from whitehat.reports import compare_results, import_report  # noqa: E402
from whitehat.research import export_markdown, initialize_workspace  # noqa: E402


def main() -> int:
    tools = {name: str(ROOT / ".whitehat/tools" / name / spec["platforms"][platform_key()]["executable"])
             for name, spec in TOOLS.items()}
    counts = {}
    with tempfile.TemporaryDirectory(prefix="whitehat-evaluate-") as temp:
        root = Path(temp, "case")
        initialize_workspace(str(root), "Owned security rule evaluation")
        for name, expected in (("vulnerable", 5), ("fixed", 0), ("negative", 0)):
            result = scan_native(str(ROOT / "examples/research" / name), "opengrep", tools["opengrep"])
            counts[name] = result["summary"]["observations"]
            if counts[name] != expected:
                raise RuntimeError(f"{name} expected {expected} source observations")
            save_result_document(result, root / "results" / f"{name}.json")
        comparison = compare_results(str(root / "results/vulnerable.json"), str(root / "results/fixed.json"))
        if comparison["summary"] != {"introduced": 0, "absent": 5, "unchanged": 0}:
            raise RuntimeError("baseline comparison failed")
        for name, expected in (("secrets", 1), ("negative", 0)):
            result = scan_native(str(ROOT / "examples/research" / name), "betterleaks", tools["betterleaks"])
            counts[f"secret-{name}"] = result["summary"]["observations"]
            if counts[f"secret-{name}"] != expected or "a1b2c3d4e5f6g7h8i9j0k1l2" in json.dumps(result):
                raise RuntimeError("secret detection/redaction control failed")
        imported = import_report(str(ROOT / "examples/reports/osv.json"), "osv")
        path = root / "results/advisories.json"
        save_result_document(imported, path)
        review = create_review_document(imported, "needs-work", "Reachability requires a separate controlled check.")
        write_json_document(review, root / "notes/review.json")
        exported = export_markdown(str(path), str(root / "exports/review.md"),
            case_path=str(root / "case.json"), review_path=str(root / "notes/review.json"))
        if not exported["ok"] or "Fixed versions reported" not in (root / "exports/review.md").read_text():
            raise RuntimeError("review export failed")
    print(json.dumps({"ok": True, "platform": platform_key(), "nativeFixtures": counts,
        "baseline": comparison["summary"], "reviewExport": True,
        "claim": "Owned fixture evaluation only; no real-target finding or general accuracy claim."}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
