"""Exercise the selected bounty workflow through the CLI using owned captures."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ISOLATED_INSTALL = False


def run(*args: str) -> dict:
    result = subprocess.run(
        [
            sys.executable,
            *(["-I"] if ISOLATED_INSTALL else []),
            "-B",
            "-m",
            "whitehat",
            *args,
            "--json",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return json.loads(result.stdout)


def evaluate(root: Path) -> dict:
    run("init", str(root), "--title", "Owned API bounty workflow")
    source = json.loads((ROOT / "examples/bounty/capture.har").read_text())
    capture_path = root / "inputs/capture.har"
    capture_path.write_text(json.dumps(source), encoding="utf-8")
    prepared = run(
        "http",
        "prepare",
        str(capture_path),
        "--project",
        "owned-api",
        "--identity",
        "alice",
        "--object",
        "owned-item",
        "--operation",
        "create",
        "--output-dir",
        str(root / "prepared"),
    )
    vulnerable_path = root / "results/vulnerable.json"
    vulnerable = run(
        "http",
        "import",
        str(capture_path),
        "--project",
        "owned-api",
        "--select",
        "/id",
        "--select",
        "/marker",
        "--output",
        str(vulnerable_path),
    )
    source["log"]["entries"][2]["response"] = {
        "status": 403,
        "content": {"text": '{"error":"denied"}'},
    }
    fixed_capture = root / "inputs/fixed.har"
    fixed_capture.write_text(json.dumps(source), encoding="utf-8")
    fixed_path = root / "results/fixed.json"
    fixed = run(
        "http",
        "import",
        str(fixed_capture),
        "--project",
        "owned-api",
        "--select",
        "/id",
        "--select",
        "/marker",
        "--output",
        str(fixed_path),
    )
    comparison_path = root / "results/comparison.json"
    run(
        "http",
        "compare",
        str(vulnerable_path),
        str(fixed_path),
        "--before-index",
        "2",
        "--after-index",
        "2",
        "--output",
        str(comparison_path),
    )
    assessment_path = root / "results/assessment.json"
    assessment = run(
        "http",
        "assess",
        str(ROOT / "examples/bounty/access-matrix.json"),
        "--evidence",
        str(vulnerable_path),
        "--output",
        str(assessment_path),
    )
    template = json.loads((ROOT / "examples/http/request.example.json").read_text())
    template.update(
        url="https://owned.example.invalid/items/PLACEHOLDER",
        objectId="owned-item",
        operationId="read",
    )
    template_path = root / "inputs/read-template.json"
    template_path.write_text(json.dumps(template), encoding="utf-8")
    preview = run("http", "preview", str(template_path))
    plan = {
        "schemaVersion": "whitehat-request-binding-v1",
        "projectId": "owned-api",
        "source": {
            "path": "results/vulnerable.json",
            "resultSha256": vulnerable["resultSha256"],
            "evidenceSha256": vulnerable["exchanges"][0]["evidenceSha256"],
            "pointer": "/id",
            "identityId": "alice",
            "objectId": "owned-item",
        },
        "request": {
            "path": "inputs/read-template.json",
            "requestSha256": preview["requestSha256"],
        },
        "pathSegment": 2,
        "expectedSegment": "PLACEHOLDER",
    }
    (root / "binding.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    bound = run(
        "http", "bind", str(root / "binding.json"), "--output-dir", str(root / "bound")
    )
    if (
        json.loads((root / "bound/request.json").read_text())["url"]
        != "https://owned.example.invalid/items/owned-42"
    ):
        raise RuntimeError("owned binding did not preserve the expected request")
    manifest_path = root / "packet.json"
    run(
        "packet",
        "init",
        "--project",
        "owned-api",
        "--title",
        "Owned cross-identity access review",
        "--evidence",
        str(vulnerable_path),
        "--evidence",
        str(fixed_path),
        "--evidence",
        str(comparison_path),
        "--evidence",
        str(assessment_path),
        "--output",
        str(manifest_path),
    )
    manifest = json.loads(manifest_path.read_text())
    manifest.update(
        prerequisites="Owned synthetic captures label Alice as owner and Bob as another controlled identity. No live reproduction was performed.",
        impact="The vulnerable synthetic capture exposes the owned marker to Bob; the fixed capture denies the same labeled request.",
        limitations="These are authored fixtures. Identity, object ownership and production impact are not independently established.",
        negativeControl="Alice's intended owner read remains successful; Bob's corresponding fixed response is 403 without the owned marker.",
    )
    manifest["steps"] = [
        {
            "id": "access-comparison",
            "action": "Inspect Alice's owner read and Bob's read of the same owned object in both captures.",
            "expected": "Alice sees the marker; Bob cannot see it.",
            "actual": "Bob sees the marker in the vulnerable capture and receives 403 in the fixed capture.",
            "evidence": [r["id"] for r in manifest["evidence"]],
        }
    ]
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    checked = run("packet", "check", str(manifest_path))
    if not checked["contentComplete"] or assessment["summary"]["observations"] != 1:
        raise RuntimeError("owned report completeness or access expectation failed")
    exported = run(
        "packet",
        "export",
        str(manifest_path),
        "--preset",
        "hackerone",
        "--output",
        str(root / "exports/bounty-review.md"),
    )
    candidate = str(root / "candidate")
    run(
        "candidate",
        "init",
        candidate,
        "--id",
        "owned-access-1",
        "--project",
        "owned-api",
        "--title",
        "Owned access discrepancy",
    )
    run(
        "candidate",
        "record",
        candidate,
        "--evidence",
        str(vulnerable_path),
        "--select",
        vulnerable["exchanges"][2]["evidenceSha256"],
        "--decision",
        "needs-work",
        "--note",
        "Synthetic discrepancy; verify ownership and real impact before a finding.",
    )
    retest = run(
        "candidate",
        "record",
        candidate,
        "--evidence",
        str(fixed_path),
        "--select",
        fixed["exchanges"][2]["evidenceSha256"],
        "--decision",
        "not-reproduced",
        "--note",
        "The fixed synthetic twin denies Bob while preserving Alice's control.",
        "--retest-of",
        "1",
    )
    history = run("candidate", "history", candidate)
    covered = run(
        "api",
        "coverage",
        str(ROOT / "examples/api/before.json"),
        "--project",
        "owned-api",
        "--evidence",
        str(vulnerable_path),
        "--matrix",
        str(ROOT / "examples/bounty/access-matrix.json"),
        "--output",
        str(root / "results/coverage.json"),
    )
    if (
        retest["decision"] != "not-reproduced"
        or len(history["decisions"]) != 2
        or len(covered["accessCases"]) != 2
    ):
        raise RuntimeError("owned triage/coverage workflow failed")
    return {
        "ok": True,
        "preparedRequest": prepared["requestSha256"],
        "boundRequest": bound["requestSha256"],
        "packet": exported["markdownSha256"],
        "contentComplete": checked["contentComplete"],
        "candidateDecisions": len(history["decisions"]),
        "accessCases": len(covered["accessCases"]),
        "externalTargetsTested": False,
    }


def main() -> int:
    global ISOLATED_INSTALL
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir", help="Keep the owned walkthrough artifacts in a new directory."
    )
    parser.add_argument(
        "--installed",
        action="store_true",
        help="Use isolated Python imports to exercise the installed package.",
    )
    args = parser.parse_args()
    ISOLATED_INSTALL = args.installed
    if args.output_dir:
        result = evaluate(Path(args.output_dir).absolute())
    else:
        with tempfile.TemporaryDirectory(
            prefix="whitehat-bounty-evaluation-"
        ) as temporary:
            result = evaluate(Path(temporary) / "review")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
