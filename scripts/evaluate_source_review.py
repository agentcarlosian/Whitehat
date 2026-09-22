"""Exercise source-flow imports, native controls and review output through the CLI."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def evaluate(root: Path, *, native: bool, installed: bool) -> dict:
    def run(*args, json_output=True):
        completed = subprocess.run(
            [
                sys.executable,
                *(["-I"] if installed else []),
                "-B",
                "-m",
                "whitehat",
                *map(str, args),
                *(["--json"] if json_output else []),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if completed.returncode:
            raise RuntimeError(completed.stdout + completed.stderr)
        return json.loads(completed.stdout) if json_output else completed.stdout

    run("init", root, "--title", "Owned framework source review")
    imported = run(
        "import",
        ROOT / "examples/reports/source-flow.sarif",
        "--format",
        "sarif",
        "--output",
        root / "results/import.json",
    )
    context = imported["observations"][0]["sourceContext"]
    if len(context["relatedLocations"]) != 2 or len(context["flows"][0]["steps"]) != 3:
        raise RuntimeError("SARIF source context was not preserved")
    readable = run(
        "import",
        ROOT / "examples/reports/source-flow.sarif",
        "--format",
        "sarif",
        json_output=False,
    )
    if (
        "Tool-reported source context (unverified)" not in readable
        or "condition: src/guards.ts:4" not in readable
    ):
        raise RuntimeError("terminal source context missing")
    if "synthetic-private-value" in json.dumps(imported) + readable:
        raise RuntimeError("source context retained unselected content")
    evidence = root / "results/import.json"
    counts = {}
    if native:
        for name, expected in (("vulnerable", 6), ("fixed", 0), ("negative", 0)):
            result = run(
                "scan",
                "opengrep",
                ROOT / "examples/research/express" / name,
                "--profile",
                "express-typescript",
                "--output",
                root / f"results/{name}.json",
            )
            counts[name] = result["summary"]["observations"]
            if counts[name] != expected or not result["effects"]["workspaceCleaned"]:
                raise RuntimeError("native Express profile control failed")
            for item in result["observations"]:
                flow = item["sourceContext"]
                if (
                    not flow["representationComplete"]
                    or flow["validation"] != "unverified"
                ):
                    raise RuntimeError("native flow was missing or overstated")
        evidence = root / "results/vulnerable.json"
        compared = run("compare", evidence, root / "results/fixed.json")
        if compared["summary"]["absent"] != 6 or not compared["sameAnalysisProfile"]:
            raise RuntimeError("source-profile comparison failed")
    run(
        "report",
        evidence,
        "--case",
        root / "case.json",
        "--output",
        root / "exports/review.md",
    )
    run(
        "packet",
        "init",
        "--project",
        "owned-source",
        "--title",
        "Owned source flow",
        "--evidence",
        evidence,
        "--output",
        root / "packet.json",
    )
    run(
        "packet", "export", root / "packet.json", "--output", root / "exports/packet.md"
    )
    for name in ("review", "packet"):
        content = (root / f"exports/{name}.md").read_text()
        if "unverified" not in content or "supplied step order" not in content:
            raise RuntimeError("export did not preserve source context")
        if "synthetic-private-value" in content:
            raise RuntimeError("export retained private fixture text")
    return {
        "ok": True,
        "sarifLocations": 2,
        "sarifFlowSteps": 3,
        "nativeControls": counts,
        "reviewAndPacketExport": True,
        "installed": installed,
        "sourceExecuted": False,
        "externalTargetsTested": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--native",
        action="store_true",
        help="Require the installed pinned native engine and run owned controls.",
    )
    parser.add_argument("--installed", action="store_true")
    parser.add_argument("--output-dir")
    args = parser.parse_args()
    if args.output_dir:
        result = evaluate(
            Path(args.output_dir).absolute(),
            native=args.native,
            installed=args.installed,
        )
    else:
        with tempfile.TemporaryDirectory(prefix="whitehat-source-review-") as temporary:
            result = evaluate(
                Path(temporary) / "review", native=args.native, installed=args.installed
            )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
