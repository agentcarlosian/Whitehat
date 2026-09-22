"""Exercise workspace dependency inspection with owned artifacts through the CLI."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def evaluate(root: Path, installed: bool = False) -> dict:
    def run(*args, expected=0):
        result = subprocess.run(
            [
                sys.executable,
                *(["-I"] if installed else []),
                "-B",
                "-m",
                "whitehat",
                *map(str, args),
                "--json",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != expected:
            raise RuntimeError(result.stdout + result.stderr)
        return json.loads(result.stdout)

    run("init", root, "--title", "Owned workspace status review")
    source = root / "inputs/report.json"
    source.write_bytes((ROOT / "examples/reports/osv.json").read_bytes())
    for name in ("before", "after"):
        run(
            "import",
            source,
            "--format",
            "osv",
            "--output",
            root / f"results/{name}.json",
        )
    run(
        "compare",
        root / "results/before.json",
        root / "results/after.json",
        "--output",
        root / "results/comparison.json",
    )
    run(
        "packet",
        "init",
        "--project",
        "owned",
        "--title",
        "Owned packet",
        "--evidence",
        root / "results/before.json",
        "--output",
        root / "packet.json",
    )
    run(
        "workspace",
        "index",
        root,
        "--project",
        "owned",
        "--input",
        "inputs/report.json",
        "--result",
        "results/before.json",
        "--result",
        "results/after.json",
        "--result",
        "results/comparison.json",
        "--packet",
        "packet.json",
        "--depends-on",
        "results/before.json=inputs/report.json",
        "--depends-on",
        "results/after.json=inputs/report.json",
        "--output",
        root / "workspace.json",
    )
    current = run("workspace", "check", root / "workspace.json")
    if not current["consistent"]:
        raise RuntimeError("new index failed integrity checks")
    # An explicit input edit invalidates the derived evidence chain.
    value = json.loads(source.read_text())
    value["results"][0]["packages"][0]["package"]["version"] = "1.0.2"
    source.write_text(json.dumps(value), encoding="utf-8")
    stale = run(
        "workspace",
        "check",
        root / "workspace.json",
        "--output",
        root / "results/workspace-status.json",
        expected=3,
    )
    states = {item["path"]: item["status"] for item in stale["artifacts"]}
    if states.get("inputs/report.json") != "changed" or any(
        states.get(name) != "stale"
        for name in ("results/comparison.json", "packet.json")
    ):
        raise RuntimeError("input drift did not propagate to comparison and packet")
    return {
        "ok": True,
        "artifacts": len(states),
        "inputDriftDetected": True,
        "comparisonAndPacketStale": True,
        "installed": installed,
        "network": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir")
    parser.add_argument("--installed", action="store_true")
    args = parser.parse_args()
    if args.output_dir:
        result = evaluate(Path(args.output_dir).absolute(), args.installed)
    else:
        with tempfile.TemporaryDirectory(prefix="whitehat-workspace-") as temporary:
            result = evaluate(Path(temporary) / "review", args.installed)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
