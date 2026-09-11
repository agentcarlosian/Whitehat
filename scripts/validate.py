from __future__ import annotations

import json
import platform
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _run(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        arguments,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        if completed.stdout:
            print(completed.stdout, end="")
        if completed.stderr:
            print(completed.stderr, end="", file=sys.stderr)
        raise SystemExit(completed.returncode)
    return completed


def _syntax_check() -> int:
    checked = 0
    for path in sorted(ROOT.rglob("*.py")):
        if ".git" in path.parts or "__pycache__" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        compile(source, str(path), "exec")
        checked += 1
    return checked


def main() -> int:
    syntax_files = _syntax_check()
    tests = _run(
        [
            sys.executable,
            "-B",
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-p",
            "test_*.py",
            "-v",
        ]
    )
    doctor = json.loads(
        _run([sys.executable, "-B", "-m", "whitehat", "doctor", "--json"]).stdout
    )
    smoke = json.loads(
        _run(
            [
                sys.executable,
                "-B",
                "-m",
                "whitehat",
                "analyze",
                "diff",
                str(ROOT / "examples" / "before"),
                str(ROOT / "examples" / "after"),
                "--json",
            ]
        ).stdout
    )
    expected = {"added": 1, "deleted": 0, "modified": 1, "unchanged": 1}
    if not doctor.get("ok") or smoke.get("summary") != expected:
        raise SystemExit("golden-path validation failed")
    test_count = sum(
        line.startswith("test_") for line in (tests.stdout + tests.stderr).splitlines()
    )
    skipped_match = re.search(r"skipped=(\d+)", tests.stdout + tests.stderr)
    skipped = int(skipped_match.group(1)) if skipped_match else 0
    print(
        json.dumps(
            {
                "schemaVersion": "whitehat-validation-v1",
                "ok": True,
                "python": platform.python_version(),
                "skipped": skipped,
                "syntaxFiles": syntax_files,
                "testsRan": test_count,
                "goldenPath": expected,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
