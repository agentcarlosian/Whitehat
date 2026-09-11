from __future__ import annotations

import json
import platform
import re
import subprocess
import sys
import tempfile
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
    inventory = json.loads(
        _run(
            [
                sys.executable,
                "-B",
                "-m",
                "whitehat",
                "analyze",
                "inventory",
                str(ROOT / "examples" / "before"),
                "--json",
            ]
        ).stdout
    )
    dependency_comparison = json.loads(
        _run(
            [
                sys.executable,
                "-B",
                "-m",
                "whitehat",
                "analyze",
                "dependencies",
                str(ROOT / "examples" / "dependencies" / "before" / "pyproject.toml"),
                str(ROOT / "examples" / "dependencies" / "after" / "pyproject.toml"),
                "--json",
            ]
        ).stdout
    )
    synthetic_run = json.loads(
        _run(
            [
                sys.executable,
                "-B",
                "-m",
                "whitehat",
                "run",
                "synthetic",
                "--message",
                "owned golden path",
                "--repeat",
                "2",
                "--json",
            ]
        ).stdout
    )
    ruff_problem = json.loads(
        _run(
            [
                sys.executable,
                "-B",
                "-m",
                "whitehat",
                "scan",
                "ruff",
                str(ROOT / "examples" / "scanner" / "problem"),
                "--json",
            ]
        ).stdout
    )
    ruff_clean = json.loads(
        _run(
            [
                sys.executable,
                "-B",
                "-m",
                "whitehat",
                "scan",
                "ruff",
                str(ROOT / "examples" / "scanner" / "clean"),
                "--json",
            ]
        ).stdout
    )
    network_session = json.loads(
        _run(
            [
                sys.executable,
                "-B",
                "-m",
                "whitehat",
                "session",
                "validate",
                str(ROOT / "examples" / "network-session.synthetic.json"),
                "--evaluation-time",
                "2026-09-11T01:30:00Z",
                "--json",
            ]
        ).stdout
    )
    expected_diff = {"added": 1, "deleted": 0, "modified": 1, "unchanged": 1}
    expected_inventory = {"files": 2, "bytes": 31}
    expected_dependencies = {"added": 1, "removed": 1, "changed": 1, "unchanged": 1}
    with tempfile.TemporaryDirectory() as temporary:
        result_path = Path(temporary, "inventory.json")
        review_path = Path(temporary, "review.json")
        stored_result = json.loads(
            _run(
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "whitehat",
                    "analyze",
                    "inventory",
                    str(ROOT / "examples" / "before"),
                    "--output",
                    str(result_path),
                    "--json",
                ]
            ).stdout
        )
        stored_review = json.loads(
            _run(
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "whitehat",
                    "review",
                    str(result_path),
                    "--decision",
                    "accepted",
                    "--note",
                    "Golden-path local record.",
                    "--output",
                    str(review_path),
                    "--json",
                ]
            ).stdout
        )
        records_valid = (
            json.loads(result_path.read_text(encoding="utf-8")) == stored_result
            and json.loads(review_path.read_text(encoding="utf-8")) == stored_review
            and stored_review.get("reviewOf", {}).get("resultSha256")
            == stored_result.get("resultSha256")
        )
    if (
        not doctor.get("ok")
        or smoke.get("summary") != expected_diff
        or inventory.get("summary") != expected_inventory
        or dependency_comparison.get("summary") != expected_dependencies
        or not records_valid
        or synthetic_run.get("profile") != "python.synthetic.echo"
        or synthetic_run.get("effects", {}).get("workspaceCleaned") is not True
        or synthetic_run.get("effects", {}).get("network") is not False
        or ruff_problem.get("summary", {}).get("codes") != {"F401": 1, "F841": 1}
        or ruff_problem.get("effects", {}).get("workspaceCleaned") is not True
        or ruff_problem.get("claims", {}).get("findingValidityEstablished") is not False
        or ruff_clean.get("summary") != {"observations": 0, "codes": {}}
        or network_session.get("claims", {}).get("networkEngineImplemented")
        is not False
        or network_session.get("claims", {}).get("networkExecutionAuthorized")
        is not False
        or network_session.get("effects", {}).get("network") is not False
    ):
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
                "goldenPath": {
                    "dependencies": expected_dependencies,
                    "diff": expected_diff,
                    "inventory": expected_inventory,
                    "records": {"resultStored": True, "reviewStored": True},
                    "ruffScanner": {"clean": 0, "problem": {"F401": 1, "F841": 1}},
                    "sessionDesign": {
                        "network": False,
                        "networkEngineImplemented": False,
                    },
                    "syntheticRunner": {"network": False, "workspaceCleaned": True},
                },
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
