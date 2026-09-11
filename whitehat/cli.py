from __future__ import annotations

import argparse
import json
from typing import Any, Sequence

from . import __version__
from .diagnostics import doctor_result
from .local_diff import DiffError, DiffLimits, compare_directories


def _emit(value: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
        return
    if value.get("schemaVersion") == "whitehat-doctor-v1":
        enabled = [name for name, available in value["capabilities"].items() if available]
        print(f"Whitehat {value['version']} ({value['runtime']['python']})")
        print("Available: " + ", ".join(enabled))
        return
    if value.get("schemaVersion") == "whitehat-error-v1":
        print(f"Error: {value['error']['message']}")
        return
    summary = value["summary"]
    print(
        "Directory comparison: "
        f"{summary['added']} added, {summary['deleted']} deleted, "
        f"{summary['modified']} modified, {summary['unchanged']} unchanged"
    )
    for change in value["changes"]:
        print(f"{change['kind']:8} {change['path']}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="whitehat",
        description="Local-first tools for authorized security research.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    doctor = commands.add_parser("doctor", help="Report implemented capability boundaries.")
    doctor.add_argument("--json", action="store_true", help="Emit deterministic JSON.")

    analyze = commands.add_parser("analyze", help="Run local read-only analysis.")
    analyze_commands = analyze.add_subparsers(dest="analysis_command", required=True)
    diff = analyze_commands.add_parser("diff", help="Compare two local directories.")
    diff.add_argument("before")
    diff.add_argument("after")
    diff.add_argument("--max-entries", type=int, default=20_000)
    diff.add_argument("--max-files", type=int, default=10_000)
    diff.add_argument("--max-file-bytes", type=int, default=64 * 1024 * 1024)
    diff.add_argument("--max-total-bytes", type=int, default=512 * 1024 * 1024)
    diff.add_argument("--json", action="store_true", help="Emit deterministic JSON.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "doctor":
            _emit(doctor_result(), args.json)
            return 0
        if args.command == "analyze" and args.analysis_command == "diff":
            limits = DiffLimits(
                max_entries=args.max_entries,
                max_files=args.max_files,
                max_file_bytes=args.max_file_bytes,
                max_total_bytes=args.max_total_bytes,
            )
            _emit(compare_directories(args.before, args.after, limits), args.json)
            return 0
    except DiffError as exc:
        failure = {
            "schemaVersion": "whitehat-error-v1",
            "ok": False,
            "error": {"code": exc.error_code, "message": str(exc)},
        }
        _emit(failure, bool(getattr(args, "json", False)))
        return exc.exit_code
    raise AssertionError("unhandled command")
