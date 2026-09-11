from __future__ import annotations

import argparse
import json
from typing import Any, Sequence

from . import __version__
from .dependencies import (
    DependencyError,
    DependencyLimits,
    compare_dependency_manifests,
)
from .diagnostics import doctor_result
from .local_diff import DiffError, DiffLimits, compare_directories, inventory_directory


def _emit(value: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(
            json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        )
        return
    if value.get("schemaVersion") == "whitehat-doctor-v1":
        enabled = [
            name for name, available in value["capabilities"].items() if available
        ]
        print(f"Whitehat {value['version']} ({value['runtime']['python']})")
        print("Available: " + ", ".join(enabled))
        return
    if value.get("schemaVersion") == "whitehat-error-v1":
        print(f"Error: {value['error']['message']}")
        return
    if value.get("schemaVersion") == "whitehat-local-inventory-v1":
        print(
            f"Local inventory: {value['summary']['files']} files, "
            f"{value['summary']['bytes']} bytes"
        )
        for record in value["files"]:
            print(f"{record['size']:10} {record['sha256']} {record['path']}")
        return
    if value.get("schemaVersion") == "whitehat-dependency-comparison-v1":
        summary = value["summary"]
        print(
            f"{value['ecosystem']} dependencies: {summary['added']} added, "
            f"{summary['removed']} removed, {summary['changed']} changed, "
            f"{summary['unchanged']} unchanged"
        )
        for change in value["changes"]:
            print(f"{change['kind']:8} {change['key']}")
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

    doctor = commands.add_parser(
        "doctor", help="Report implemented capability boundaries."
    )
    doctor.add_argument("--json", action="store_true", help="Emit deterministic JSON.")

    analyze = commands.add_parser("analyze", help="Run local read-only analysis.")
    analyze_commands = analyze.add_subparsers(dest="analysis_command", required=True)

    inventory = analyze_commands.add_parser(
        "inventory", help="Inventory one local directory."
    )
    inventory.add_argument("root")
    _add_scan_limits(inventory)
    inventory.add_argument(
        "--json", action="store_true", help="Emit deterministic JSON."
    )

    diff = analyze_commands.add_parser("diff", help="Compare two local directories.")
    diff.add_argument("before")
    diff.add_argument("after")
    _add_scan_limits(diff)
    diff.add_argument("--json", action="store_true", help="Emit deterministic JSON.")

    dependencies = analyze_commands.add_parser(
        "dependencies",
        help="Compare Python or npm dependency manifests.",
    )
    dependencies.add_argument("before")
    dependencies.add_argument("after")
    dependencies.add_argument(
        "--max-manifest-bytes", type=int, default=16 * 1024 * 1024
    )
    dependencies.add_argument("--max-dependencies", type=int, default=20_000)
    dependencies.add_argument(
        "--json", action="store_true", help="Emit deterministic JSON."
    )
    return parser


def _add_scan_limits(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-entries", type=int, default=20_000)
    parser.add_argument("--max-files", type=int, default=10_000)
    parser.add_argument("--max-file-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--max-total-bytes", type=int, default=512 * 1024 * 1024)


def _scan_limits(args: argparse.Namespace) -> DiffLimits:
    return DiffLimits(
        max_entries=args.max_entries,
        max_files=args.max_files,
        max_file_bytes=args.max_file_bytes,
        max_total_bytes=args.max_total_bytes,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "doctor":
            _emit(doctor_result(), args.json)
            return 0
        if args.command == "analyze":
            if args.analysis_command == "inventory":
                _emit(inventory_directory(args.root, _scan_limits(args)), args.json)
                return 0
            if args.analysis_command == "diff":
                _emit(
                    compare_directories(args.before, args.after, _scan_limits(args)),
                    args.json,
                )
                return 0
            if args.analysis_command == "dependencies":
                limits = DependencyLimits(
                    max_manifest_bytes=args.max_manifest_bytes,
                    max_dependencies=args.max_dependencies,
                )
                _emit(
                    compare_dependency_manifests(args.before, args.after, limits),
                    args.json,
                )
                return 0
    except (DiffError, DependencyError) as exc:
        failure = {
            "schemaVersion": "whitehat-error-v1",
            "ok": False,
            "error": {"code": exc.error_code, "message": str(exc)},
        }
        _emit(failure, bool(getattr(args, "json", False)))
        return exc.exit_code
    raise AssertionError("unhandled command")
