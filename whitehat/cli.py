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
from .records import (
    MAX_RESULT_BYTES,
    REVIEW_DECISIONS,
    RecordError,
    create_review_document,
    load_result_document,
    save_result_document,
    write_json_document,
)
from .runner import ProcessLimits, RunnerError, run_synthetic
from .scanner import ScannerError, ScannerLimits, scan_with_ruff


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
    if value.get("schemaVersion") == "whitehat-local-review-v1":
        print(
            f"Local review: {value['decision']} for {value['reviewOf']['resultSha256']}"
        )
        print(value["note"])
        return
    if value.get("schemaVersion") == "whitehat-synthetic-run-v1":
        print(
            f"Synthetic run: {value['profile']} exited {value['process']['exitCode']} "
            f"in {value['process']['elapsedMs']} ms"
        )
        print(
            f"Payload: {value['output']['payloadBytes']} bytes, "
            f"workspace cleaned: {value['effects']['workspaceCleaned']}"
        )
        return
    if value.get("schemaVersion") == "whitehat-scanner-result-v1":
        print(
            f"Ruff scan: {value['summary']['observations']} observations, "
            f"workspace cleaned: {value['effects']['workspaceCleaned']}"
        )
        for observation in value["observations"]:
            location = observation["location"]
            print(
                f"{observation['code']:8} {observation['path']}:"
                f"{location['row']}:{location['column']}"
            )
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
    _add_output(inventory)
    inventory.add_argument(
        "--json", action="store_true", help="Emit deterministic JSON."
    )

    diff = analyze_commands.add_parser("diff", help="Compare two local directories.")
    diff.add_argument("before")
    diff.add_argument("after")
    _add_scan_limits(diff)
    _add_output(diff)
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
    _add_output(dependencies)
    dependencies.add_argument(
        "--json", action="store_true", help="Emit deterministic JSON."
    )

    review = commands.add_parser(
        "review", help="Write a bounded local review of one saved result."
    )
    review.add_argument("result")
    review.add_argument("--decision", choices=sorted(REVIEW_DECISIONS), required=True)
    review.add_argument("--note", required=True)
    review.add_argument("--author")
    review.add_argument("--output", required=True)
    review.add_argument("--max-result-bytes", type=int, default=MAX_RESULT_BYTES)
    review.add_argument("--json", action="store_true", help="Emit deterministic JSON.")

    run = commands.add_parser("run", help="Run one fixed local synthetic profile.")
    run_commands = run.add_subparsers(dest="run_command", required=True)
    synthetic = run_commands.add_parser(
        "synthetic", help="Run the fixed dependency-free synthetic child."
    )
    synthetic.add_argument("--message", required=True)
    synthetic.add_argument("--repeat", type=int, default=1)
    synthetic.add_argument("--delay-ms", type=int, default=0)
    synthetic.add_argument("--timeout-seconds", type=float, default=5.0)
    synthetic.add_argument("--max-input-bytes", type=int, default=64 * 1024)
    synthetic.add_argument("--max-stdout-bytes", type=int, default=1024 * 1024)
    synthetic.add_argument("--max-stderr-bytes", type=int, default=64 * 1024)
    synthetic.add_argument("--workspace-root")
    _add_output(synthetic)
    synthetic.add_argument(
        "--json", action="store_true", help="Emit deterministic JSON."
    )

    scan = commands.add_parser("scan", help="Run one reviewed local scanner adapter.")
    scan_commands = scan.add_subparsers(dest="scan_command", required=True)
    ruff = scan_commands.add_parser(
        "ruff", help="Run the pinned Ruff adapter over bounded copied Python source."
    )
    ruff.add_argument("source")
    ruff.add_argument("--max-entries", type=int, default=20_000)
    ruff.add_argument("--max-source-files", type=int, default=1_000)
    ruff.add_argument("--max-file-bytes", type=int, default=1024 * 1024)
    ruff.add_argument("--max-total-bytes", type=int, default=16 * 1024 * 1024)
    ruff.add_argument("--max-observations", type=int, default=1_000)
    ruff.add_argument("--timeout-seconds", type=float, default=30.0)
    ruff.add_argument("--max-stdout-bytes", type=int, default=8 * 1024 * 1024)
    ruff.add_argument("--max-stderr-bytes", type=int, default=64 * 1024)
    ruff.add_argument("--workspace-root")
    _add_output(ruff)
    ruff.add_argument("--json", action="store_true", help="Emit deterministic JSON.")
    return parser


def _add_scan_limits(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-entries", type=int, default=20_000)
    parser.add_argument("--max-files", type=int, default=10_000)
    parser.add_argument("--max-file-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--max-total-bytes", type=int, default=512 * 1024 * 1024)


def _add_output(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--output",
        help="Optionally store the exact JSON result; refuses overwrite.",
    )


def _scan_limits(args: argparse.Namespace) -> DiffLimits:
    return DiffLimits(
        max_entries=args.max_entries,
        max_files=args.max_files,
        max_file_bytes=args.max_file_bytes,
        max_total_bytes=args.max_total_bytes,
    )


def _emit_analysis(result: dict[str, Any], args: argparse.Namespace) -> None:
    saved = save_result_document(result, args.output) if args.output else None
    _emit(result, args.json)
    if saved is not None and not args.json:
        print(f"Saved result: {saved}")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "doctor":
            _emit(doctor_result(), args.json)
            return 0
        if args.command == "analyze":
            if args.analysis_command == "inventory":
                _emit_analysis(inventory_directory(args.root, _scan_limits(args)), args)
                return 0
            if args.analysis_command == "diff":
                _emit_analysis(
                    compare_directories(args.before, args.after, _scan_limits(args)),
                    args,
                )
                return 0
            if args.analysis_command == "dependencies":
                limits = DependencyLimits(
                    max_manifest_bytes=args.max_manifest_bytes,
                    max_dependencies=args.max_dependencies,
                )
                _emit_analysis(
                    compare_dependency_manifests(args.before, args.after, limits),
                    args,
                )
                return 0
        if args.command == "review":
            result = load_result_document(args.result, args.max_result_bytes)
            review = create_review_document(
                result, args.decision, args.note, args.author
            )
            saved = write_json_document(review, args.output)
            _emit(review, args.json)
            if not args.json:
                print(f"Saved review: {saved}")
            return 0
        if args.command == "run" and args.run_command == "synthetic":
            limits = ProcessLimits(
                timeout_seconds=args.timeout_seconds,
                max_input_bytes=args.max_input_bytes,
                max_stdout_bytes=args.max_stdout_bytes,
                max_stderr_bytes=args.max_stderr_bytes,
            )
            _emit_analysis(
                run_synthetic(
                    args.message,
                    args.repeat,
                    args.delay_ms,
                    limits,
                    args.workspace_root,
                ),
                args,
            )
            return 0
        if args.command == "scan" and args.scan_command == "ruff":
            limits = ScannerLimits(
                max_entries=args.max_entries,
                max_source_files=args.max_source_files,
                max_file_bytes=args.max_file_bytes,
                max_total_bytes=args.max_total_bytes,
                max_observations=args.max_observations,
                timeout_seconds=args.timeout_seconds,
                max_stdout_bytes=args.max_stdout_bytes,
                max_stderr_bytes=args.max_stderr_bytes,
            )
            _emit_analysis(
                scan_with_ruff(args.source, limits, args.workspace_root),
                args,
            )
            return 0
    except (DiffError, DependencyError, RecordError, RunnerError, ScannerError) as exc:
        failure = {
            "schemaVersion": "whitehat-error-v1",
            "ok": False,
            "error": {"code": exc.error_code, "message": str(exc)},
        }
        _emit(failure, bool(getattr(args, "json", False)))
        return exc.exit_code
    raise AssertionError("unhandled command")
