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
from .network_session import (
    NetworkSessionError,
    load_and_validate_network_session,
    parse_evaluation_time,
)
from .network_engine import (
    NetworkExecutionError,
    execute_loopback_observation,
    stop_loopback_session,
)
from .records import (
    MAX_RESULT_BYTES,
    REVIEW_DECISIONS,
    RecordError,
    create_review_document,
    load_result_document,
    save_result_document,
    write_json_document,
)
from .release_audit import ReleaseAuditError, audit_release
from .runner import ProcessLimits, RunnerError, run_synthetic
from .scanner import ScannerError, ScannerLimits, scan_with_ruff
from .native_tools import scan_native, toolkit_status
from .reports import FORMATS, compare_results, import_report
from .research import export_markdown, initialize_workspace
from .http_evidence import import_capture, compare_http, assess_access
from .http_replay import replay, request_preview, stop_session, run_scenario
from .api_schema import inventory_schema, compare_schema, coverage
from .api_testing import test_owned_api
from .preparation import prepare_capture, bind_request
from .packets import initialize_packet, check_packet, export_packet
from .candidates import DECISIONS, initialize_candidate, record_decision, candidate_history


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
    if value.get("schemaVersion") == "whitehat-toolkit-v1":
        for tool in value["native"]:
            print(f"{tool['tool']} {tool['version']} ({', '.join(tool['platforms'])})")
        print("Report imports: " + ", ".join(value["imports"]))
        print("Explicit setup: " + value["setup"])
        return
    if value.get("schemaVersion") == "whitehat-research-result-v1":
        print(f"Research results: {value['summary']['observations']} observations")
        for item in value["observations"]:
            location = item["path"] or item["endpoint"] or "(no location)"
            if item["line"] is not None:
                location += f":{item['line']}"
            print(f"{item['tool']} / {item['ruleId']}  {location}")
            print("  " + item["explanation"])
        return
    if value.get("schemaVersion") == "whitehat-research-comparison-v1":
        summary = value["summary"]
        print(f"Research comparison: {summary['introduced']} introduced, {summary['absent']} absent, {summary['unchanged']} unchanged")
        print(f"Metadata changes: {summary.get('metadataChanged', 0)}; comparison: {value.get('comparisonSuitability', 'unspecified')}")
        print(value["interpretation"])
        return
    if value.get("schemaVersion") == "whitehat-workspace-v1":
        print(f"Created research workspace: {value['title']}")
        print("Edit case.json; use inputs/, results/, notes/, and exports/.")
        return
    if value.get("schemaVersion") == "whitehat-markdown-export-v1":
        print(f"Exported research review ({value['bytes']} bytes), SHA-256 {value['markdownSha256']}")
        return
    if value.get("schemaVersion") == "whitehat-http-evidence-v1":
        print(f"HTTP evidence: {len(value['exchanges'])} exchanges in {value['projectId']}")
        incomplete = value.get("provenance", {}).get("incompleteEntries", [])
        if incomplete:
            print(f"Incomplete capture entries: {len(incomplete)} (no HTTP response)")
        for entry in value["exchanges"]:
            c = entry["context"]
            print(f"{c['identityId']} {c['method']} {c['endpoint']} -> {entry['response']['status']}")
        return
    if value.get("schemaVersion") == "whitehat-http-comparison-v1":
        print(f"HTTP comparison: {len(value['shapeChanges'])} structural and {len(value['valueChanges'])} selected-value changes")
        print(f"Status: {value['status']['before']} -> {value['status']['after']}")
        return
    if value.get("schemaVersion") == "whitehat-request-preview-v1":
        print(f"{value['method']} {value['endpoint']}\nRequest SHA-256: {value['requestSha256']}")
        return
    if value.get("schemaVersion") == "whitehat-replay-stop-v1":
        print(f"Stopped replay session {value['sessionId']}")
        return
    if value.get("schemaVersion") == "whitehat-api-inventory-v1":
        for op in value["operations"]:
            print(f"{op['method']} {op['path']} - {op['operationId']} (anonymous declared: {op['anonymousDeclared']})")
        return
    if value.get("schemaVersion") == "whitehat-api-coverage-v1":
        print(f"API coverage: {len(value['observedOperations'])} observed, {len(value['unobservedOperations'])} unobserved, {len(value['undocumentedRequests'])} undocumented/ambiguous requests")
        for case in value.get("accessCases", []):
            print(f"Access {case['rowId']}: {case['outcome']}")
        for scenario in value.get("scenarios", []):
            for step in scenario["steps"]:
                print(f"Scenario step {step['stepId']}: {step['outcome']}")
        return
    if value.get("schemaVersion") == "whitehat-preparation-v1":
        print(f"Prepared {value['method']} {value['endpoint']}")
        print(f"Request SHA-256: {value['requestSha256']}")
        for diagnostic in value["diagnostics"]:
            print("  " + diagnostic["code"])
        print("Request artifacts written; session approval is still required for execution.")
        return
    if value.get("schemaVersion") in {"whitehat-packet-init-v1", "whitehat-packet-check-v1", "whitehat-packet-export-v1"}:
        print("Packet manifest SHA-256: " + value["manifestSha256"])
        if "contentComplete" in value:
            print("Content complete: " + str(value["contentComplete"]))
            for issue in value["issues"]:
                print(f"  {issue['code']}: {issue['item']}")
        return
    if value.get("schemaVersion") == "whitehat-candidate-init-v1":
        print(f"Created candidate {value['candidateId']}: {value['title']}")
        return
    if value.get("schemaVersion") == "whitehat-candidate-decision-v1":
        print(f"Candidate {value['candidateId']} decision {value['sequence']}: {value['decision']}")
        print(value["note"])
        if value["comparisonSuitable"] is False:
            print("Retest evidence is not comparable to the selected prior decision.")
        return
    if value.get("schemaVersion") == "whitehat-candidate-history-v1":
        print("Candidate " + value["candidate"]["candidateId"])
        for item in value["decisions"]:
            print(f"{item['sequence']}: {item['decision']} - {item['note']}")
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
    if value.get("schemaVersion") == "whitehat-network-session-validation-v1":
        print(
            f"Network session design: {value['sessionId']} is valid at "
            f"{value['evaluatedAt']}"
        )
        print(
            f"Network engine implemented: "
            f"{str(value['claims']['networkEngineImplemented']).lower()}; "
            "execution authorized by validation: false"
        )
        return
    if value.get("schemaVersion") == "whitehat-loopback-observation-v1":
        print(
            f"Loopback observation {value['request']['sequence']}: "
            f"HTTP {value['response']['status']} ({value['response']['bytesRead']} bytes)"
        )
        print(
            f"Outcome: {value['response']['outcome']}; "
            f"remaining requests: {value['ledger']['remainingRequests']}"
        )
        return
    if value.get("schemaVersion") == "whitehat-loopback-stop-v1":
        print(f"Loopback session stopped: {value['sessionId']} ({value['stopReason']})")
        return
    if value.get("schemaVersion") == "whitehat-release-audit-v1":
        print(
            f"Release audit: {value['status']} at {value['commitSha'][:12]} "
            f"with {value['secrets']['matches']} secret matches"
        )
        print("Publication authorized: false; publication performed: false")
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
        description="Security research and authorized bounty workflows.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    doctor = commands.add_parser(
        "doctor", help="Report implemented capability boundaries."
    )
    doctor.add_argument("--json", action="store_true", help="Emit deterministic JSON.")

    toolkit = commands.add_parser("tools", help="List reviewed tools, versions, platforms, and import formats.")
    toolkit.add_argument("--json", action="store_true")

    report_import = commands.add_parser("import", help="Normalize an existing security report without running its tool.")
    report_import.add_argument("report")
    report_import.add_argument("--format", required=True, choices=FORMATS)
    report_import.add_argument("--source-root", help="Lexical prefix to strip from absolute report paths; no files are opened there.")
    report_import.add_argument("--json", action="store_true")
    _add_output(report_import)

    compare = commands.add_parser("compare", help="Compare saved research results by observation fingerprint.")
    compare.add_argument("before")
    compare.add_argument("after")
    compare.add_argument("--json", action="store_true")
    _add_output(compare)

    initialize = commands.add_parser("init", help="Create a portable research workspace in a new directory.")
    initialize.add_argument("directory")
    initialize.add_argument("--title", default="Security research review")
    initialize.add_argument("--json", action="store_true")

    report = commands.add_parser("report", help="Export a saved research result and optional case/review as Markdown.")
    report.add_argument("result")
    report.add_argument("--case", help="Structured research case JSON.")
    report.add_argument("--review", help="Hash-linked Whitehat review note for this result.")
    report.add_argument("--output", required=True)
    report.add_argument("--json", action="store_true")

    packet = commands.add_parser("packet", help="Assemble selected evidence into a reproducible research draft.")
    packet_commands = packet.add_subparsers(dest="packet_command", required=True)
    packet_init = packet_commands.add_parser("init", help="Create a manifest with explicitly selected normalized evidence.")
    packet_init.add_argument("--project", required=True)
    packet_init.add_argument("--title", default="Research draft")
    packet_init.add_argument("--evidence", action="append", required=True)
    packet_init.add_argument("--output", required=True)
    packet_init.add_argument("--json", action="store_true")
    packet_check = packet_commands.add_parser("check", help="Verify evidence links and report missing draft content.")
    packet_check.add_argument("manifest")
    _add_output(packet_check)
    packet_check.add_argument("--json", action="store_true")
    packet_export = packet_commands.add_parser("export", help="Render selected evidence and draft completeness as Markdown.")
    packet_export.add_argument("manifest")
    packet_export.add_argument("--preset", choices=("generic", "hackerone", "bugcrowd"), default="generic")
    packet_export.add_argument("--output", required=True)
    packet_export.add_argument("--json", action="store_true")

    candidate = commands.add_parser("candidate", help="Record per-candidate decisions and explicit retest history.")
    candidate_commands = candidate.add_subparsers(dest="candidate_command", required=True)
    candidate_init = candidate_commands.add_parser("init", help="Create a candidate directory and empty decision history.")
    candidate_init.add_argument("directory")
    candidate_init.add_argument("--id", required=True)
    candidate_init.add_argument("--project", required=True)
    candidate_init.add_argument("--title", required=True)
    candidate_init.add_argument("--json", action="store_true")
    decision = candidate_commands.add_parser("record", help="Append a hash-linked decision selecting observations or exchanges.")
    decision.add_argument("directory")
    decision.add_argument("--evidence", required=True)
    decision.add_argument("--select", action="append", default=[])
    decision.add_argument("--decision", choices=sorted(DECISIONS), required=True)
    decision.add_argument("--note", required=True)
    decision.add_argument("--retest-of", type=int)
    decision.add_argument("--related")
    decision.add_argument("--relation", choices=("possible-duplicate", "same-candidate"))
    decision.add_argument("--json", action="store_true")
    history = candidate_commands.add_parser("history", help="Validate and display a candidate's linked decisions.")
    history.add_argument("directory")
    _add_output(history)
    history.add_argument("--json", action="store_true")

    http = commands.add_parser("http", help="Import HTTP evidence, compare responses, and assess access expectations.")
    http_commands = http.add_subparsers(dest="http_command", required=True)
    prepare = http_commands.add_parser("prepare", help="Prepare one source capture entry and an unapproved session draft.")
    prepare.add_argument("capture")
    prepare.add_argument("--format", choices=("har", "capture"), default="har")
    prepare.add_argument("--index", type=int, default=0)
    prepare.add_argument("--project", required=True)
    prepare.add_argument("--identity", default="researcher")
    prepare.add_argument("--object", default="object")
    prepare.add_argument("--operation", default="operation")
    prepare.add_argument("--output-dir", required=True)
    prepare.add_argument("--json", action="store_true")
    binding = http_commands.add_parser("bind", help="Bind a selected evidence ID into one declared path segment offline.")
    binding.add_argument("plan")
    binding.add_argument("--output-dir", required=True)
    binding.add_argument("--json", action="store_true")
    capture = http_commands.add_parser("import", help="Import HAR 1.2 or an explicit request/response capture.")
    capture.add_argument("capture")
    capture.add_argument("--format", choices=("har", "capture"), default="har")
    capture.add_argument("--project", required=True)
    capture.add_argument("--identity", default="unlabeled")
    capture.add_argument("--object", default="unlabeled")
    capture.add_argument("--operation", default="unlabeled")
    capture.add_argument("--select", action="append", default=[], help="Retain one explicitly selected nonsensitive scalar JSON pointer.")
    _add_output(capture)
    capture.add_argument("--json", action="store_true")
    http_compare = http_commands.add_parser("compare", help="Compare two selected exchanges, preserving identity and status context.")
    http_compare.add_argument("before")
    http_compare.add_argument("after")
    http_compare.add_argument("--before-index", type=int, default=0)
    http_compare.add_argument("--after-index", type=int, default=0)
    http_compare.add_argument("--ignore", action="append", default=[])
    _add_output(http_compare)
    http_compare.add_argument("--json", action="store_true")
    access = http_commands.add_parser("assess", help="Assess explicit identity/object/access expectations against saved evidence.")
    access.add_argument("matrix")
    access.add_argument("--evidence", action="append", required=True)
    _add_output(access)
    access.add_argument("--json", action="store_true")
    preview = http_commands.add_parser("preview", help="Validate a prepared request and show its approval hash without sending it.")
    preview.add_argument("request")
    preview.add_argument("--json", action="store_true")
    replay_cmd = http_commands.add_parser("replay", help="Replay one exact approved request with a session identity.")
    replay_cmd.add_argument("request")
    replay_cmd.add_argument("--session", required=True)
    replay_cmd.add_argument("--identity", required=True)
    replay_cmd.add_argument("--state", required=True)
    _add_output(replay_cmd)
    replay_cmd.add_argument("--json", action="store_true")
    stop_replay = http_commands.add_parser("stop", help="Stop subsequent requests in the named replay session.")
    stop_replay.add_argument("session")
    stop_replay.add_argument("--state", required=True)
    stop_replay.add_argument("--json", action="store_true")
    scenario = http_commands.add_parser("scenario", help="Run explicit approved requests and state expectations in sequence.")
    scenario.add_argument("scenario")
    scenario.add_argument("--session", required=True)
    scenario.add_argument("--state", required=True)
    _add_output(scenario)
    scenario.add_argument("--json", action="store_true")

    api = commands.add_parser("api", help="Inspect prepared API schemas and research changes.")
    api_commands = api.add_subparsers(dest="api_command", required=True)
    inventory = api_commands.add_parser("inventory", help="Inventory OpenAPI operations and effective authentication declarations.")
    inventory.add_argument("schema")
    inventory.add_argument("--project", required=True)
    _add_output(inventory)
    inventory.add_argument("--json", action="store_true")
    api_diff = api_commands.add_parser("diff", help="Compare prepared OpenAPI schemas using pinned oasdiff and authentication semantics.")
    api_diff.add_argument("before")
    api_diff.add_argument("after")
    api_diff.add_argument("--project", required=True)
    api_diff.add_argument("--tool-path")
    _add_output(api_diff)
    api_diff.add_argument("--json", action="store_true")
    api_coverage = api_commands.add_parser("coverage", help="Compare observed HTTP operations with a prepared schema.")
    api_coverage.add_argument("schema")
    api_coverage.add_argument("--evidence", action="append", required=True)
    api_coverage.add_argument("--matrix", help="Explicit identity/object access expectations.")
    api_coverage.add_argument("--scenario", action="append", default=[], help="Explicit scenario plan for step and transition coverage.")
    api_coverage.add_argument("--project", required=True)
    _add_output(api_coverage)
    api_coverage.add_argument("--json", action="store_true")
    owned_test = api_commands.add_parser("test-owned", help="Run pinned Schemathesis and explicit lifecycle checks on an owned disposable mini-API.")
    owned_test.add_argument("--vulnerable", action="store_true")
    _add_output(owned_test)
    owned_test.add_argument("--json", action="store_true")

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

    for name, description in (("opengrep", "Analyze Python/JavaScript with authored security rules."),
                              ("secrets", "Detect potential secrets with pinned Betterleaks; no live credential checks.")):
        native = scan_commands.add_parser(name, help=description)
        native.add_argument("source")
        native.add_argument("--tool-path", help="Exact pinned native executable; version and companion hashes must match.")
        native.add_argument("--max-entries", type=int, default=20_000)
        native.add_argument("--max-source-files", type=int, default=1_000)
        native.add_argument("--max-file-bytes", type=int, default=1024 * 1024)
        native.add_argument("--max-total-bytes", type=int, default=16 * 1024 * 1024)
        native.add_argument("--max-observations", type=int, default=1_000)
        native.add_argument("--timeout-seconds", type=float, default=30.0)
        native.add_argument("--json", action="store_true")
        _add_output(native)

    session = commands.add_parser(
        "session", help="Validate a local design contract for future network work."
    )
    session_commands = session.add_subparsers(dest="session_command", required=True)
    validate_session = session_commands.add_parser(
        "validate", help="Validate one session contract without network access."
    )
    validate_session.add_argument("document")
    validate_session.add_argument(
        "--evaluation-time",
        help="Offline evaluation clock; future network execution must use its own clock.",
    )
    _add_output(validate_session)
    validate_session.add_argument(
        "--json", action="store_true", help="Emit deterministic JSON."
    )

    release = commands.add_parser("release", help="Run technical release checks.")
    release_commands = release.add_subparsers(dest="release_command", required=True)
    audit = release_commands.add_parser(
        "audit", help="Audit a clean tracked export and built distributions."
    )
    audit.add_argument("--root", default=".")
    _add_output(audit)
    audit.add_argument("--json", action="store_true", help="Emit deterministic JSON.")

    network = commands.add_parser(
        "network", help="Execute the owned-loopback network profile only."
    )
    network_commands = network.add_subparsers(dest="network_command", required=True)
    observe_loopback = network_commands.add_parser(
        "observe-loopback", help="Make one bounded GET to exact IPv4 loopback."
    )
    observe_loopback.add_argument("session")
    observe_loopback.add_argument("--state", required=True)
    observe_loopback.add_argument("--path", required=True)
    _add_output(observe_loopback)
    observe_loopback.add_argument(
        "--json", action="store_true", help="Emit deterministic JSON."
    )
    stop_loopback = network_commands.add_parser(
        "stop", help="Apply the monotonic user stop to an owned-loopback session."
    )
    stop_loopback.add_argument("session")
    stop_loopback.add_argument("--state", required=True)
    stop_loopback.add_argument(
        "--json", action="store_true", help="Emit deterministic JSON."
    )
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
        if args.command == "tools":
            _emit(toolkit_status(), args.json)
            return 0
        if args.command == "init":
            _emit(initialize_workspace(args.directory, args.title), args.json)
            return 0
        if args.command == "report":
            _emit(export_markdown(args.result, args.output, case_path=args.case, review_path=args.review), args.json)
            return 0
        if args.command == "packet":
            if args.packet_command == "init":
                _emit(initialize_packet(args.output, args.project, args.title, args.evidence), args.json)
            elif args.packet_command == "export":
                _emit(export_packet(args.manifest, args.output, args.preset), args.json)
            else:
                _emit_analysis(check_packet(args.manifest), args)
            return 0
        if args.command == "candidate":
            if args.candidate_command == "init":
                _emit(initialize_candidate(args.directory, args.id, args.project, args.title), args.json)
            elif args.candidate_command == "record":
                _emit(record_decision(args.directory, args.evidence, args.select, args.decision, args.note, args.retest_of, args.related, args.relation), args.json)
            else:
                _emit_analysis(candidate_history(args.directory), args)
            return 0
        if args.command == "http":
            if args.http_command == "prepare":
                _emit(prepare_capture(args.capture, args.output_dir, args.project, index=args.index, identity=args.identity,
                                      object_id=args.object, operation=args.operation, format_name=args.format), args.json)
                return 0
            if args.http_command == "bind":
                _emit(bind_request(args.plan, args.output_dir), args.json)
                return 0
            if args.http_command == "preview":
                _emit(request_preview(args.request), args.json)
                return 0
            if args.http_command == "stop":
                _emit(stop_session(args.session, args.state), args.json)
                return 0
            if args.http_command == "import":
                result = import_capture(args.capture, args.project, format_name=args.format, identity=args.identity,
                    object_id=args.object, operation=args.operation, selected=args.select)
            elif args.http_command == "compare":
                result = compare_http(args.before, args.after, args.before_index, args.after_index, args.ignore)
            elif args.http_command == "replay":
                result = replay(args.session, args.request, args.identity, args.state)
            elif args.http_command == "scenario":
                result = run_scenario(args.scenario, args.session, args.state)
            else:
                result = assess_access(args.matrix, args.evidence)
            _emit_analysis(result, args)
            return 0
        if args.command == "api":
            if args.api_command == "inventory":
                result = inventory_schema(args.schema, args.project)
            elif args.api_command == "diff":
                result = compare_schema(args.before, args.after, args.project, args.tool_path)
            elif args.api_command == "test-owned":
                result = test_owned_api(args.vulnerable)
            else:
                result = coverage(args.schema, args.evidence, args.project, args.matrix, args.scenario)
            _emit_analysis(result, args)
            return 0
        if args.command == "import":
            _emit_analysis(import_report(args.report, args.format, args.source_root), args)
            return 0
        if args.command == "compare":
            _emit_analysis(compare_results(args.before, args.after), args)
            return 0
        if args.command == "scan" and args.scan_command in {"opengrep", "secrets"}:
            limits = ScannerLimits(max_entries=args.max_entries, max_source_files=args.max_source_files,
                max_file_bytes=args.max_file_bytes, max_total_bytes=args.max_total_bytes,
                max_observations=args.max_observations, timeout_seconds=args.timeout_seconds)
            tool = "opengrep" if args.scan_command == "opengrep" else "betterleaks"
            _emit_analysis(scan_native(args.source, tool, args.tool_path, limits), args)
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
        if args.command == "session" and args.session_command == "validate":
            _emit_analysis(
                load_and_validate_network_session(
                    args.document,
                    parse_evaluation_time(args.evaluation_time),
                ),
                args,
            )
            return 0
        if args.command == "release" and args.release_command == "audit":
            _emit_analysis(audit_release(args.root), args)
            return 0
        if args.command == "network":
            if args.network_command == "observe-loopback":
                _emit_analysis(
                    execute_loopback_observation(
                        args.session,
                        args.state,
                        args.path,
                    ),
                    args,
                )
                return 0
            if args.network_command == "stop":
                _emit(
                    stop_loopback_session(args.session, args.state),
                    args.json,
                )
                return 0
    except (
        DiffError,
        DependencyError,
        NetworkExecutionError,
        NetworkSessionError,
        RecordError,
        ReleaseAuditError,
        RunnerError,
        ScannerError,
        OSError,
    ) as exc:
        failure = {
            "schemaVersion": "whitehat-error-v1",
            "ok": False,
            "error": {"code": getattr(exc, "error_code", "invalid-input"),
                      "message": "filesystem operation failed; check input/output paths and permissions" if isinstance(exc, OSError) else str(exc)},
        }
        _emit(failure, bool(getattr(args, "json", False)))
        return getattr(exc, "exit_code", 3)
    raise AssertionError("unhandled command")
