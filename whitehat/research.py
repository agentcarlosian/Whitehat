"""Portable research workspaces and explicit Markdown export."""
from __future__ import annotations

import hashlib
import html
import os
from pathlib import Path
from typing import Any

from .records import RecordError, _bounded_text, write_json_document
from .reports import canonical, checked_research_result, parse_json, read_bytes, relative_path
from .source_context import context_lines


CASE_SCHEMA = "whitehat-research-case-v1"
CASE_FIELDS = {"schemaVersion", "title", "target", "versions", "hypothesis", "boundary",
               "reproduction", "negativeControl", "duplicateAssessment", "nextAction", "evidenceReferences"}
NOTE_FIELDS = ("target", "versions", "hypothesis", "boundary", "negativeControl", "duplicateAssessment", "nextAction")
NOTE_LABELS = {"target": "Target", "versions": "Versions", "hypothesis": "Hypothesis",
               "boundary": "Boundary", "negativeControl": "Negative control",
               "duplicateAssessment": "Duplicate assessment", "nextAction": "Next action"}
CONTEXT_LABELS = {"package": "Package", "ecosystem": "Ecosystem", "version": "Reported version",
                  "aliases": "Advisory aliases", "fixedVersionsReported": "Fixed versions reported",
                  "matchStatus": "Match status", "reachability": "Reachability", "withdrawn": "Advisory withdrawn"}


def case_template(title: str) -> dict[str, Any]:
    return {
        "schemaVersion": CASE_SCHEMA,
        "title": _bounded_text(title, "case title", 200),
        "target": "Specify the exact project, asset, or owned fixture.",
        "versions": "Record the source commit and affected/fixed versions under review.",
        "hypothesis": "Describe the behavior to investigate and what would reject the hypothesis.",
        "boundary": "Identify the actor, controlled input, protected object, and expected permission.",
        "reproduction": {"status": "not-attempted", "notes": "No reproduction evidence recorded."},
        "negativeControl": "Record a comparison that should not produce the suspected behavior.",
        "duplicateAssessment": "Check relevant advisories, fixes, and earlier reports.",
        "nextAction": "Inspect an observation and record the evidence needed for a decision.",
        "evidenceReferences": [],
    }


def validate_case(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != CASE_FIELDS or value.get("schemaVersion") != CASE_SCHEMA:
        raise RecordError("case fields or schema version are invalid")
    result = {"schemaVersion": CASE_SCHEMA, "title": _bounded_text(value["title"], "title", 200)}
    for field in NOTE_FIELDS:
        result[field] = _bounded_text(value[field], field, 4000)
    reproduction = value["reproduction"]
    if (not isinstance(reproduction, dict) or set(reproduction) != {"status", "notes"}
            or reproduction["status"] not in {"not-attempted", "reproduced", "not-reproduced", "inconclusive"}):
        raise RecordError("reproduction needs a supported status and notes")
    result["reproduction"] = {"status": reproduction["status"], "notes": _bounded_text(reproduction["notes"], "reproduction notes", 4000)}
    references = value["evidenceReferences"]
    if not isinstance(references, list) or len(references) > 50:
        raise RecordError("evidenceReferences must be an array of at most 50 relative paths")
    result["evidenceReferences"] = [relative_path(v) for v in references]
    return result


def initialize_workspace(path_value: str, title: str) -> dict[str, Any]:
    case = case_template(title)
    destination = Path(path_value)
    if destination.exists() or destination.is_symlink():
        raise RecordError("workspace already exists; choose a new directory")
    try:
        parent = destination.parent.resolve(strict=True)
        if not parent.is_dir():
            raise RecordError("workspace parent must be a directory")
        root = parent / destination.name
        root.mkdir()
        for name in ("inputs", "results", "notes", "exports"):
            (root / name).mkdir()
        write_json_document(case, root / "case.json")
        (root / ".gitignore").write_text("*\n!.gitignore\n", encoding="utf-8")
        (root / "README.md").write_text(
            "# Research workspace\n\nEdit case.json as evidence develops. Keep source inputs in inputs/,\n"
            "normalized tool output in results/, notes in notes/, and Markdown in exports/.\n"
            "Paths are portable. Evidence references are labels; the exporter never follows them.\n"
            "Review all records before sharing. A case note does not authorize target activity.\n", encoding="utf-8")
    except OSError as exc:
        raise RecordError("cannot initialize workspace; a partial directory may remain") from exc
    return {"schemaVersion": "whitehat-workspace-v1", "ok": True, "title": case["title"],
            "directories": ["inputs", "results", "notes", "exports"], "case": "case.json",
            "effects": {"filesystemWrite": True, "network": False}}


def _markdown(value: Any) -> str:
    # Tool/analyst text is rendered literally, never as links, HTML, or images.
    escaped = html.escape(str(value), quote=False)
    for character in "\\`*_{}[]()#+-.!|":
        escaped = escaped.replace(character, "\\" + character)
    return escaped.replace("\r", "").replace("\n", "  \n")


def _review_for_result(path: str, result: dict[str, Any]) -> dict[str, Any]:
    review = parse_json(read_bytes(Path(path), 64 * 1024))
    if not isinstance(review, dict) or review.get("schemaVersion") != "whitehat-local-review-v1":
        raise RecordError("unsupported review record")
    payload = dict(review)
    digest = payload.pop("reviewSha256", None)
    if hashlib.sha256(canonical(payload)).hexdigest() != digest:
        raise RecordError("review hash mismatch")
    if review.get("reviewOf") != {"schemaVersion": result["schemaVersion"], "resultSha256": result["resultSha256"]}:
        raise RecordError("review is linked to a different result")
    if review.get("decision") not in {"accepted", "dismissed", "needs-work"}:
        raise RecordError("invalid review decision")
    _bounded_text(review.get("note"), "review note", 4000)
    return review


def export_markdown(result_path: str, output_path: str, *, case_path: str | None = None,
                    review_path: str | None = None) -> dict[str, Any]:
    result = checked_research_result(result_path)
    case = validate_case(parse_json(read_bytes(Path(case_path), 64 * 1024))) if case_path else case_template("Security research review")
    review = _review_for_result(review_path, result) if review_path else None
    lines = [f"# {_markdown(case['title'])}", "", "Research review packet. Tool output and analyst statements require independent verification.", "",
             f"Result SHA-256: `{result['resultSha256']}`", "",
             f"Observations: {len(result['observations'])}", ""]
    for field in NOTE_FIELDS:
        lines.extend([f"## {NOTE_LABELS[field]}", "", _markdown(case[field]), ""])
    lines.extend(["## Reproduction", "", f"Analyst-reported status: {_markdown(case['reproduction']['status'])}", "", _markdown(case["reproduction"]["notes"]), ""])
    if review:
        lines.extend(["## Review decision", "", _markdown(review["decision"]), "", _markdown(review["note"]), ""])
    lines.extend(["## Tool observations", ""])
    for index, item in enumerate(result["observations"], 1):
        location = item.get("path") or item.get("endpoint") or "No location reported"
        if item.get("line") is not None:
            location += f":{item['line']}"
        lines.extend([f"### {index}. {_markdown(item.get('ruleId', 'Observation'))}", "",
                      f"Tool: {_markdown(item.get('tool', 'unknown'))}", "",
                      f"Location: {_markdown(location)}", "",
                      _markdown(item.get("explanation", "Inspect the underlying evidence.")), "",
                      f"Tool-reported severity: {_markdown(item.get('severityReported') or 'unspecified')}", ""])
        if item.get("context"):
            for key, value in sorted(item["context"].items()):
                if isinstance(value, list):
                    value = ", ".join(str(v) for v in value) or "None reported"
                lines.append(f"- {_markdown(CONTEXT_LABELS.get(key, key))}: {_markdown(value)}")
            lines.append("")
        if "sourceContext" in item:
            lines.extend("- " + _markdown(line) for line in context_lines(item["sourceContext"]))
            lines.append("")
    lines.extend(["## Evidence references", "", "References are not opened or embedded by this exporter.", ""])
    lines.extend(f"- {_markdown(reference)}" for reference in case["evidenceReferences"])
    lines.extend(["", "## Provenance", "", "The result JSON contains the complete machine-readable provenance and process receipt.", ""])
    for key, label in (("kind", "Origin"), ("tool", "Tool"), ("toolVersion", "Tool version"),
                       ("format", "Imported format"), ("reportSha256", "Imported report SHA-256"),
                       ("sourceTreeSha256", "Source tree SHA-256"), ("configSha256", "Rules/config SHA-256"),
                       ("analysisProfile", "Analysis profile"), ("taintScope", "Taint scope")):
        if key in result["provenance"]:
            lines.append(f"- {label}: {_markdown(result['provenance'][key])}")
    lines.extend(["", "This packet records research. It does not establish authorization, exploitability, impact, eligibility, or a validated finding.", ""])
    content = "\n".join(lines).encode("utf-8")
    if len(content) > 16 * 1024 * 1024:
        raise RecordError("Markdown export size limit exceeded")
    output = Path(output_path)
    if output.exists() or output.is_symlink():
        raise RecordError("output already exists")
    try:
        parent = output.parent.resolve(strict=True)
        with (parent / output.name).open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise RecordError("cannot write Markdown export") from exc
    return {"schemaVersion": "whitehat-markdown-export-v1", "ok": True,
            "resultSha256": result["resultSha256"], "markdownSha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content), "effects": {"filesystemWrite": True, "network": False}}
