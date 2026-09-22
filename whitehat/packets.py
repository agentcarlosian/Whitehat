"""Explicit evidence-linked Markdown packets with informational readiness."""

from __future__ import annotations

import hashlib
from pathlib import Path

from .evidence_links import (
    contained_path,
    evidence_result,
    fields,
    project_of,
    selectable,
    sha256,
)
from .http_evidence import HTTP_SCHEMA, digest, label
from .records import RecordError, write_json_document
from .reports import CLAIMS, ReportError, parse_json, read_bytes, seal
from .research import _markdown
from .source_context import context_lines

MANIFEST_SCHEMA = "whitehat-report-manifest-v1"
TEXT_FIELDS = ("title", "prerequisites", "impact", "limitations", "negativeControl")


def note(value, name: str, maximum: int = 4000) -> str:
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or any(ord(c) < 32 and c not in "\n\r\t" for c in value)
    ):
        raise ReportError(f"invalid {name} text")
    return value


def initialize_packet(
    output: str, project: str, title: str, evidence_paths: list[str]
) -> dict:
    if not 1 <= len(evidence_paths) <= 20:
        raise ReportError("packet requires 1-20 explicitly selected evidence files")
    # Compare the caller's path spellings before resolving the common root.
    # macOS /var is an alias for /private/var. Resolving only the root would
    # incorrectly classify its own children as outside. contained_path then
    # resolves that root and rejects links/escapes below it.
    root = Path(output).parent.absolute()
    references = []
    for index, value in enumerate(evidence_paths):
        try:
            relative = Path(value).absolute().relative_to(root).as_posix()
        except ValueError as exc:
            raise ReportError(
                "packet evidence must be beneath the manifest directory"
            ) from exc
        path = contained_path(root, relative)
        result = evidence_result(path)
        if project_of(result) not in (None, project):
            raise ReportError("packet evidence project mismatch")
        references.append(
            {
                "id": f"evidence-{index + 1}",
                "path": relative,
                "resultSha256": result["resultSha256"],
                "select": list(selectable(result)),
            }
        )
    manifest = {
        "schemaVersion": MANIFEST_SCHEMA,
        "projectId": label(project, "project"),
        "title": note(title, "title", 200),
        "prerequisites": "",
        "impact": "",
        "limitations": "",
        "negativeControl": "",
        "evidence": references,
        "steps": [
            {
                "id": "step-1",
                "action": "",
                "expected": "",
                "actual": "",
                "evidence": [r["id"] for r in references],
            }
        ],
    }
    write_json_document(manifest, output)
    return seal(
        {
            "schemaVersion": "whitehat-packet-init-v1",
            "ok": True,
            "manifestSha256": digest(manifest),
            "evidenceCount": len(references),
            "effects": {"network": False, "filesystemWrite": True},
        }
    )


def _load_packet(path: str) -> tuple[dict, dict, list[dict]]:
    source = Path(path)
    manifest = fields(
        parse_json(read_bytes(source, 256 * 1024)),
        {"schemaVersion", "projectId", *TEXT_FIELDS, "evidence", "steps"},
        "report manifest",
    )
    if manifest["schemaVersion"] != MANIFEST_SCHEMA:
        raise ReportError("unsupported report manifest")
    label(manifest["projectId"], "project")
    for name in TEXT_FIELDS:
        note(manifest[name], name, 200 if name == "title" else 4000)
    references, steps = manifest["evidence"], manifest["steps"]
    if (
        not isinstance(references, list)
        or len(references) > 20
        or not isinstance(steps, list)
        or len(steps) > 50
    ):
        raise ReportError("packet exceeds 20 evidence files or 50 steps")
    issues = [
        {"code": "missing-content", "item": name}
        for name in TEXT_FIELDS
        if not manifest[name].strip()
    ]
    loaded, seen = {}, set()
    total_bytes = 0
    for ref in references:
        fields(ref, {"id", "path", "resultSha256", "select"}, "evidence reference")
        name = label(ref["id"], "reference")
        if name in seen:
            raise ReportError("duplicate packet evidence ID")
        seen.add(name)
        sha256(ref["resultSha256"])
        selected = ref["select"]
        if (
            not isinstance(selected, list)
            or len(selected) > 1000
            or any(not isinstance(v, str) for v in selected)
            or len(selected) != len(set(selected))
        ):
            raise ReportError("invalid packet selection")
        for item in selected:
            sha256(item)
        linked_path = contained_path(source.parent, ref["path"])
        try:
            total_bytes += linked_path.stat().st_size
            if total_bytes > 32 * 1024 * 1024:
                raise ReportError("packet input total exceeds 32 MiB")
            result = evidence_result(linked_path)
        except (OSError, RecordError, ReportError):
            issues.append({"code": "unavailable-or-invalid-evidence", "item": name})
            continue
        if result["resultSha256"] != ref["resultSha256"]:
            issues.append({"code": "evidence-hash-mismatch", "item": name})
            continue
        if project_of(result) not in (None, manifest["projectId"]):
            raise ReportError("packet evidence project mismatch")
        if set(selected) - selectable(result).keys():
            raise ReportError("packet selects unknown observations/exchanges")
        if selectable(result) and not selected:
            issues.append({"code": "no-selected-observations", "item": name})
        loaded[name] = result
    step_ids = set()
    for step in steps:
        fields(step, {"id", "action", "expected", "actual", "evidence"}, "report step")
        name = label(step["id"], "step")
        if name in step_ids:
            raise ReportError("duplicate report step ID")
        step_ids.add(name)
        for key in ("action", "expected", "actual"):
            if not note(step[key], key).strip():
                issues.append({"code": "missing-content", "item": name + "." + key})
        links = step["evidence"]
        if (
            not isinstance(links, list)
            or len(links) > 20
            or any(not isinstance(v, str) for v in links)
            or len(links) != len(set(links))
            or set(links) - seen
        ):
            raise ReportError("report step references unknown/duplicate evidence IDs")
        if not links:
            issues.append({"code": "step-without-evidence", "item": name})
    if not steps or not references:
        issues.append({"code": "missing-steps-or-evidence", "item": "manifest"})
    # Linked result/exchange hashes must actually be supplied, not merely printed.
    result_hashes = {r["resultSha256"] for r in loaded.values()}
    exchange_hashes = {
        h
        for ref in references
        if ref["id"] in loaded and loaded[ref["id"]]["schemaVersion"] == HTTP_SCHEMA
        for h in ref["select"]
    }
    for name, result in loaded.items():
        provenance = result.get("provenance", {})
        if result["schemaVersion"] == "whitehat-http-comparison-v1":
            for side in ("before", "after"):
                if result[side + "EvidenceSha256"] not in exchange_hashes:
                    issues.append(
                        {"code": "missing-linked-exchange", "item": name + "." + side}
                    )
        if provenance.get("kind") == "access-assessment":
            for value in provenance.get("evidenceResults", []):
                if value not in result_hashes:
                    issues.append({"code": "missing-assessment-evidence", "item": name})
            for evaluation in provenance.get("evaluations", []):
                if any(
                    h not in exchange_hashes
                    for h in evaluation.get("evidenceSha256", [])
                ):
                    issues.append(
                        {"code": "unselected-assessment-exchange", "item": name}
                    )
        if provenance.get("kind") == "relational-assessment":
            for hash_value in provenance.get("evidenceResults", []):
                if hash_value not in result_hashes:
                    issues.append({"code": "missing-relational-evidence", "item": name})
        if provenance.get("kind") == "fuzz-run":
            if provenance["httpEvidence"]["resultSha256"] not in result_hashes:
                issues.append({"code": "missing-fuzz-http-evidence", "item": name})
            if not provenance["complete"]:
                issues.append({"code": "incomplete-fuzz-run", "item": name})
            if any(c["cleanup"] == "incomplete" for c in provenance["cases"]):
                issues.append({"code": "incomplete-fuzz-reset", "item": name})
        if provenance.get("profile") == "explicit-scenario":
            if provenance.get("executedSteps") != provenance.get("plannedSteps"):
                issues.append({"code": "incomplete-scenario", "item": name})
            if any(
                e.get("outcome") != "consistent"
                for e in provenance.get("evaluations", [])
            ):
                issues.append({"code": "scenario-expectation-mismatch", "item": name})
    return manifest, loaded, issues


def check_packet(path: str) -> dict:
    manifest, loaded, issues = _load_packet(path)
    return seal(
        {
            "schemaVersion": "whitehat-packet-check-v1",
            "ok": True,
            "projectId": manifest["projectId"],
            "manifestSha256": digest(manifest),
            "contentComplete": not issues,
            "issues": issues,
            "verifiedEvidence": sorted(loaded),
            "claims": dict(CLAIMS),
            "effects": {"network": False},
        }
    )


def _line(name: str, value) -> str:
    return f"{name}: {_markdown(value)}  "


def _render_evidence(result: dict, selected: list[str]) -> list[str]:
    lines = [_line("Result SHA-256", result["resultSha256"]), ""]
    schema = result["schemaVersion"]
    if schema == HTTP_SCHEMA:
        for hash_value in selected:
            entry = selectable(result)[hash_value]
            context, response = entry["context"], entry["response"]
            lines.extend(
                [
                    _line("Request", context["method"] + " " + context["endpoint"]),
                    _line(
                        "Identity / object / operation",
                        " / ".join(
                            context[k]
                            for k in ("identityId", "objectId", "operationId")
                        ),
                    ),
                    _line("Response status", response["status"]),
                    _line("Body captured", response["bodyCaptured"]),
                    _line("Evidence SHA-256", hash_value),
                ]
            )
            for pointer, value in sorted(response["json"]["values"].items()):
                lines.append(_line("Selected " + _markdown(pointer), value))
            lines.append("")
        provenance = result["provenance"]
        lines.append(_line("Evidence origin", provenance.get("kind", "unknown")))
        lines.append("Identity labels are operator assertions.")
        for entry in provenance.get("incompleteEntries", []):
            lines.append(_line("Incomplete capture entry", entry.get("entryIndex")))
        if provenance.get("profile") == "explicit-scenario":
            lines.extend(
                [
                    _line("Planned steps", provenance.get("plannedSteps")),
                    _line("Executed steps", provenance.get("executedSteps")),
                    _line("Scenario SHA-256", provenance.get("scenarioSha256")),
                ]
            )
            for evaluation in provenance.get("evaluations", []):
                lines.append(
                    _line(
                        "Step " + _markdown(evaluation.get("stepId")),
                        evaluation.get("outcome"),
                    )
                )
    elif schema == "whitehat-http-comparison-v1":
        for side in ("before", "after"):
            lines.extend(
                [
                    _line(
                        side.title() + " context",
                        " / ".join(
                            str(result["contexts"][side].get(k, ""))
                            for k in ("method", "endpoint", "identityId", "objectId")
                        ),
                    ),
                    _line(side.title() + " status", result["status"][side]),
                    _line(
                        side.title() + " evidence SHA-256",
                        result[side + "EvidenceSha256"],
                    ),
                ]
            )
        lines.append(
            _line("Ignored pointers", ", ".join(result.get("ignoredPointers", [])))
        )
        for name in ("shapeChanges", "valueChanges"):
            for change in result[name]:
                lines.append(
                    _line(
                        name + " " + _markdown(change["pointer"]),
                        f"{change['before'] if change['beforePresent'] else '[absent]'} -> {change['after'] if change['afterPresent'] else '[absent]'}",
                    )
                )
    else:
        for hash_value in selected:
            item = selectable(result)[hash_value]
            lines.extend(
                [
                    _line("Observation", item["ruleId"]),
                    _line(
                        "Location", item["path"] or item["endpoint"] or "unspecified"
                    ),
                    _line(
                        "Tool-reported severity",
                        item["severityReported"] or "unspecified",
                    ),
                    _line("Explanation", item["explanation"]),
                    _line("Observation fingerprint", hash_value),
                    "",
                ]
            )
            if "sourceContext" in item:
                lines.extend("- " + _markdown(line) for line in context_lines(item["sourceContext"]))
                lines.append("")
        provenance = result["provenance"]
        if provenance.get("kind") == "relational-assessment":
            lines.append(_line("Relational plan SHA-256", provenance.get("planSha256")))
            lines.append("Evidence ordering is operator asserted.")
            for evaluation in provenance["evaluations"]:
                lines.append(
                    _line(
                        "Assertion " + _markdown(evaluation["assertionId"]),
                        evaluation["outcome"],
                    )
                )
                lines.extend(
                    _line("Linked exchange SHA-256", value)
                    for value in evaluation["evidenceSha256"]
                )
        if provenance.get("kind") == "fuzz-run":
            lines.extend(
                [
                    _line("Fuzz batch SHA-256", provenance["batchSha256"]),
                    _line("Batch complete", provenance["complete"]),
                    _line(
                        "HTTP evidence SHA-256",
                        provenance["httpEvidence"]["resultSha256"],
                    ),
                ]
            )
            for case in provenance["cases"]:
                lines.extend(
                    [
                        _line("Case " + _markdown(case["caseId"]), case["outcome"]),
                        _line("Reset", case["cleanup"]),
                        _line("Failure signals", ", ".join(case["failureKeys"])),
                    ]
                )
        if provenance.get("kind") == "access-assessment":
            lines.extend(
                [
                    _line("Access matrix SHA-256", provenance.get("matrixSha256")),
                    "Identity bindings are operator assertions.",
                ]
            )
            for evaluation in provenance.get("evaluations", []):
                lines.append(
                    _line(
                        "Access row " + _markdown(evaluation.get("rowId")),
                        evaluation.get("outcome"),
                    )
                )
                lines.extend(
                    _line("Linked exchange SHA-256", v)
                    for v in evaluation.get("evidenceSha256", [])
                )
    return lines


def export_packet(path: str, output: str, preset: str = "generic") -> dict:
    if preset not in {"generic", "hackerone", "bugcrowd"}:
        raise ReportError("unsupported packet preset")
    manifest, loaded, issues = _load_packet(path)
    lines = [
        "# " + _markdown(manifest["title"] or "Research draft"),
        "",
        "Draft research packet; analyst statements require verification.",
        "",
        _line("Project", manifest["projectId"]),
        _line("Manifest SHA-256", digest(manifest)),
        "",
        "## Content readiness",
        "",
    ]
    lines.extend(
        ["Required content is present; this does not validate the finding."]
        if not issues
        else [_line(issue["code"], issue["item"]) for issue in issues]
    )
    for field, heading in (
        ("prerequisites", "Prerequisites"),
        ("negativeControl", "Negative control"),
        ("impact", "Demonstrated impact"),
        ("limitations", "Limitations"),
    ):
        lines.extend(
            ["", "## " + heading, "", _markdown(manifest[field] or "Not recorded.")]
        )
    heading = (
        "Walkthrough and proof of concept"
        if preset == "bugcrowd"
        else "Steps to reproduce"
    )
    lines.extend(["", "## " + heading, ""])
    for index, step in enumerate(manifest["steps"], 1):
        lines.extend(
            [
                f"### {index}. {_markdown(step['id'])}",
                "",
                _line("Action", step["action"] or "Not recorded."),
                _line("Expected", step["expected"] or "Not recorded."),
                _line("Observed", step["actual"] or "Not recorded."),
                _line("Evidence references", ", ".join(step["evidence"])),
                "",
            ]
        )
    lines.extend(["## Selected evidence", ""])
    for ref in manifest["evidence"]:
        lines.extend(["### " + _markdown(ref["id"]), ""])
        if ref["id"] not in loaded:
            lines.extend(
                ["Unavailable or changed evidence; content was not embedded.", ""]
            )
        else:
            lines.extend(_render_evidence(loaded[ref["id"]], ref["select"]) + [""])
    lines.extend(
        [
            "Hashes verify consistency with supplied artifacts, not origin, authority, impact, or finding validity.",
            "Only selected normalized evidence is embedded. Raw requests and credentials are not packet inputs.",
            "",
        ]
    )
    content = "\n".join(lines).encode("utf-8")
    if len(content) > 16 * 1024 * 1024:
        raise ReportError("packet output exceeds 16 MiB")
    destination = Path(output)
    if destination.exists() or destination.is_symlink():
        raise RecordError("output already exists")
    with (destination.parent.resolve(strict=True) / destination.name).open(
        "xb"
    ) as stream:
        stream.write(content)
    return seal(
        {
            "schemaVersion": "whitehat-packet-export-v1",
            "ok": True,
            "manifestSha256": digest(manifest),
            "markdownSha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content),
            "contentComplete": not issues,
            "issues": issues,
            "effects": {"network": False, "filesystemWrite": True},
        }
    )
