"""Portable per-candidate decisions and conservative retest histories."""

from __future__ import annotations

from pathlib import Path

from .evidence_links import evidence_result, fields, project_of, selectable, sha256
from .http_evidence import HTTP_SCHEMA, digest, label
from .packets import note
from .records import RecordError, _review_timestamp, write_json_document
from .reports import CLAIMS, ReportError, parse_json, read_bytes, seal

DECISIONS = {
    "open",
    "needs-work",
    "dismissed",
    "reproduced",
    "not-reproduced",
    "inconclusive",
    "not-comparable",
}
RETESTS = {"reproduced", "not-reproduced", "inconclusive", "not-comparable"}


def initialize_candidate(
    directory: str, candidate_id: str, project: str, title: str
) -> dict:
    root = Path(directory)
    if root.exists() or root.is_symlink():
        raise RecordError("candidate directory already exists")
    document = {
        "schemaVersion": "whitehat-candidate-v1",
        "candidateId": label(candidate_id, "candidate"),
        "projectId": label(project, "project"),
        "title": note(title, "title", 200),
    }
    root.parent.resolve(strict=True)
    root.mkdir()
    (root / "decisions").mkdir()
    write_json_document(document, root / "candidate.json")
    return seal(
        {
            "schemaVersion": "whitehat-candidate-init-v1",
            "ok": True,
            **{k: document[k] for k in ("candidateId", "projectId", "title")},
            "effects": {"network": False, "filesystemWrite": True},
        }
    )


def _history(directory: str) -> tuple[dict, list[dict]]:
    root = Path(directory)
    if root.is_symlink() or (hasattr(root, "is_junction") and root.is_junction()):
        raise ReportError("candidate directory must not be a link")
    from .evidence_links import contained_path

    candidate = fields(
        parse_json(read_bytes(contained_path(root, "candidate.json"), 16 * 1024)),
        {"schemaVersion", "candidateId", "projectId", "title"},
        "candidate",
    )
    if candidate["schemaVersion"] != "whitehat-candidate-v1":
        raise ReportError("unsupported candidate")
    label(candidate["candidateId"], "candidate")
    label(candidate["projectId"], "project")
    note(candidate["title"], "title", 200)
    decision_root = contained_path(root, "decisions")
    paths = sorted(decision_root.iterdir())
    if len(paths) > 1000:
        raise ReportError("candidate history exceeds 1000 records")
    records, previous = [], None
    for sequence, path in enumerate(paths, 1):
        if path.name != f"{sequence:06d}.json":
            raise ReportError("candidate history has a gap or unexpected file")
        path = contained_path(root, "decisions/" + path.name)
        value = parse_json(read_bytes(path, 256 * 1024))
        fields(
            value,
            {
                "schemaVersion",
                "ok",
                "candidateId",
                "projectId",
                "candidateSha256",
                "sequence",
                "previousSha256",
                "createdAt",
                "decision",
                "requestedDecision",
                "note",
                "evidence",
                "comparisonKey",
                "comparisonSuitable",
                "retestOf",
                "relationship",
                "claims",
                "effects",
                "resultSha256",
            },
            "candidate decision",
        )
        payload = {k: v for k, v in value.items() if k != "resultSha256"}
        if (
            digest(payload) != sha256(value["resultSha256"])
            or value["previousSha256"] != previous
            or type(value["sequence"]) is not int
            or value["sequence"] != sequence
        ):
            raise ReportError("candidate history hash/sequence mismatch")
        if (
            value["candidateSha256"] != digest(candidate)
            or value["candidateId"] != candidate["candidateId"]
            or value["projectId"] != candidate["projectId"]
        ):
            raise ReportError("candidate history belongs to a different candidate")
        if (
            value["schemaVersion"] != "whitehat-candidate-decision-v1"
            or value["claims"] != CLAIMS
            or not isinstance(value["decision"], str)
            or value["decision"] not in DECISIONS
        ):
            raise ReportError("invalid candidate decision")
        if (
            not isinstance(value["requestedDecision"], str)
            or value["requestedDecision"] not in DECISIONS
            or value["ok"] is not True
        ):
            raise ReportError("invalid requested candidate decision")
        note(value["note"], "decision note")
        from .http_replay import _time

        _time(value["createdAt"])
        sha256(value["comparisonKey"])
        fields(
            value["evidence"],
            {"schemaVersion", "resultSha256", "selected"},
            "candidate evidence",
        )
        sha256(value["evidence"]["resultSha256"])
        selected = value["evidence"]["selected"]
        if not isinstance(selected, list) or len(selected) > 500:
            raise ReportError("invalid candidate evidence selection")
        for item in selected:
            sha256(item)
        if (
            value["comparisonSuitable"] is not None
            and type(value["comparisonSuitable"]) is not bool
        ):
            raise ReportError("invalid retest suitability")
        retest_of = value["retestOf"]
        if retest_of is not None and (
            type(retest_of) is not int or not 1 <= retest_of < sequence
        ):
            raise ReportError("invalid retest predecessor")
        if value["relationship"] is not None:
            relation = fields(
                value["relationship"],
                {"candidateId", "relation"},
                "candidate relationship",
            )
            label(relation["candidateId"], "related candidate")
            if relation["relation"] not in ("possible-duplicate", "same-candidate"):
                raise ReportError("invalid candidate relationship")
        records.append(value)
        previous = value["resultSha256"]
    return candidate, records


def _comparison_key(result: dict, selected: list[str], project: str) -> str:
    provenance = result.get("provenance", {})
    profile = {
        k: provenance.get(k)
        for k in (
            "kind",
            "tool",
            "toolVersion",
            "configSha256",
            "format",
            "sourceSuffixes",
            "excludedDirectories",
            "matrixSha256",
            "scenarioSha256",
        )
    }
    contexts = []
    for item_id in selected:
        item = selectable(result)[item_id]
        if result["schemaVersion"] == HTTP_SCHEMA:
            contexts.append(
                {
                    "context": item["context"],
                    "request": {
                        k: item["request"][k]
                        for k in (
                            "urlSha256",
                            "bodySha256",
                            "bodyCaptured",
                            "headerNames",
                        )
                    },
                    "selectors": item["response"]["json"]["selectedPointers"],
                }
            )
        else:
            contexts.append(
                {
                    k: item[k]
                    for k in ("tool", "ruleId", "path", "line", "endpoint", "context")
                }
            )
    # Empty results cannot demonstrate that an earlier selected observation is fixed.
    return digest(
        {
            "projectId": project,
            "schema": result["schemaVersion"],
            "profile": profile,
            "contexts": sorted(contexts, key=digest),
        }
    )


def record_decision(
    directory: str,
    evidence_path: str,
    selected: list[str],
    decision: str,
    explanation: str,
    retest_of: int | None = None,
    related: str | None = None,
    relation: str | None = None,
) -> dict:
    candidate, records = _history(directory)
    if len(records) >= 1000:
        raise ReportError("candidate history limit reached")
    if decision not in DECISIONS or not note(explanation, "decision note").strip():
        raise ReportError(
            "candidate decision requires a supported outcome and rationale"
        )
    result = evidence_result(Path(evidence_path))
    if project_of(result) not in (None, candidate["projectId"]):
        raise ReportError("candidate evidence project mismatch")
    if result["schemaVersion"] == "whitehat-http-comparison-v1":
        raise ReportError(
            "candidate decisions select observations or exchanges, not comparisons"
        )
    if (
        not isinstance(selected, list)
        or len(selected) > 500
        or any(not isinstance(v, str) for v in selected)
        or len(selected) != len(set(selected))
        or set(selected) - selectable(result).keys()
    ):
        raise ReportError("candidate decision selects unknown/duplicate evidence")
    if not selected and decision not in {"inconclusive", "not-comparable"}:
        raise ReportError("select at least one observation or exchange")
    if (related is None) != (relation is None) or relation not in (
        None,
        "possible-duplicate",
        "same-candidate",
    ):
        raise ReportError(
            "candidate relationship needs a related ID and supported relation"
        )
    relationship = (
        None
        if related is None
        else {"candidateId": label(related, "related candidate"), "relation": relation}
    )
    if related == candidate["candidateId"]:
        raise ReportError("candidate cannot relate to itself")
    key = _comparison_key(result, selected, candidate["projectId"])
    suitable = None
    requested = decision
    if retest_of is not None:
        if (
            type(retest_of) is not int
            or not 1 <= retest_of <= len(records)
            or decision not in RETESTS
        ):
            raise ReportError(
                "retest requires a prior decision sequence and retest outcome"
            )
        suitable = bool(selected) and key == records[retest_of - 1]["comparisonKey"]
        if result["schemaVersion"] == HTTP_SCHEMA:
            suitable = suitable and all(
                selectable(result)[s]["response"]["bodyCaptured"]
                and selectable(result)[s]["response"]["json"]["parsed"]
                for s in selected
            )
        if not suitable:
            decision = "not-comparable"
    elif decision in RETESTS:
        # Initial reproduction conclusions are allowed and explicitly not labelled retests.
        suitable = None
    sequence = len(records) + 1
    value = seal(
        {
            "schemaVersion": "whitehat-candidate-decision-v1",
            "ok": True,
            "candidateId": candidate["candidateId"],
            "projectId": candidate["projectId"],
            "candidateSha256": digest(candidate),
            "sequence": sequence,
            "previousSha256": records[-1]["resultSha256"] if records else None,
            "createdAt": _review_timestamp(None),
            "decision": decision,
            "requestedDecision": requested,
            "note": explanation,
            "evidence": {
                "schemaVersion": result["schemaVersion"],
                "resultSha256": result["resultSha256"],
                "selected": sorted(selected),
            },
            "comparisonKey": key,
            "comparisonSuitable": suitable,
            "retestOf": retest_of,
            "relationship": relationship,
            "claims": dict(CLAIMS),
            "effects": {"network": False, "filesystemWrite": True},
        }
    )
    # Two concurrent writers choose the same next filename; exclusive creation refuses the loser.
    write_json_document(value, Path(directory) / "decisions" / f"{sequence:06d}.json")
    return value


def candidate_history(directory: str) -> dict:
    candidate, decisions = _history(directory)
    return seal(
        {
            "schemaVersion": "whitehat-candidate-history-v1",
            "ok": True,
            "candidate": candidate,
            "decisions": decisions,
            "claims": dict(CLAIMS),
            "effects": {"network": False},
        }
    )
