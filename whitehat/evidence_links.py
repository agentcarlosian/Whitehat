"""Bounded explicit artifact links used by research packets and binding plans."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .http_evidence import HTTP_SCHEMA, label, pointers, validate_evidence
from .records import load_result_document
from .reports import (
    CLAIMS,
    ReportError,
    checked_research_result,
    endpoint,
    relative_path,
)


def fields(value: Any, names: set[str], kind: str) -> dict:
    if not isinstance(value, dict) or set(value) != names:
        raise ReportError(f"invalid {kind} fields")
    return value


def sha256(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise ReportError("expected a SHA-256 digest")
    return value


def contained_path(root: Path, value: Any) -> Path:
    relative = relative_path(value)
    root = root.resolve(strict=True)
    path = root
    for part in Path(relative).parts:
        path = path / part
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise ReportError(
                "artifact link must not traverse a symbolic link or junction"
            )
    try:
        path.resolve().relative_to(root)
    except (ValueError, RuntimeError) as exc:
        raise ReportError("artifact link escapes its directory") from exc
    return path


def evidence_result(path: Path) -> dict:
    value = load_result_document(path, 8 * 1024 * 1024)
    schema = value["schemaVersion"]
    if schema == HTTP_SCHEMA:
        return validate_evidence(value)
    if schema == "whitehat-research-result-v1":
        result = checked_research_result(str(path))
        provenance = result["provenance"]
        if provenance.get("kind") == "fuzz-run":
            from .fuzz_corpus import load_run

            return load_run(str(path))
        if provenance.get("kind") == "relational-assessment":
            evaluations = provenance.get("evaluations")
            if not isinstance(evaluations, list) or len(evaluations) > 32:
                raise ReportError("invalid relational assessment")
            for evaluation in evaluations:
                fields(
                    evaluation,
                    {"assertionId", "relation", "outcome", "evidenceSha256"},
                    "relational evaluation",
                )
                label(evaluation["assertionId"], "assertion")
                if evaluation["outcome"] not in (
                    "consistent",
                    "mismatch",
                    "inconclusive",
                ) or not isinstance(evaluation["evidenceSha256"], list):
                    raise ReportError("invalid relational outcome/evidence")
                for value in evaluation["evidenceSha256"]:
                    sha256(value)
        if provenance.get("kind") == "access-assessment":
            label(provenance.get("projectId"), "project")
            sha256(provenance.get("matrixSha256"))
            hashes, evaluations = (
                provenance.get("evidenceResults"),
                provenance.get("evaluations"),
            )
            if (
                not isinstance(hashes, list)
                or len(hashes) > 20
                or not isinstance(evaluations, list)
                or len(evaluations) > 200
            ):
                raise ReportError("invalid access-assessment provenance")
            for hash_value in hashes:
                sha256(hash_value)
            for evaluation in evaluations:
                fields(
                    evaluation,
                    {"rowId", "expect", "outcome", "evidenceSha256"},
                    "access evaluation",
                )
                label(evaluation["rowId"], "access row")
                if evaluation["expect"] not in ("allow", "deny") or evaluation[
                    "outcome"
                ] not in ("consistent", "mismatch", "not-tested", "inconclusive"):
                    raise ReportError("invalid access expectation/outcome")
                if (
                    not isinstance(evaluation["evidenceSha256"], list)
                    or len(evaluation["evidenceSha256"]) > 10000
                ):
                    raise ReportError("invalid access evidence references")
                for hash_value in evaluation["evidenceSha256"]:
                    sha256(hash_value)
        return result
    if schema != "whitehat-http-comparison-v1" or value.get("claims") != CLAIMS:
        raise ReportError(
            "packet evidence must be normalized HTTP, comparison, or research results"
        )
    # Bound and type-check the fields used by renderers; do not render arbitrary extras.
    label(value.get("projectId"), "project")
    if not isinstance(value.get("contexts"), dict) or not isinstance(
        value.get("status"), dict
    ):
        raise ReportError("invalid HTTP comparison context/status")
    pointers(value.get("ignoredPointers"))
    for side in ("before", "after"):
        sha256(value.get(side + "EvidenceSha256"))
        context = value.get("contexts", {}).get(side)
        if not isinstance(context, dict) or not isinstance(
            context.get("endpoint"), str
        ):
            raise ReportError("invalid HTTP comparison context")
        if (
            endpoint(context["endpoint"]) != context["endpoint"]
            or context.get("projectId") != value["projectId"]
        ):
            raise ReportError("HTTP comparison endpoint/project mismatch")
        for key in ("identityId", "objectId", "operationId"):
            label(context.get(key), key)
        status = value.get("status", {}).get(side)
        if type(status) is not int or not 100 <= status <= 599:
            raise ReportError("invalid HTTP comparison status")
    for key in ("shapeChanges", "valueChanges"):
        if not isinstance(value.get(key), list) or len(value[key]) > 4000:
            raise ReportError("invalid HTTP comparison changes")
        for change in value[key]:
            fields(
                change,
                {"pointer", "beforePresent", "afterPresent", "before", "after"},
                "comparison change",
            )
            if not isinstance(change["pointer"], str) or any(
                isinstance(change[s], (list, dict)) for s in ("before", "after")
            ):
                raise ReportError("invalid HTTP comparison scalar")
            for side in ("before", "after"):
                if type(change[side + "Present"]) is not bool or (
                    isinstance(change[side], str) and len(change[side]) > 256
                ):
                    raise ReportError("invalid HTTP comparison value")
    return value


def project_of(value: dict) -> str | None:
    return value.get("projectId") or value.get("provenance", {}).get("projectId")


def selectable(value: dict) -> dict[str, dict]:
    if value["schemaVersion"] == HTTP_SCHEMA:
        return {e["evidenceSha256"]: e for e in value["exchanges"]}
    if value["schemaVersion"] == "whitehat-research-result-v1":
        return {e["fingerprint"]: e for e in value["observations"]}
    return {}
