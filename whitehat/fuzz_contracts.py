"""Shared bounded contracts for concrete fuzz cases and batches."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .evidence_links import contained_path, fields, sha256
from .http_evidence import digest, label, pointers
from .http_replay import prepared_request
from .records import RecordError, write_json_document
from .reports import ReportError, canonical, parse_json, read_bytes

CASE_SCHEMA = "whitehat-fuzz-case-v1"
BATCH_SCHEMA = "whitehat-fuzz-batch-v1"
PLAN_SCHEMA = "whitehat-fuzz-plan-v1"


def integer(value: Any, name: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ReportError(f"{name} must be an integer from {low} to {high}")
    return value


def json_file(path: Path, maximum: int = 256 * 1024) -> dict:
    value = parse_json(read_bytes(path, maximum))
    if not isinstance(value, dict):
        raise ReportError("expected a JSON object")
    return value


def expectation(value: Any) -> dict:
    fields(value, {"statuses", "values", "absent"}, "fuzz expectation")
    if (
        not isinstance(value["statuses"], list)
        or not 1 <= len(value["statuses"]) <= 100
    ):
        raise ReportError("expectation needs bounded explicit status codes")
    for status in value["statuses"]:
        integer(status, "status", 100, 599)
    if not isinstance(value["values"], dict) or not isinstance(value["absent"], list):
        raise ReportError("invalid expected response values")
    pointers(list(value["values"]) + value["absent"])
    for item in value["values"].values():
        scalar(item)
    return value


def scalar(value: Any) -> Any:
    if isinstance(value, (dict, list)) or len(canonical(value)) > 1024:
        raise ReportError("expected a bounded scalar")
    if isinstance(value, str) and (len(value) > 256 or any(ord(c) < 32 for c in value)):
        raise ReportError("scalar contains unsupported content")
    return value


def assertions(value: Any, step_ids: set[str]) -> list[dict]:
    if not isinstance(value, list) or len(value) > 32:
        raise ReportError("at most 32 relational assertions are supported")
    seen = set()
    for assertion in value:
        fields(
            assertion,
            {"id", "relation", "left", "right", "value"},
            "relational assertion",
        )
        name = label(assertion["id"], "assertion")
        if name in seen:
            raise ReportError("duplicate assertion ID")
        seen.add(name)
        relation = assertion["relation"]
        if relation not in (
            "unchanged",
            "equals",
            "delta",
            "absent",
            "present",
            "equals-value",
        ):
            raise ReportError("unsupported relational assertion")
        for side in ("left", "right"):
            operand = assertion[side]
            if side == "right" and relation in ("absent", "present", "equals-value"):
                if operand is not None:
                    raise ReportError("unary assertion must omit right operand")
                continue
            fields(
                operand,
                {"stepId", "pointer", "identityId", "objectId"},
                "assertion operand",
            )
            if label(operand["stepId"], "operand step") not in step_ids:
                raise ReportError("assertion refers to an unknown step")
            pointers([operand["pointer"]])
            for key in ("identityId", "objectId"):
                if label(operand[key], key) == "unlabeled":
                    raise ReportError(
                        "assertions require explicit identity/object labels"
                    )
        scalar(assertion["value"])
        if relation == "delta" and type(assertion["value"]) is not int:
            raise ReportError("delta requires an integer")
        if (
            relation in ("unchanged", "equals", "absent", "present")
            and assertion["value"] is not None
        ):
            raise ReportError("this relation does not accept a comparison value")
    return value


def load_case(path: Path) -> tuple[dict, dict[str, dict]]:
    value = json_file(path)
    fields(
        value,
        {
            "schemaVersion",
            "projectId",
            "id",
            "setup",
            "steps",
            "reset",
            "assertions",
            "lineage",
        },
        "fuzz case",
    )
    if value["schemaVersion"] != CASE_SCHEMA:
        raise ReportError("unsupported fuzz case")
    label(value["projectId"], "project")
    label(value["id"], "case")
    if not isinstance(value["lineage"], dict):
        raise ReportError("invalid case provenance")
    requests, seen, observable = {}, set(), set()
    for phase in ("setup", "steps", "reset"):
        steps = value[phase]
        if (
            not isinstance(steps, list)
            or len(steps) > 20
            or (phase == "steps" and not steps)
        ):
            raise ReportError("fuzz case needs 1-20 test steps and bounded setup/reset")
        for step in steps:
            fields(
                step,
                {"id", "request", "requestSha256", "identityId", "expect"},
                "fuzz step",
            )
            name = label(step["id"], "step")
            if name in seen:
                raise ReportError("duplicate case step ID")
            seen.add(name)
            if phase != "reset":
                observable.add(name)
            label(step["identityId"], "identity")
            expectation(step["expect"])
            request = prepared_request(
                json_file(contained_path(path.parent, step["request"]), 128 * 1024)
            )
            if digest(request) != sha256(step["requestSha256"]):
                raise ReportError("case request hash mismatch")
            requests[name] = request
    assertions(value["assertions"], observable)
    if len(seen) > 40:
        raise ReportError("case exceeds 40 total request steps")
    return value, requests


def load_batch(path: str) -> tuple[dict, list[tuple[dict, dict[str, dict]]]]:
    source = Path(path)
    value = json_file(source)
    fields(value, {"schemaVersion", "projectId", "cases", "provenance"}, "fuzz batch")
    if value["schemaVersion"] != BATCH_SCHEMA:
        raise ReportError("unsupported fuzz batch")
    label(value["projectId"], "project")
    if not isinstance(value["cases"], list) or not 1 <= len(value["cases"]) <= 32:
        raise ReportError("batch requires 1-32 cases")
    cases, seen = [], set()
    for reference in value["cases"]:
        fields(reference, {"path", "caseSha256"}, "batch case reference")
        case, requests = load_case(contained_path(source.parent, reference["path"]))
        if (
            digest(case) != sha256(reference["caseSha256"])
            or case["projectId"] != value["projectId"]
        ):
            raise ReportError("batch case hash/project mismatch")
        if case["id"] in seen:
            raise ReportError("duplicate batch case ID")
        seen.add(case["id"])
        cases.append((case, requests))
    if sum(len(requests) for _, requests in cases) > 100:
        raise ReportError("batch exceeds 100 total requests including setup/reset")
    return value, cases


def write_tree(directory: str, documents: dict[str, dict]) -> None:
    destination = Path(directory)
    if destination.exists() or destination.is_symlink():
        raise RecordError("output directory already exists")
    root = destination.parent.resolve(strict=True) / destination.name
    for name in documents:
        # Validate lexical containment before any write.
        from .reports import relative_path

        relative_path(name)
    if sum(len(canonical(v)) for v in documents.values()) > 16 * 1024 * 1024:
        raise ReportError("generated artifact limit exceeded")
    root.mkdir()
    for name, document in documents.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        write_json_document(document, path)


def embedded_step(value: Any) -> dict:
    fields(value, {"id", "request", "identityId", "expect"}, "embedded step")
    label(value["id"], "step")
    label(value["identityId"], "identity")
    prepared_request(value["request"])
    expectation(value["expect"])
    return value


def bundle_case(value: dict, documents: dict) -> dict:
    import copy

    case = copy.deepcopy(value)
    for phase in ("setup", "steps", "reset"):
        for step in case[phase]:
            embedded_step(step)
            request = step["request"]
            key = digest(request)
            name = f"requests/{key}.json"
            documents[name] = request
            step["request"] = name
            step["requestSha256"] = key
    return case
