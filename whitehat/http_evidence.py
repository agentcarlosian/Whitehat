"""Project-bound HTTP evidence, capture imports, comparisons and access expectations."""

from __future__ import annotations

import base64
import hashlib
import math
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .records import load_result_document
from .reports import (
    CLAIMS,
    ReportError,
    ReportLimitError,
    canonical,
    endpoint,
    observation,
    parse_json,
    read_bytes,
    result_document,
    seal,
    text,
)

HTTP_SCHEMA = "whitehat-http-evidence-v1"
MAX_BODY = 1024 * 1024
MAX_EXCHANGES = 500
_SENSITIVE = re.compile(
    r"token|password|passwd|secret|authorization|cookie|credential|private.?key", re.I
)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def label(value: Any, name: str) -> str:
    value = text(value, name, 100)
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,99}", value):
        raise ReportError(f"{name} must be a simple label")
    return value


def pointers(values: Any) -> list[str]:
    if (
        not isinstance(values, list)
        or len(values) > 32
        or any(not isinstance(value, str) for value in values)
        or len(values) != len(set(values))
    ):
        raise ReportError("select at most 32 unique JSON pointers")
    for value in values:
        text(value, "JSON pointer", 256)
        if (
            not value.startswith("/")
            or _SENSITIVE.search(value)
            or re.search(r"~(?![01])", value)
        ):
            raise ReportError("JSON pointer is invalid or names sensitive data")
    return sorted(values)


def _pointer(value: Any, pointer: str) -> tuple[bool, Any]:
    current = value
    for component in pointer[1:].split("/"):
        component = component.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and component in current:
            current = current[component]
        elif (
            isinstance(current, list)
            and component.isdecimal()
            and int(component) < len(current)
        ):
            current = current[int(component)]
        else:
            return False, None
    return True, current


def json_summary(raw: bytes, selected: list[str]) -> dict[str, Any]:
    if len(raw) > MAX_BODY:
        raise ReportLimitError("HTTP body limit exceeded")
    selected = pointers(selected)
    try:
        parsed = parse_json(raw)
    except ReportError:
        return {
            "parsed": False,
            "shape": {},
            "selectedPointers": selected,
            "values": {},
        }
    shape: dict[str, str] = {}

    def visit(value: Any, path: str, depth: int) -> None:
        if depth > 16 or len(shape) >= 2000:
            raise ReportLimitError("JSON shape depth/node limit exceeded")
        kind = (
            "object"
            if isinstance(value, dict)
            else "array"
            if isinstance(value, list)
            else "null"
            if value is None
            else "boolean"
            if isinstance(value, bool)
            else "number"
            if isinstance(value, (int, float))
            else "string"
        )
        shape[path] = kind
        if isinstance(value, dict):
            for key, child in value.items():
                text(key, "JSON property", 256)
                visit(
                    child,
                    path + "/" + key.replace("~", "~0").replace("/", "~1"),
                    depth + 1,
                )
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, path + f"/{index}", depth + 1)

    visit(parsed, "", 0)
    retained = {}
    for pointer in selected:
        present, value = _pointer(parsed, pointer)
        if present:
            if isinstance(value, (dict, list)) or (
                isinstance(value, str)
                and (len(value) > 256 or any(ord(c) < 32 for c in value))
            ):
                raise ReportError("selected evidence must be a bounded scalar")
            retained[pointer] = value
    return {
        "parsed": True,
        "shape": dict(sorted(shape.items())),
        "selectedPointers": selected,
        "values": retained,
    }


def _headers(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > 100:
        raise ReportError("HTTP headers must be a bounded array")
    names = []
    for entry in value:
        if not isinstance(entry, dict):
            raise ReportError("invalid header")
        name = text(entry.get("name"), "header name", 100).lower()
        if not re.fullmatch(r"[a-z0-9!#$%&'*+.^_`|~-]+", name):
            raise ReportError("invalid header name")
        names.append(name)
    return sorted(set(names))


def exchange(
    project: str,
    request: dict[str, Any],
    response: dict[str, Any],
    *,
    identity: str,
    object_id: str,
    operation: str,
    selected: list[str],
) -> dict[str, Any]:
    project = label(project, "project")
    method = request.get("method")
    if not isinstance(method, str) or not re.fullmatch(r"[A-Z]{3,16}", method):
        raise ReportError("invalid HTTP method")
    url = endpoint(request.get("url"))
    query = urlsplit(request["url"]).query
    if len(query) > 8192:
        raise ReportLimitError("query size limit exceeded")
    try:
        query_names = sorted(
            {
                text(k, "query parameter", 128)
                for k, _ in parse_qsl(query, keep_blank_values=True, max_num_fields=100)
            }
        )
    except ValueError as exc:
        raise ReportError("invalid query parameters") from exc
    posted = request.get("postData", {})
    if not isinstance(posted, dict) or (
        posted.get("text") is not None and not isinstance(posted["text"], str)
    ):
        raise ReportError("invalid captured request body")
    request_raw = (posted.get("text") or "").encode("utf-8")
    if not isinstance(posted.get("mimeType", ""), str):
        raise ReportError("invalid captured request MIME type")
    request_json = json_summary(request_raw, [])
    body_parameters = sorted(
        k
        for k, kind in request_json["shape"].items()
        if k and kind not in {"object", "array"}
    )
    if (
        posted.get("mimeType", "").split(";", 1)[0]
        == "application/x-www-form-urlencoded"
    ):
        try:
            body_parameters = sorted(
                {
                    text(k, "form parameter", 128)
                    for k, _ in parse_qsl(
                        posted.get("text") or "",
                        keep_blank_values=True,
                        max_num_fields=100,
                    )
                }
            )
        except ValueError as exc:
            raise ReportError("invalid form parameters") from exc
    status = response.get("status")
    if (
        isinstance(status, bool)
        or not isinstance(status, int)
        or not 100 <= status <= 599
    ):
        raise ReportError("invalid HTTP response status")
    content = response.get("content", {})
    if not isinstance(content, dict):
        raise ReportError("invalid response content")
    body = content.get("text") or ""
    if content.get("text") is not None and not isinstance(content["text"], str):
        raise ReportError("invalid captured response body")
    if not isinstance(body, str) or len(body) > MAX_BODY * 2:
        raise ReportLimitError("response text limit exceeded")
    encoding = content.get("encoding")
    if encoding not in (None, "base64"):
        raise ReportError("unsupported capture encoding")
    try:
        raw = (
            base64.b64decode(body, validate=True) if encoding else body.encode("utf-8")
        )
    except ValueError as exc:
        raise ReportError("invalid base64 body") from exc
    if len(raw) > MAX_BODY:
        raise ReportLimitError("HTTP body limit exceeded")
    context = {
        "projectId": project,
        "method": method,
        "endpoint": url,
        "queryNames": query_names,
        "bodyParameters": body_parameters,
        "identityId": label(identity, "identity"),
        "objectId": label(object_id, "object"),
        "operationId": label(operation, "operation"),
    }
    result = {
        "context": context,
        "observationId": digest(context),
        "request": {
            "headerNames": _headers(request.get("headers", [])),
            "urlSha256": hashlib.sha256(request["url"].encode("utf-8")).hexdigest(),
            "bodyCaptured": isinstance(posted.get("text"), str),
            "bodySha256": hashlib.sha256(request_raw).hexdigest(),
            "jsonShape": request_json["shape"],
        },
        "response": {
            "status": status,
            "bodyCaptured": isinstance(content.get("text"), str),
            "headerNames": _headers(response.get("headers", [])),
            "bodyBytes": len(raw),
            "bodySha256": hashlib.sha256(raw).hexdigest(),
            "json": json_summary(raw, selected),
        },
    }
    result["evidenceSha256"] = digest(result)
    return result


def evidence_document(
    project: str, records: list[dict[str, Any]], provenance: dict[str, Any]
) -> dict[str, Any]:
    if len(records) > MAX_EXCHANGES:
        raise ReportLimitError("HTTP exchange count exceeded")
    return seal(
        {
            "schemaVersion": HTTP_SCHEMA,
            "ok": True,
            "projectId": label(project, "project"),
            "exchanges": records,
            "provenance": provenance,
            "claims": dict(CLAIMS),
            "effects": {
                "network": provenance.get("kind") == "replay",
                "rawHeadersExported": False,
            },
        }
    )


def capture_entries(raw: bytes, format_name: str = "har") -> list[dict[str, Any]]:
    """Read an archive as data; never run producer extensions or scripts."""
    value = parse_json(raw)
    if not isinstance(value, dict):
        raise ReportError("capture must be an object")
    if format_name == "har":
        log = value.get("log")
        if not isinstance(log, dict) or log.get("version") != "1.2":
            raise ReportError("expected HAR 1.2")
        entries = log.get("entries")
    elif (
        format_name == "capture"
        and value.get("schemaVersion") == "whitehat-http-capture-v1"
    ):
        entries = value.get("entries")
    else:
        raise ReportError("unsupported capture format")
    if not isinstance(entries, list) or len(entries) > MAX_EXCHANGES:
        raise ReportError("capture entries must be a bounded array")
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("request"), dict)
            or (
                entry.get("response") is not None
                and not isinstance(entry["response"], dict)
            )
        ):
            raise ReportError(
                "capture entry requires a request and optional response object"
            )
    return entries


def import_capture(
    path: str,
    project: str,
    *,
    format_name: str = "har",
    identity: str = "unlabeled",
    object_id: str = "unlabeled",
    operation: str = "unlabeled",
    selected: list[str] | None = None,
) -> dict[str, Any]:
    raw = read_bytes(Path(path))
    entries = capture_entries(raw, format_name)
    records, indexes, incomplete, diagnostics = [], [], [], []
    for index, entry in enumerate(entries):
        binding = entry.get("_whitehat", {})
        if not isinstance(binding, dict) or set(binding) - {
            "identityId",
            "objectId",
            "operationId",
        }:
            raise ReportError("invalid capture labels")
        response = entry.get("response")
        missing = response is None or (
            type(response.get("status")) is int and response["status"] == 0
        )
        # Validate every retained request/body/header even for incomplete entries.
        # The placeholder is internal only and is never emitted as an exchange.
        checked_response = dict(response or {})
        if missing:
            checked_response["status"] = 200
        record = exchange(
            project,
            entry["request"],
            checked_response,
            identity=binding.get("identityId", identity),
            object_id=binding.get("objectId", object_id),
            operation=binding.get("operationId", operation),
            selected=selected or [],
        )
        if missing:
            incomplete.append(
                {
                    "entryIndex": index,
                    "context": record["context"],
                    "reason": "no-http-response",
                }
            )
        else:
            records.append(record)
            indexes.append(index)
        if "_webSocketMessages" in entry:
            diagnostics.append(
                {"entryIndex": index, "code": "websocket-messages-not-imported"}
            )
    return evidence_document(
        project,
        records,
        {
            "kind": "import",
            "format": format_name,
            "captureSha256": hashlib.sha256(raw).hexdigest(),
            "executionVerified": False,
            "identityBinding": "operator-asserted",
            "entryIndexes": indexes,
            "incompleteEntries": incomplete,
            "diagnostics": diagnostics,
        },
    )


def load_evidence(path: str) -> dict[str, Any]:
    value = load_result_document(path)
    return validate_evidence(value)


def validate_evidence(value: dict[str, Any]) -> dict[str, Any]:
    from .records import validate_result_document

    validate_result_document(value)
    if value["schemaVersion"] != HTTP_SCHEMA or value.get("claims") != CLAIMS:
        raise ReportError("expected HTTP evidence")
    provenance = value.get("provenance")
    if not isinstance(provenance, dict):
        raise ReportError("invalid HTTP evidence provenance")
    for key in ("incompleteEntries", "diagnostics", "evaluations"):
        items = provenance.get(key, [])
        if (
            not isinstance(items, list)
            or len(items) > MAX_EXCHANGES
            or any(not isinstance(v, dict) for v in items)
        ):
            raise ReportError("invalid HTTP evidence provenance records")
    if provenance.get("profile") == "explicit-scenario":
        planned, executed = (
            provenance.get("plannedSteps"),
            provenance.get("executedSteps"),
        )
        if (
            type(planned) is not int
            or not 1 <= planned <= 20
            or type(executed) is not int
            or not 0 <= executed <= planned
            or len(provenance.get("evaluations", [])) != executed
        ):
            raise ReportError("invalid scenario completion counts")
        for evaluation in provenance["evaluations"]:
            if set(evaluation) != {"stepId", "outcome", "evidenceSha256"} or evaluation[
                "outcome"
            ] not in ("consistent", "mismatch"):
                raise ReportError("invalid scenario evaluation")
            label(evaluation["stepId"], "scenario step")
    project = label(value.get("projectId"), "project")
    records = value.get("exchanges")
    if not isinstance(records, list) or len(records) > MAX_EXCHANGES:
        raise ReportError("invalid evidence records")
    for item in records:
        if not isinstance(item, dict) or set(item) != {
            "context",
            "observationId",
            "request",
            "response",
            "evidenceSha256",
        }:
            raise ReportError("invalid exchange fields")
        context = item["context"]
        if (
            not isinstance(context, dict)
            or context.get("projectId") != project
            or digest(context) != item["observationId"]
        ):
            raise ReportError("HTTP observation identity mismatch")
        if set(context) != {
            "projectId",
            "method",
            "endpoint",
            "queryNames",
            "bodyParameters",
            "identityId",
            "objectId",
            "operationId",
        }:
            raise ReportError("invalid HTTP context fields")
        for key in ("identityId", "objectId", "operationId"):
            label(context[key], key)
        for key in ("queryNames", "bodyParameters"):
            names = context[key]
            if (
                not isinstance(names, list)
                or len(names) > 2000
                or any(not isinstance(n, str) or len(n) > 256 for n in names)
            ):
                raise ReportError("invalid HTTP parameter context")
        if not isinstance(context["method"], str) or not re.fullmatch(
            r"[A-Z]{3,16}", context["method"]
        ):
            raise ReportError("invalid evidence method")
        if endpoint(context["endpoint"]) != context["endpoint"]:
            raise ReportError("invalid evidence endpoint")
        request = item["request"]
        if not isinstance(request, dict) or set(request) != {
            "headerNames",
            "urlSha256",
            "bodyCaptured",
            "bodySha256",
            "jsonShape",
        }:
            raise ReportError("invalid request evidence fields")
        if type(request["bodyCaptured"]) is not bool or not isinstance(
            request["jsonShape"], dict
        ):
            raise ReportError("invalid request evidence types")
        response = item["response"]
        if not isinstance(response, dict) or set(response) != {
            "status",
            "bodyCaptured",
            "headerNames",
            "bodyBytes",
            "bodySha256",
            "json",
        }:
            raise ReportError("invalid response evidence fields")
        if (
            type(response["status"]) is not int
            or not 100 <= response["status"] <= 599
            or type(response["bodyCaptured"]) is not bool
        ):
            raise ReportError("invalid response status/capture flag")
        for headers in (request["headerNames"], response["headerNames"]):
            if not isinstance(headers, list) or len(headers) > 100:
                raise ReportError("invalid evidence header names")
            _headers([{"name": name} for name in headers])
        for hash_value in (
            request["urlSha256"],
            request["bodySha256"],
            response["bodySha256"],
        ):
            if not isinstance(hash_value, str) or not re.fullmatch(
                r"[a-f0-9]{64}", hash_value
            ):
                raise ReportError("invalid request/response digest")
        if (
            type(response["bodyBytes"]) is not int
            or not 0 <= response["bodyBytes"] <= MAX_BODY
        ):
            raise ReportError("invalid response byte count")
        data = response["json"]
        if not isinstance(data, dict) or set(data) != {
            "parsed",
            "shape",
            "selectedPointers",
            "values",
        }:
            raise ReportError("invalid JSON evidence fields")
        pointers(data["selectedPointers"])
        if (
            type(data["parsed"]) is not bool
            or not isinstance(data["shape"], dict)
            or not isinstance(data["values"], dict)
        ):
            raise ReportError("invalid JSON evidence types")
        if len(data["shape"]) > 2000 or set(data["values"]) - set(
            data["selectedPointers"]
        ):
            raise ReportError("invalid JSON evidence selection")
        for scalar in data["values"].values():
            if (
                isinstance(scalar, (dict, list))
                or (isinstance(scalar, float) and not math.isfinite(scalar))
                or (
                    isinstance(scalar, str)
                    and (len(scalar) > 256 or any(ord(c) < 32 for c in scalar))
                )
            ):
                raise ReportError("selected evidence must be a bounded scalar")
        if (not data["parsed"] or not response["bodyCaptured"]) and data["values"]:
            raise ReportError(
                "uncaptured/unparsed responses cannot contain selected values"
            )
        payload = {k: v for k, v in item.items() if k != "evidenceSha256"}
        if digest(payload) != item["evidenceSha256"]:
            raise ReportError("HTTP evidence hash mismatch")
    if provenance.get("profile") == "explicit-scenario":
        if provenance["executedSteps"] != len(records) or len(
            {e["stepId"] for e in provenance["evaluations"]}
        ) != len(provenance["evaluations"]):
            raise ReportError("scenario steps and exchanges differ")
        if any(
            e["evidenceSha256"] != r["evidenceSha256"]
            for e, r in zip(provenance["evaluations"], records)
        ):
            raise ReportError("scenario evaluation references a different exchange")
    return value


def compare_http(
    before: str,
    after: str,
    before_index: int = 0,
    after_index: int = 0,
    ignored: list[str] | None = None,
) -> dict[str, Any]:
    a, b = load_evidence(before), load_evidence(after)
    if a["projectId"] != b["projectId"]:
        raise ReportError("cannot compare different projects")
    if not 0 <= before_index < len(a["exchanges"]) or not 0 <= after_index < len(
        b["exchanges"]
    ):
        raise ReportError("exchange index out of range")
    left, right = a["exchanges"][before_index], b["exchanges"][after_index]
    ignored = pointers(ignored or [])
    aj, bj = left["response"]["json"], right["response"]["json"]
    if aj["selectedPointers"] != bj["selectedPointers"]:
        raise ReportError("comparison requires identical response selectors")

    def changes(first: dict[str, Any], second: dict[str, Any]) -> list[dict[str, Any]]:
        result = []
        for key in sorted(first.keys() | second.keys()):
            if key in ignored or any(key.startswith(v + "/") for v in ignored):
                continue
            if key not in first or key not in second or first[key] != second[key]:
                result.append(
                    {
                        "pointer": key,
                        "beforePresent": key in first,
                        "afterPresent": key in second,
                        "before": first.get(key),
                        "after": second.get(key),
                    }
                )
        return result

    return seal(
        {
            "schemaVersion": "whitehat-http-comparison-v1",
            "ok": True,
            "projectId": a["projectId"],
            "beforeEvidenceSha256": left["evidenceSha256"],
            "afterEvidenceSha256": right["evidenceSha256"],
            "contexts": {"before": left["context"], "after": right["context"]},
            "status": {
                "before": left["response"]["status"],
                "after": right["response"]["status"],
            },
            "shapeChanges": changes(aj["shape"], bj["shape"]),
            "valueChanges": changes(aj["values"], bj["values"]),
            "ignoredPointers": ignored,
            "claims": dict(CLAIMS),
            "effects": {"network": False},
        }
    )


def assess_access(matrix_path: str, evidence_paths: list[str]) -> dict[str, Any]:
    matrix = parse_json(read_bytes(Path(matrix_path), 256 * 1024))
    if (
        not isinstance(matrix, dict)
        or set(matrix) != {"schemaVersion", "projectId", "rows"}
        or matrix["schemaVersion"] != "whitehat-access-matrix-v1"
    ):
        raise ReportError("invalid access matrix")
    project = label(matrix["projectId"], "project")
    rows = matrix["rows"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 200:
        raise ReportError("matrix needs 1-200 rows")
    if not 1 <= len(evidence_paths) <= 20:
        raise ReportError("supply 1-20 evidence files")
    records = []
    hashes = []
    for path in evidence_paths:
        document = load_evidence(path)
        if document["projectId"] != project:
            raise ReportError("matrix and evidence project differ")
        records.extend(document["exchanges"])
        hashes.append(document["resultSha256"])
    observations, evaluations, seen = [], [], set()
    for row in rows:
        fields = {
            "id",
            "identityId",
            "objectId",
            "operationId",
            "method",
            "endpoint",
            "expect",
            "proof",
        }
        if (
            not isinstance(row, dict)
            or set(row) != fields
            or row["expect"] not in {"allow", "deny"}
        ):
            raise ReportError("invalid access row")
        row_id = label(row["id"], "row")
        if row_id in seen:
            raise ReportError("duplicate access row")
        seen.add(row_id)
        proof = row["proof"]
        if not isinstance(proof, dict) or set(proof) != {"pointer", "equals"}:
            raise ReportError(
                "access proof needs a selected pointer and exact owned marker"
            )
        pointers([proof["pointer"]])
        text(proof["equals"], "owned marker", 256)
        for name in ("identityId", "objectId", "operationId"):
            label(row[name], name)
            if row[name] == "unlabeled":
                raise ReportError(
                    "access assessment requires explicit identity/object/operation labels"
                )
        if not isinstance(row["method"], str) or not re.fullmatch(
            r"[A-Z]{3,16}", row["method"]
        ):
            raise ReportError("invalid matrix method")
        if endpoint(row["endpoint"]) != row["endpoint"]:
            raise ReportError("matrix endpoint must omit query/fragment")
        matching = [
            r
            for r in records
            if all(
                r["context"].get(k) == row[k]
                for k in ("identityId", "objectId", "operationId", "method", "endpoint")
            )
        ]
        outcomes = []
        for record in matching:
            response = record["response"]
            data = response["json"]
            if (
                proof["pointer"] not in data["selectedPointers"]
                or not data["parsed"]
                or not response["bodyCaptured"]
            ):
                outcome = "inconclusive"
            else:
                marker = data["values"].get(proof["pointer"]) == proof["equals"]
                denied = response["status"] in {401, 403, 404}
                if row["expect"] == "deny":
                    outcome = (
                        "mismatch"
                        if marker
                        else "consistent"
                        if denied
                        else "inconclusive"
                    )
                else:
                    outcome = (
                        "consistent"
                        if marker and 200 <= response["status"] < 300
                        else "mismatch"
                        if denied
                        else "inconclusive"
                    )
            outcomes.append(outcome)
        disposition = (
            "not-tested"
            if not outcomes
            else "mismatch"
            if "mismatch" in outcomes
            else "inconclusive"
            if "inconclusive" in outcomes
            else "consistent"
        )
        evaluations.append(
            {
                "rowId": row_id,
                "expect": row["expect"],
                "outcome": disposition,
                "evidenceSha256": sorted({r["evidenceSha256"] for r in matching}),
            }
        )
        if disposition == "mismatch":
            observations.append(
                observation(
                    "whitehat-http",
                    "access-expectation-mismatch",
                    url=row["endpoint"],
                    category="web-observation",
                    context={
                        "projectId": project,
                        "rowId": row_id,
                        "method": row["method"],
                        "identityId": row["identityId"],
                        "objectId": row["objectId"],
                        "expected": row["expect"],
                    },
                    explanation="Recorded behavior conflicts with the operator's access expectation. Verify identity, object ownership, and authoritative state before claiming a finding.",
                )
            )
    return result_document(
        observations,
        {
            "kind": "access-assessment",
            "projectId": project,
            "matrixSha256": digest(matrix),
            "evidenceResults": sorted(set(hashes)),
            "evaluations": evaluations,
            "executionVerified": False,
            "identityBinding": "operator-asserted",
        },
    )
