"""Prepared OpenAPI inventory and pinned oasdiff execution. Never fetch references."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .http_evidence import label, load_evidence
from .native_tools import TOOLS, platform_key, verify_tool
from .reports import (
    CLAIMS,
    ReportError,
    ReportLimitError,
    canonical,
    observation,
    parse_json,
    read_bytes,
    result_document,
    seal,
    text,
)
from .runner import ProcessLimits, execute_fixed_profile


def load_schema(path: str) -> dict[str, Any]:
    raw = read_bytes(Path(path), 2 * 1024 * 1024)
    if Path(path).suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml
        except ImportError as exc:
            raise ReportError("YAML requires the optional api extra") from exc

        class UniqueLoader(yaml.SafeLoader):
            pass

        def mapping(loader, node, deep=False):
            result = {}
            for key_node, value_node in node.value:
                key = loader.construct_object(key_node, deep=deep)
                if not isinstance(key, str) or key in result:
                    raise ReportError("YAML keys must be unique strings")
                result[key] = loader.construct_object(value_node, deep=deep)
            return result

        UniqueLoader.add_constructor(
            yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping
        )
        try:
            value = yaml.load(raw, Loader=UniqueLoader)
        except (yaml.YAMLError, RecursionError) as exc:
            raise ReportError("invalid OpenAPI YAML") from exc
    else:
        value = parse_json(raw)
    if not isinstance(value, dict) or not re.fullmatch(
        r"3\.[01]\.\d+", str(value.get("openapi", ""))
    ):
        raise ReportError("OpenAPI 3.0/3.1 is required")
    count = 0
    active: set[int] = set()

    def walk(node: Any, depth: int) -> None:
        nonlocal count
        count += 1
        if count > 30_000 or depth > 40:
            raise ReportLimitError("schema node/depth limit exceeded")
        if isinstance(node, (dict, list)):
            if id(node) in active:
                raise ReportError("recursive YAML aliases are unsupported")
            active.add(id(node))
            if isinstance(node, dict):
                if any(not isinstance(k, str) for k in node):
                    raise ReportError("schema keys must be strings")
                if "$ref" in node and (
                    not isinstance(node["$ref"], str)
                    or not node["$ref"].startswith("#/")
                ):
                    raise ReportError("external schema references are not permitted")
                children = node.values()
            else:
                children = node
            for child in children:
                walk(child, depth + 1)
            active.remove(id(node))
        elif node is not None and not isinstance(node, (str, bool, int, float)):
            raise ReportError("schema contains unsupported YAML types")

    walk(value, 0)
    try:
        canonical(value)
    except ValueError as exc:
        raise ReportError("schema contains a non-finite number") from exc
    return value


def _resolve(value: Any, root: dict[str, Any]) -> dict[str, Any]:
    seen = set()
    while isinstance(value, dict) and "$ref" in value:
        reference = value["$ref"]
        if reference in seen or len(seen) > 20:
            raise ReportError("cyclic reference while resolving an inventory node")
        seen.add(reference)
        current: Any = root
        for key in reference[2:].split("/"):
            key = key.replace("~1", "/").replace("~0", "~")
            if not isinstance(current, dict) or key not in current:
                raise ReportError("schema reference does not resolve")
            current = current[key]
        value = current
    if not isinstance(value, dict):
        raise ReportError("schema inventory node must be an object")
    return value


def _security(value: Any) -> list[dict[str, list[str]]]:
    if not isinstance(value, list) or len(value) > 30:
        raise ReportError("security requirements must be a bounded array")
    result = []
    for alternative in value:
        if not isinstance(alternative, dict) or len(alternative) > 20:
            raise ReportError("invalid security alternative")
        checked = {}
        for scheme, scopes in alternative.items():
            text(scheme, "security scheme", 128)
            if not isinstance(scopes, list) or len(scopes) > 50:
                raise ReportError("invalid security scopes")
            checked[scheme] = sorted({text(scope, "scope", 128) for scope in scopes})
        result.append(dict(sorted(checked.items())))
    return sorted(result, key=canonical)


def inventory_value(schema: dict[str, Any], project: str) -> dict[str, Any]:
    paths = schema.get("paths")
    if not isinstance(paths, dict) or len(paths) > 1000:
        raise ReportError("schema paths must be a bounded object")
    operations = []
    global_security = _security(schema.get("security", []))
    for path, node in sorted(paths.items()):
        text(path, "API path", 1024)
        if not path.startswith("/") or "?" in path or "#" in path:
            raise ReportError("invalid OpenAPI path")
        node = _resolve(node, schema)
        for method in (
            "get",
            "head",
            "post",
            "put",
            "patch",
            "delete",
            "options",
            "trace",
        ):
            if method not in node:
                continue
            operation = _resolve(node[method], schema)
            security = (
                _security(operation["security"])
                if "security" in operation
                else global_security
            )
            parameters = []
            shared_parameters = node.get("parameters", [])
            own_parameters = operation.get("parameters", [])
            if (
                not isinstance(shared_parameters, list)
                or not isinstance(own_parameters, list)
                or len(shared_parameters) + len(own_parameters) > 200
            ):
                raise ReportError("parameters must be bounded arrays")
            for parameter in shared_parameters + own_parameters:
                parameter = _resolve(parameter, schema)
                parameters.append(
                    {
                        "name": text(parameter.get("name"), "parameter", 128),
                        "in": text(parameter.get("in"), "parameter location", 32),
                        "required": parameter.get("required") is True,
                    }
                )
            parameters = list({(p["name"], p["in"]): p for p in parameters}.values())
            properties = {}
            responses = operation.get("responses", {})
            if not isinstance(responses, dict):
                raise ReportError("responses must be an object")
            for status, response in responses.items():
                response = _resolve(response, schema)
                content = response.get("content", {})
                if isinstance(content, dict) and "application/json" in content:
                    media = _resolve(content["application/json"], schema)
                    response_schema = _resolve(media.get("schema", {}), schema)
                    fields = response_schema.get("properties", {})
                    if not isinstance(fields, dict):
                        raise ReportError("response properties must be an object")
                    properties[str(status)] = sorted(
                        text(key, "property", 256) for key in fields
                    )
            operations.append(
                {
                    "method": method.upper(),
                    "path": path,
                    "operationId": text(
                        operation.get("operationId", f"{method} {path}"),
                        "operation id",
                        256,
                    ),
                    "securityAlternatives": security,
                    "anonymousDeclared": not security or {} in security,
                    "parameters": parameters,
                    "responseProperties": properties,
                }
            )
    return seal(
        {
            "schemaVersion": "whitehat-api-inventory-v1",
            "ok": True,
            "projectId": label(project, "project"),
            "schemaSha256": hashlib.sha256(canonical(schema)).hexdigest(),
            "operations": operations,
            "securitySemantics": "Alternatives are OR; schemes within each alternative are AND. Declarations do not prove enforcement.",
            "effects": {"network": False, "serverUrlsFollowed": False},
            "claims": dict(CLAIMS),
        }
    )


def inventory_schema(path: str, project: str) -> dict[str, Any]:
    return inventory_value(load_schema(path), project)


def compare_schema(
    before: str, after: str, project: str, tool_path: str | None = None
) -> dict[str, Any]:
    a, b = load_schema(before), load_schema(after)
    ai, bi = inventory_value(a, project), inventory_value(b, project)
    spec = TOOLS["oasdiff"]["platforms"][platform_key()]
    executable, _ = verify_tool(
        "oasdiff", tool_path or Path(".whitehat/tools/oasdiff") / spec["executable"]
    )

    def prepare(workspace: Path) -> None:
        (workspace / "before.json").write_bytes(canonical(a))
        (workspace / "after.json").write_bytes(canonical(b))
        (workspace / "config.yaml").write_text("{}\n", encoding="utf-8")

    execution = execute_fixed_profile(
        profile="api.oasdiff.changelog",
        executable=executable,
        prepare=prepare,
        arguments=lambda w: [
            "--config",
            str(w / "config.yaml"),
            "changelog",
            str(w / "before.json"),
            str(w / "after.json"),
            "--format",
            "json",
            "--allow-external-refs=false",
        ],
        limits=ProcessLimits(
            timeout_seconds=30, max_stdout_bytes=4 * 1024 * 1024, max_stderr_bytes=65536
        ),
    )
    verify_tool("oasdiff", executable)
    changes = parse_json(execution.stdout)
    if changes is None:
        changes = []
    if not isinstance(changes, list) or len(changes) > 5000:
        raise ReportError("invalid oasdiff result")
    observations = []
    for change in changes:
        if not isinstance(change, dict):
            raise ReportError("invalid API change")
        rule = text(change.get("id"), "change id", 128)
        observations.append(
            observation(
                "oasdiff",
                rule,
                category="api-contract-change",
                context={
                    "projectId": project,
                    "method": text(change.get("operation", "GLOBAL"), "method", 16),
                    "apiPath": text(change.get("path", "/"), "API path", 1024),
                },
                explanation="The API contract changed. Inspect the schema difference and actual server behavior; this is not proof of a vulnerability.",
            )
        )
    old = {(o["method"], o["path"]): o for o in ai["operations"]}
    for operation in bi["operations"]:
        prior = old.get((operation["method"], operation["path"]))
        if prior and prior["securityAlternatives"] != operation["securityAlternatives"]:
            observations.append(
                observation(
                    "whitehat-openapi",
                    "effective-security-changed",
                    category="api-contract-change",
                    context={
                        "projectId": project,
                        "method": operation["method"],
                        "apiPath": operation["path"],
                        "beforeSecurity": prior["securityAlternatives"],
                        "afterSecurity": operation["securityAlternatives"],
                    },
                    explanation="Effective authentication declarations changed after applying operation overrides. Verify enforcement on the authorized API.",
                )
            )
    return result_document(
        observations,
        {
            "kind": "api-diff",
            "projectId": project,
            "beforeSchemaSha256": ai["schemaSha256"],
            "afterSchemaSha256": bi["schemaSha256"],
            "tool": "oasdiff",
            "toolVersion": TOOLS["oasdiff"]["version"],
            "process": execution.receipt(),
            "executionVerified": True,
        },
        effects={"network": False, "processCreation": True, "workspaceCleaned": True},
    )


def coverage(
    schema_path: str,
    evidence_path: str | list[str],
    project: str,
    matrix_path: str | None = None,
    scenario_paths: list[str] | None = None,
) -> dict[str, Any]:
    inventory = inventory_schema(schema_path, project)
    paths = [evidence_path] if isinstance(evidence_path, str) else evidence_path
    if not isinstance(paths, list) or not 1 <= len(paths) <= 20:
        raise ReportError("coverage requires 1-20 evidence files")
    documents = [load_evidence(p) for p in paths]
    if any(d["projectId"] != project for d in documents):
        raise ReportError("schema/evidence project mismatch")
    from urllib.parse import urlsplit

    operations = inventory["operations"]
    seen = set()
    undocumented = []
    for entry in (entry for doc in documents for entry in doc["exchanges"]):
        context = entry["context"]
        path = urlsplit(context["endpoint"]).path
        matches = []
        for index, operation in enumerate(operations):
            pattern = re.sub(r"\\\{[^{}]+\\\}", "[^/]+", re.escape(operation["path"]))
            if context["method"] == operation["method"] and re.fullmatch(pattern, path):
                matches.append(index)
        if len(matches) == 1:
            seen.add(matches[0])
        else:
            undocumented.append(
                {
                    "method": context["method"],
                    "path": path,
                    "reason": "unmatched" if not matches else "ambiguous",
                }
            )
    access = []
    if matrix_path:
        from .http_evidence import assess_access

        assessment = assess_access(matrix_path, paths)
        matrix = parse_json(read_bytes(Path(matrix_path), 256 * 1024))
        rows = {r["id"]: r for r in matrix["rows"]}
        for evaluation in assessment["provenance"]["evaluations"]:
            row = rows[evaluation["rowId"]]
            access.append(
                {
                    **evaluation,
                    **{
                        k: row[k]
                        for k in (
                            "identityId",
                            "objectId",
                            "operationId",
                            "method",
                            "endpoint",
                        )
                    },
                }
            )
    scenario_coverage = _scenario_coverage(scenario_paths or [], documents, project)
    return seal(
        {
            "schemaVersion": "whitehat-api-coverage-v1",
            "ok": True,
            "projectId": project,
            "observedOperations": [operations[i] for i in sorted(seen)],
            "unobservedOperations": [
                op for i, op in enumerate(operations) if i not in seen
            ],
            "undocumentedRequests": undocumented,
            "accessCases": access,
            "scenarios": scenario_coverage,
            "evidenceResults": sorted({d["resultSha256"] for d in documents}),
            "interpretation": "Route observation is not authorization or state-transition coverage. Access and scenario outcomes refer only to supplied explicit expectations.",
            "claims": dict(CLAIMS),
            "effects": {"network": False},
        }
    )


def _scenario_coverage(
    paths: list[str], documents: list[dict], project: str
) -> list[dict]:
    from .evidence_links import contained_path, fields
    from .http_evidence import digest, label
    from .http_replay import prepared_request

    if len(paths) > 20:
        raise ReportError("coverage supports at most 20 scenario plans")
    result = []
    for path in paths:
        source = Path(path)
        plan = fields(
            parse_json(read_bytes(source, 256 * 1024)),
            {"schemaVersion", "projectId", "steps"},
            "scenario plan",
        )
        if (
            plan["schemaVersion"] != "whitehat-http-scenario-v1"
            or plan["projectId"] != project
        ):
            raise ReportError("coverage scenario schema/project mismatch")
        if not isinstance(plan["steps"], list) or not 1 <= len(plan["steps"]) <= 20:
            raise ReportError("coverage scenario requires 1-20 steps")
        step_ids, prepared_requests = [], []
        for step in plan["steps"]:
            fields(step, {"id", "request", "identityId", "expect"}, "scenario step")
            step_ids.append(label(step["id"], "step"))
            label(step["identityId"], "identity")
            prepared_requests.append(
                prepared_request(
                    parse_json(
                        read_bytes(
                            contained_path(source.parent, step["request"]), 128 * 1024
                        )
                    )
                )
            )
        if len(step_ids) != len(set(step_ids)):
            raise ReportError("duplicate scenario step ID")
        matched = [
            d
            for d in documents
            if d.get("provenance", {}).get("profile") == "explicit-scenario"
            and d["provenance"].get("scenarioSha256") == digest(plan)
        ]
        compatible, incompatible = [], []
        for document in matched:
            if document["provenance"]["plannedSteps"] != len(step_ids) or len(document["exchanges"]) > len(step_ids):
                raise ReportError("scenario receipt counts differ from its plan")
            matches_requests = True
            for index, entry in enumerate(document["exchanges"]):
                request = prepared_requests[index]
                context = entry["context"]
                if (
                    any(
                        context[k] != request[k]
                        for k in ("method", "objectId", "operationId")
                    )
                    or context["identityId"] != plan["steps"][index]["identityId"]
                    or entry["request"]["urlSha256"]
                    != hashlib.sha256(request["url"].encode("utf-8")).hexdigest()
                    or entry["request"]["bodySha256"]
                    != hashlib.sha256(
                        (request["body"] or "").encode("utf-8")
                    ).hexdigest()
                ):
                    matches_requests = False
            (compatible if matches_requests else incompatible).append(document)
        matched = compatible
        steps = []
        for step_id in step_ids:
            evaluations = []
            for document in matched:
                known = {e["evidenceSha256"] for e in document["exchanges"]}
                entries = document["provenance"].get("evaluations", [])
                if not isinstance(entries, list) or len(entries) > len(step_ids):
                    raise ReportError("invalid scenario evaluations")
                for index, evaluation in enumerate(entries):
                    fields(
                        evaluation,
                        {"stepId", "outcome", "evidenceSha256"},
                        "scenario evaluation",
                    )
                    if (
                        evaluation["stepId"] != step_ids[index]
                        or evaluation["evidenceSha256"] not in known
                        or evaluation["outcome"] not in {"consistent", "mismatch"}
                    ):
                        raise ReportError(
                            "scenario receipt does not match plan/evidence"
                        )
                    if evaluation["stepId"] == step_id:
                        evaluations.append(evaluation)
            outcomes = {e["outcome"] for e in evaluations}
            outcome = (
                "not-tested"
                if not outcomes
                else "conflicting"
                if len(outcomes) > 1
                else next(iter(outcomes))
            )
            steps.append(
                {
                    "stepId": step_id,
                    "outcome": outcome,
                    "evidenceSha256": sorted(
                        {e["evidenceSha256"] for e in evaluations}
                    ),
                }
            )
        transitions = []
        for index in range(1, len(step_ids)):
            receipts = [
                d["resultSha256"]
                for d in matched
                if len(d["provenance"]["evaluations"]) > index
            ]
            transitions.append(
                {
                    "from": step_ids[index - 1],
                    "to": step_ids[index],
                    "outcome": "observed" if receipts else "not-tested",
                    "evidenceResults": sorted(set(receipts)),
                }
            )
        result.append(
            {
                "scenarioSha256": digest(plan),
                "steps": steps,
                "transitions": transitions,
                "notComparableResults": sorted(
                    {d["resultSha256"] for d in incompatible}
                ),
            }
        )
    return result
