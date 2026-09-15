"""Deterministic boundary/Hypothesis generation into reviewable request batches."""

from __future__ import annotations

import copy
import importlib.metadata
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .evidence_links import fields
from .fuzz_contracts import (
    BATCH_SCHEMA,
    CASE_SCHEMA,
    PLAN_SCHEMA,
    assertions,
    bundle_case,
    embedded_step,
    expectation,
    integer,
    json_file,
    write_tree,
)
from .http_evidence import digest, label, pointers
from .http_replay import prepared_request
from .preparation import _SENSITIVE, _private_fields, session_draft
from .records import write_json_document
from .reports import ReportError, canonical, parse_json, seal

HYPOTHESIS_VERSION = "6.168.0"


def scalar_schema(value: dict) -> dict:
    if not isinstance(value, dict) or set(value) - {
        "type",
        "enum",
        "minimum",
        "maximum",
        "minLength",
        "maxLength",
    }:
        raise ReportError(
            "first mutation profile supports bounded scalar schema keywords only"
        )
    if value.get("type") not in ("string", "integer", "number", "boolean"):
        raise ReportError("mutation schema needs a scalar type")
    for key in ("minimum", "maximum"):
        if key in value and (
            type(value[key]) not in (int, float)
            or not -1000000 <= value[key] <= 1000000
        ):
            raise ReportError("numeric mutation bounds exceed the supported range")
    if value.get("minimum", -1000000) > value.get("maximum", 1000000):
        raise ReportError("schema minimum exceeds maximum")
    if value["type"] == "integer":
        import math

        if math.ceil(value.get("minimum", -1000000)) > math.floor(
            value.get("maximum", 1000000)
        ):
            raise ReportError("integer schema has no representable value")
    for key in ("minLength", "maxLength"):
        if key in value:
            integer(value[key], key, 0, 128)
    if value.get("minLength", 0) > value.get("maxLength", 128):
        raise ReportError("schema minimum length exceeds maximum")
    if "enum" in value and (
        not isinstance(value["enum"], list) or not 1 <= len(value["enum"]) <= 20
    ):
        raise ReportError("enum requires 1-20 values")
    for item in value.get("enum", []):
        if isinstance(item, (dict, list)) or len(canonical(item)) > 256:
            raise ReportError("enum values must be bounded scalars")
    return value


def valid_scalar(value, schema: dict) -> bool:
    kind = schema["type"]
    if not {
        "integer": type(value) is int,
        "number": type(value) in (int, float),
        "string": isinstance(value, str),
        "boolean": type(value) is bool,
    }[kind]:
        return False
    if "enum" in schema and digest(value) not in {digest(v) for v in schema["enum"]}:
        return False
    if kind in ("integer", "number"):
        return (
            schema.get("minimum", float("-inf"))
            <= value
            <= schema.get("maximum", float("inf"))
        )
    if kind == "string":
        return schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", 128)
    return True


def boundary_values(schema: dict) -> list:
    values = [None, False, True, 0, "", [], {}]
    values.extend(schema.get("enum", []))
    if schema["type"] in ("integer", "number"):
        low, high = schema.get("minimum", 0), schema.get("maximum", 10)
        values.extend([low - 1, low, low + 1, high - 1, high, high + 1])
    elif schema["type"] == "string":
        low, high = schema.get("minLength", 0), schema.get("maxLength", 16)
        values.extend(
            "a" * n
            for n in sorted({max(0, low - 1), low, low + 1, high, min(129, high + 1)})
        )
        values.extend(["é", "e\u0301"])
    return list({digest(v): v for v in values}.values())


def hypothesis_samples(schema: dict, count: int, seed: int) -> list:
    if count == 0:
        return []
    try:
        version = importlib.metadata.version("hypothesis")
    except importlib.metadata.PackageNotFoundError as exc:
        raise ReportError("install the fuzz extra for Hypothesis sampling") from exc
    if version != HYPOTHESIS_VERSION:
        raise ReportError(f"Hypothesis must be exactly {HYPOTHESIS_VERSION}")
    from hypothesis import Phase, given, seed as seeded, settings
    from hypothesis import strategies as st

    if "enum" in schema:
        strategy = st.sampled_from(schema["enum"])
    elif schema["type"] == "integer":
        import math

        strategy = st.integers(
            math.ceil(schema.get("minimum", 0)), math.floor(schema.get("maximum", 100))
        )
    elif schema["type"] == "number":
        strategy = st.floats(
            min_value=schema.get("minimum", 0),
            max_value=schema.get("maximum", 100),
            allow_nan=False,
            allow_infinity=False,
        )
    elif schema["type"] == "boolean":
        strategy = st.booleans()
    else:
        strategy = st.text(
            alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-é",
            min_size=schema.get("minLength", 0),
            max_size=schema.get("maxLength", 32),
        )
    values = []

    @seeded(seed)
    @settings(max_examples=count, database=None, deadline=None, phases=[Phase.generate])
    @given(strategy)
    def collect(value):
        values.append(value)

    collect()
    return list({digest(v): v for v in values}.values())


def _schema_fields(schema: dict, prefix: str = "", depth: int = 0) -> list[dict]:
    if (
        not isinstance(schema, dict)
        or not isinstance(schema.get("properties", {}), dict)
        or not isinstance(schema.get("required", []), list)
    ):
        raise ReportError("invalid object schema properties/required fields")
    if depth > 5:
        raise ReportError("schema field nesting exceeds five levels")
    result = []
    for name, item in schema.get("properties", {}).items():
        if not isinstance(item, dict):
            raise ReportError("invalid property schema")
        if _SENSITIVE.search(name):
            continue
        pointer = prefix + "/" + name.replace("~", "~0").replace("/", "~1")
        if item.get("type") == "object":
            result.extend(_schema_fields(item, pointer, depth + 1))
        elif item.get("type") in ("string", "integer", "number", "boolean"):
            allowed = {
                k: item[k]
                for k in (
                    "type",
                    "enum",
                    "minimum",
                    "maximum",
                    "minLength",
                    "maxLength",
                )
                if k in item
            }
            # Do not silently erase validation semantics of unsupported keywords.
            omitted = sorted(
                set(item)
                - set(allowed)
                - {
                    "description",
                    "title",
                    "example",
                    "default",
                    "readOnly",
                    "writeOnly",
                    "deprecated",
                }
            )
            result.append(
                {
                    "location": "json",
                    "pointer": pointer,
                    "schema": scalar_schema(allowed),
                    "values": [],
                    "omit": name in schema.get("required", []),
                    "unsupportedSchemaKeywords": omitted,
                }
            )
    return result


def initialize_plan(
    request_path: str,
    output: str,
    project: str,
    identity: str,
    seed: int = 1,
    schema_path: str | None = None,
) -> dict:
    request = prepared_request(json_file(Path(request_path), 128 * 1024))
    _private_fields(request)
    mutations = []
    provenance = {"requestSha256": digest(request), "schemaSha256": None}
    if schema_path:
        from .api_schema import _resolve, load_schema

        schema = load_schema(schema_path)
        provenance["schemaSha256"] = digest(schema)
        path = urlsplit(request["url"]).path
        matches = [
            (route, item)
            for route, item in schema.get("paths", {}).items()
            if re.fullmatch(re.sub(r"\\\{[^{}]+\\\}", "[^/]+", re.escape(route)), path)
            and request["method"].lower() in item
        ]
        if len(matches) != 1:
            raise ReportError("prepared request must match one schema operation")
        item = _resolve(matches[0][1], schema)
        operation = item[request["method"].lower()]
        body = (
            _resolve(operation.get("requestBody", {}), schema)
            .get("content", {})
            .get("application/json", {})
            .get("schema", {})
        )
        mutations.extend(_schema_fields(_resolve(body, schema)))
        parameters = {}
        for parameter in item.get("parameters", []) + operation.get("parameters", []):
            parameter = _resolve(parameter, schema)
            parameters[(parameter.get("in"), parameter.get("name"))] = parameter
        for (location, name), parameter in parameters.items():
            if location == "query" and not _SENSITIVE.search(name):
                spec = _resolve(parameter.get("schema", {}), schema)
                if spec.get("type") in ("string", "integer", "number", "boolean"):
                    allowed = {
                        k: spec[k]
                        for k in (
                            "type",
                            "enum",
                            "minimum",
                            "maximum",
                            "minLength",
                            "maxLength",
                        )
                        if k in spec
                    }
                    mutations.append(
                        {
                            "location": "query",
                            "pointer": name,
                            "schema": scalar_schema(allowed),
                            "values": [],
                            "omit": bool(parameter.get("required")),
                            "unsupportedSchemaKeywords": sorted(
                                set(spec)
                                - set(allowed)
                                - {"description", "example", "default"}
                            ),
                        }
                    )
    else:
        if request["body"] is not None:
            body = parse_json(request["body"].encode("utf-8"))

            def infer(value):
                if isinstance(value, dict):
                    return {
                        "type": "object",
                        "properties": {k: infer(v) for k, v in value.items()},
                    }
                return {
                    "type": "boolean"
                    if type(value) is bool
                    else "integer"
                    if type(value) is int
                    else "number"
                    if type(value) is float
                    else "string"
                }

            mutations.extend(_schema_fields(infer(body)))
        for name, _ in parse_qsl(
            urlsplit(request["url"]).query, keep_blank_values=True, max_num_fields=100
        ):
            if not _SENSITIVE.search(name):
                mutations.append(
                    {
                        "location": "query",
                        "pointer": name,
                        "schema": {"type": "string", "maxLength": 32},
                        "values": [],
                        "omit": True,
                        "unsupportedSchemaKeywords": [],
                    }
                )
    if not 1 <= len(mutations) <= 16:
        raise ReportError(
            "select a request with 1-16 scalar body/query fields, or author a mutation plan"
        )
    plan = {
        "schemaVersion": PLAN_SCHEMA,
        "projectId": label(project, "project"),
        "identityId": label(identity, "identity"),
        "seed": integer(seed, "seed", 0, 2**32 - 1),
        "maxCases": 20,
        "samplesPerField": 4,
        "request": request,
        "mutations": mutations,
        "setup": [],
        "readback": [],
        "reset": [],
        "assertions": [],
        "positiveStatuses": [200, 201, 204],
        "negativeStatuses": [400, 422],
        "provenance": provenance,
    }
    write_json_document(plan, output)
    return seal(
        {
            "schemaVersion": "whitehat-fuzz-preparation-v1",
            "ok": True,
            "projectId": project,
            "planSha256": digest(plan),
            "fields": len(mutations),
            "effects": {"network": False, "filesystemWrite": True},
        }
    )


def mutate(
    request: dict, location: str, pointer: str, value, omit: bool = False
) -> dict:
    result = copy.deepcopy(request)
    if _SENSITIVE.search(pointer):
        raise ReportError("credential-like fields cannot be fuzz mutation slots")
    if location == "json":
        pointers([pointer])
        body = parse_json((result["body"] or "").encode("utf-8"))
        components = [
            p.replace("~1", "/").replace("~0", "~") for p in pointer[1:].split("/")
        ]
        current = body
        for component in components[:-1]:
            if not isinstance(current, dict) or component not in current:
                raise ReportError("mutation parent pointer does not exist")
            current = current[component]
        if not isinstance(current, dict):
            raise ReportError("JSON mutations target object properties")
        if omit:
            current.pop(components[-1], None)
        else:
            current[components[-1]] = value
        result["body"] = canonical(body).decode("utf-8")
    elif location == "query":
        if not isinstance(pointer, str) or not re.fullmatch(
            r"[A-Za-z0-9_.-]{1,100}", pointer
        ):
            raise ReportError("query mutation needs one ordinary parameter name")
        parsed = urlsplit(result["url"])
        pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=100)
        if len([k for k, _ in pairs if k == pointer]) > 1:
            raise ReportError(
                "duplicate query parameters require a separate representation profile"
            )
        pairs = [(k, v) for k, v in pairs if k != pointer]
        if not omit:
            pairs.append(
                (
                    pointer,
                    value
                    if isinstance(value, str)
                    else canonical(value).decode("utf-8"),
                )
            )
        result["url"] = urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, urlencode(pairs), "")
        )
    else:
        raise ReportError("mutation location must be json or query")
    prepared_request(result)
    _private_fields(result)
    return result


def write_batch(
    directory: str, project: str, cases: list[dict], provenance: dict
) -> dict:
    documents, references, hashes, identities = {}, [], [], {}
    total = 0
    for value in cases:
        case = bundle_case(value, documents)
        name = "case-" + case["id"] + ".json"
        if name in documents:
            raise ReportError("duplicate generated case ID")
        documents[name] = case
        references.append({"path": name, "caseSha256": digest(case)})
        seen = set()
        for phase in ("setup", "steps", "reset"):
            for step in case[phase]:
                if step["id"] in seen:
                    raise ReportError("duplicate generated step ID")
                seen.add(step["id"])
                hashes.append(step["requestSha256"])
                identities[step["identityId"]] = {
                    "id": step["identityId"],
                    "auth": "none",
                    "credentialEnv": None,
                }
                total += 1
        assertions(case["assertions"], {s["id"] for s in case["setup"] + case["steps"]})
    if not 1 <= len(cases) <= 32 or total > 100 or len(identities) > 10:
        raise ReportError("batch exceeds case/request/identity limits")
    batch = {
        "schemaVersion": BATCH_SCHEMA,
        "projectId": project,
        "cases": references,
        "provenance": provenance,
    }
    requests = [
        v
        for v in documents.values()
        if v.get("schemaVersion") == "whitehat-prepared-request-v1"
    ]
    origins = {(urlsplit(r["url"]).scheme, urlsplit(r["url"]).netloc) for r in requests}
    if len(origins) != 1:
        raise ReportError("batch requests must share an exact origin")
    draft = session_draft(requests[0], project, next(iter(identities)))
    draft["requestSha256"] = sorted(set(hashes))
    draft["identities"] = list(identities.values())
    draft["budgets"]["maxRequests"] = total
    selected = set()
    for case in cases:
        for step in case["setup"] + case["steps"] + case["reset"]:
            selected.update(step["expect"]["values"])
            selected.update(step["expect"]["absent"])
        for rule in case["assertions"]:
            selected.add(rule["left"]["pointer"])
            if rule["right"]:
                selected.add(rule["right"]["pointer"])
    draft["responsePointers"] = pointers(sorted(selected))
    documents.update({"batch.json": batch, "session.draft.json": draft})
    write_tree(directory, documents)
    return seal(
        {
            "schemaVersion": "whitehat-fuzz-preparation-v1",
            "ok": True,
            "projectId": project,
            "batchSha256": digest(batch),
            "cases": len(cases),
            "plannedRequests": total,
            "effects": {
                "network": False,
                "filesystemWrite": True,
                "sessionApproved": False,
            },
        }
    )


def generate_plan(path: str, directory: str) -> dict:
    plan = json_file(Path(path))
    fields(
        plan,
        {
            "schemaVersion",
            "projectId",
            "identityId",
            "seed",
            "maxCases",
            "samplesPerField",
            "request",
            "mutations",
            "setup",
            "readback",
            "reset",
            "assertions",
            "positiveStatuses",
            "negativeStatuses",
            "provenance",
        },
        "mutation plan",
    )
    if plan["schemaVersion"] != PLAN_SCHEMA:
        raise ReportError("unsupported mutation plan")
    if not isinstance(plan["provenance"], dict):
        raise ReportError("invalid mutation plan provenance")
    operation = plan["provenance"].get("graphqlOperation")
    if operation is not None and (
        not isinstance(operation, dict)
        or not isinstance(operation.get("variables"), dict)
        or any(not isinstance(v, str) for v in operation.get("variables", {}).values())
    ):
        raise ReportError("invalid GraphQL variable metadata")
    project, identity = (
        label(plan["projectId"], "project"),
        label(plan["identityId"], "identity"),
    )
    seed = integer(plan["seed"], "seed", 0, 2**32 - 1)
    maximum = integer(plan["maxCases"], "maxCases", 1, 32)
    samples = integer(plan["samplesPerField"], "samplesPerField", 0, 16)
    request = prepared_request(plan["request"])
    _private_fields(request)
    for phase in ("setup", "readback", "reset"):
        if not isinstance(plan[phase], list) or len(plan[phase]) > 10:
            raise ReportError("setup/reset requires bounded explicit steps")
        for step in plan[phase]:
            embedded_step(step)
    for key in ("positiveStatuses", "negativeStatuses"):
        expectation({"statuses": plan[key], "values": {}, "absent": []})
    mutations = plan["mutations"]
    if not isinstance(mutations, list) or not 1 <= len(mutations) <= 16:
        raise ReportError("plan requires 1-16 mutation slots")
    candidates = [(request, {"kind": "baseline"}, True)]
    rounds = []
    for index, mutation in enumerate(mutations):
        fields(
            mutation,
            {
                "location",
                "pointer",
                "schema",
                "values",
                "omit",
                "unsupportedSchemaKeywords",
            },
            "mutation slot",
        )
        spec = scalar_schema(mutation["schema"])
        if mutation["location"] == "json":
            from .http_evidence import _pointer

            pointers([mutation["pointer"]])
            found, baseline_value = _pointer(
                parse_json((request["body"] or "").encode("utf-8")), mutation["pointer"]
            )
        elif mutation["location"] == "query":
            values_in_seed = [
                v
                for k, v in parse_qsl(
                    urlsplit(request["url"]).query,
                    keep_blank_values=True,
                    max_num_fields=100,
                )
                if k == mutation["pointer"]
            ]
            found, baseline_value = (
                bool(values_in_seed),
                values_in_seed[0] if values_in_seed else None,
            )
        else:
            raise ReportError("mutation location must be json or query")
        if (found and not _valid_mutation(baseline_value, spec, mutation, plan)) or (
            not found and mutation["omit"] is True
        ):
            raise ReportError(
                "seed does not satisfy the selected scalar projection; choose a valid baseline or author an explicit case"
            )
        if mutation["unsupportedSchemaKeywords"]:
            raise ReportError(
                "review unsupported schema keywords before generating from this projection"
            )
        if (
            type(mutation["omit"]) is not bool
            or not isinstance(mutation["values"], list)
            or len(mutation["values"]) > 20
        ):
            raise ReportError("invalid explicit mutation values")
        values = (
            boundary_values(spec)
            + hypothesis_samples(spec, samples, seed + index)
            + mutation["values"]
        )
        if any(len(canonical(value)) > 2048 for value in values):
            raise ReportError("mutation value size exceeded")
        variants = [
            (
                mutate(request, mutation["location"], mutation["pointer"], value),
                {
                    "kind": "replace",
                    "location": mutation["location"],
                    "pointer": mutation["pointer"],
                    "valueSha256": digest(value),
                },
                _valid_mutation(value, spec, mutation, plan),
            )
            for value in values
        ]
        if mutation["omit"]:
            variants.insert(
                0,
                (
                    mutate(
                        request, mutation["location"], mutation["pointer"], None, True
                    ),
                    {
                        "kind": "omit",
                        "location": mutation["location"],
                        "pointer": mutation["pointer"],
                    },
                    False,
                ),
            )
        rounds.append(variants)
    # Round robin prevents a single field consuming the complete case budget.
    for index in range(max(len(v) for v in rounds)):
        for variants in rounds:
            if index < len(variants):
                candidates.append(variants[index])
    cases, seen = [], set()
    for mutated, mutation, valid in candidates:
        if digest(mutated) in seen:
            continue
        seen.add(digest(mutated))
        case = {
            "schemaVersion": CASE_SCHEMA,
            "projectId": project,
            "id": f"generated-{len(cases):03d}",
            "setup": copy.deepcopy(plan["setup"]),
            "steps": [
                {
                    "id": "test",
                    "request": mutated,
                    "identityId": identity,
                    "expect": {
                        "statuses": plan["positiveStatuses"]
                        if valid
                        else plan["negativeStatuses"],
                        "values": {},
                        "absent": [],
                    },
                }
            ]
            + copy.deepcopy(plan["readback"]),
            "reset": copy.deepcopy(plan["reset"]),
            "assertions": copy.deepcopy(plan["assertions"]),
            "lineage": {
                "planSha256": digest(plan),
                "seed": seed,
                "engine": "whitehat-boundary-v1",
                "hypothesisVersion": HYPOTHESIS_VERSION if samples else None,
                "mutation": mutation,
                "dataMode": "positive" if valid else "negative",
            },
        }
        if plan["provenance"].get("graphqlOperation"):
            case["assertions"].append(
                {
                    "id": "graphql-input-errors",
                    "relation": "absent" if valid else "present",
                    "left": {
                        "stepId": "test",
                        "pointer": "/errors/0/message",
                        "identityId": identity,
                        "objectId": mutated["objectId"],
                    },
                    "right": None,
                    "value": None,
                }
            )
        cases.append(case)
        if len(cases) == maximum:
            break
    return write_batch(
        directory,
        project,
        cases,
        {
            "kind": "mutation-generation",
            "planSha256": digest(plan),
            "seed": seed,
            "candidateRequests": len(seen),
            "maxCases": maximum,
        },
    )


def _valid_mutation(value, spec: dict, mutation: dict, plan: dict) -> bool:
    if mutation["location"] == "query":
        import math

        wire = value if isinstance(value, str) else canonical(value).decode("utf-8")
        if spec["type"] == "integer":
            if not re.fullmatch(r"[+-]?[0-9]{1,20}", wire):
                return False
            value = int(wire)
        elif spec["type"] == "number":
            try:
                value = float(wire)
            except ValueError:
                return False
            if not math.isfinite(value):
                return False
        elif spec["type"] == "boolean":
            if wire not in ("true", "false"):
                return False
            value = wire == "true"
        else:
            value = wire
    operation = plan["provenance"].get("graphqlOperation")
    if not operation:
        return valid_scalar(value, spec)
    name = mutation["pointer"].removeprefix("/variables/")
    declared = operation["variables"].get(name, "")
    if value is None:
        return not declared.endswith("!")
    if declared.rstrip("!") == "ID":
        return type(value) in (str, int)
    if declared.rstrip("!") == "Int":
        return type(value) is int and -(2**31) <= value < 2**31
    return valid_scalar(value, spec)
