"""Offline GraphQL inventory, operation identity and variable mutation plans."""

from __future__ import annotations

import copy
import hashlib
import importlib.metadata
from enum import Enum
from pathlib import Path

from .fuzz_contracts import PLAN_SCHEMA, json_file
from .fuzz_generation import mutation_schema
from .http_evidence import capture_entries, digest, evidence_document, exchange, label
from .http_replay import prepared_request
from .preparation import _SENSITIVE, _private_fields
from .records import write_json_document
from .reports import CLAIMS, ReportError, parse_json, read_bytes, seal

GRAPHQL_VERSION = "3.2.12"


def graphql_module():
    try:
        if importlib.metadata.version("graphql-core") != GRAPHQL_VERSION:
            raise ReportError(f"graphql-core must be exactly {GRAPHQL_VERSION}")
    except importlib.metadata.PackageNotFoundError as exc:
        raise ReportError("install the graphql extra for GraphQL analysis") from exc
    import graphql

    return graphql


def _bounded_ast(node, count=None, depth=0):
    count = count if count is not None else [0]
    if depth > 40 or count[0] > 5000:
        raise ReportError("GraphQL AST depth/node limit exceeded")
    if isinstance(node, (tuple, list)):
        for child in node:
            _bounded_ast(child, count, depth + 1)
    elif hasattr(node, "keys") and not isinstance(node, dict):
        count[0] += 1
        for key in node.keys:
            if key != "loc":
                _bounded_ast(getattr(node, key, None), count, depth + 1)


def load_graphql_schema(path: str):
    gql = graphql_module()
    raw = read_bytes(Path(path), 2 * 1024 * 1024)
    try:
        if Path(path).suffix.lower() == ".json":
            value = parse_json(raw)
            if not isinstance(value, dict):
                raise ReportError("expected introspection JSON object")
            value = value.get("data", value)

            # Explicitly bound recursive introspection metadata before library construction.
            def walk(node, depth=0, count=None):
                count = count if count is not None else [0]
                count[0] += 1
                if depth > 40 or count[0] > 20000:
                    raise ReportError("introspection size/depth exceeded")
                if isinstance(node, dict):
                    for child in node.values():
                        walk(child, depth + 1, count)
                elif isinstance(node, list):
                    for child in node:
                        walk(child, depth + 1, count)

            walk(value)
            schema = gql.build_client_schema(value)
        else:
            document = gql.parse(raw.decode("utf-8"), max_tokens=5000)
            _bounded_ast(document)
            schema = gql.build_ast_schema(document)
        if gql.validate_schema(schema):
            raise ReportError("GraphQL schema validation failed")
    except (ValueError, TypeError, KeyError, RecursionError, gql.GraphQLError) as exc:
        raise ReportError("invalid or unsupported GraphQL schema") from exc
    return schema, hashlib.sha256(raw).hexdigest()


def graphql_inventory(path: str, project: str) -> dict:
    schema, schema_hash = load_graphql_schema(path)
    operations = []
    for kind in ("query", "mutation", "subscription"):
        root = getattr(schema, kind + "_type")
        if root:
            for name, field in sorted(root.fields.items()):
                operations.append(
                    {
                        "kind": kind,
                        "field": name,
                        "type": str(field.type),
                        "arguments": {
                            key: str(argument.type)
                            for key, argument in sorted(field.args.items())
                        },
                    }
                )
    return seal(
        {
            "schemaVersion": "whitehat-graphql-inventory-v1",
            "ok": True,
            "projectId": label(project, "project"),
            "schemaSha256": schema_hash,
            "graphqlCoreVersion": GRAPHQL_VERSION,
            "operations": operations,
            "claims": dict(CLAIMS),
            "effects": {"network": False},
        }
    )


def _operation(schema, source: str, operation_name: str | None = None) -> dict:
    gql = graphql_module()
    if not isinstance(source, str) or len(source.encode("utf-8")) > 65536:
        raise ReportError("GraphQL document exceeds 64 KiB")
    try:
        document = gql.parse(source, max_tokens=2000)
        _bounded_ast(document)
        if gql.validate(schema, document, max_errors=10):
            raise ReportError(
                "GraphQL operation does not validate against supplied schema"
            )
        selected = gql.get_operation_ast(document, operation_name)
        if selected is None or selected.operation.value == "subscription":
            raise ReportError(
                "select one query/mutation; subscriptions require another profile"
            )
    except (gql.GraphQLError, RecursionError) as exc:
        raise ReportError("invalid GraphQL operation document") from exc
    fragments = {
        n.name.value: n
        for n in document.definitions
        if isinstance(n, gql.FragmentDefinitionNode)
    }
    paths = []

    def fields_in(selection, prefix="", depth=0):
        if depth > 30 or len(paths) > 1000:
            raise ReportError("GraphQL expansion limit exceeded")
        for field in selection.selections:
            if isinstance(field, gql.FieldNode):
                path = prefix + "/" + field.name.value
                paths.append(
                    {
                        "fieldPath": path,
                        "responseName": field.alias.value
                        if field.alias
                        else field.name.value,
                    }
                )
                if field.selection_set:
                    fields_in(field.selection_set, path, depth + 1)
            elif isinstance(field, gql.FragmentSpreadNode):
                fields_in(fragments[field.name.value].selection_set, prefix, depth + 1)
            elif isinstance(field, gql.InlineFragmentNode):
                fields_in(field.selection_set, prefix, depth + 1)

    fields_in(selected.selection_set)

    # AST kinds and field/variable names identify structure; literal values are hashed
    # only in request evidence, never retained in this operation metadata.
    def structure(node):
        if isinstance(node, Enum):
            return node.value
        if isinstance(node, (tuple, list)):
            return [structure(n) for n in node]
        if hasattr(node, "kind"):
            if node.kind in (
                "string_value",
                "int_value",
                "float_value",
                "boolean_value",
                "enum_value",
                "null_value",
            ):
                return {"kind": node.kind}
            return {
                "kind": node.kind,
                **{
                    key: structure(getattr(node, key, None))
                    for key in node.keys
                    if key != "loc"
                },
            }
        return node

    fingerprint = digest(
        {
            "operation": structure(selected),
            "fragments": {
                name: structure(node) for name, node in sorted(fragments.items())
            },
        }
    )
    return {
        "operationId": "graphql-" + fingerprint[:24],
        "name": selected.name.value if selected.name else "anonymous",
        "kind": selected.operation.value,
        "structureSha256": fingerprint,
        "fields": paths,
        "variables": {
            v.variable.name.value: gql.print_ast(v.type)
            for v in selected.variable_definitions
        },
        "requiredVariables": [
            v.variable.name.value
            for v in selected.variable_definitions
            if isinstance(v.type, gql.NonNullTypeNode) and v.default_value is None
        ],
    }


def inspect_operation(
    schema_path: str, document_path: str, project: str, name: str | None = None
) -> dict:
    schema, schema_hash = load_graphql_schema(schema_path)
    raw = read_bytes(Path(document_path), 65536)
    try:
        source = raw.decode("utf-8")
    except UnicodeError as exc:
        raise ReportError("GraphQL document must be UTF-8") from exc
    return seal(
        {
            "schemaVersion": "whitehat-graphql-operation-v1",
            "ok": True,
            "projectId": label(project, "project"),
            "schemaSha256": schema_hash,
            "documentSha256": hashlib.sha256(raw).hexdigest(),
            "operation": _operation(schema, source, name),
            "claims": dict(CLAIMS),
            "effects": {"network": False},
        }
    )


def import_graphql_capture(
    schema_path: str,
    capture_path: str,
    project: str,
    selected: list[str],
    identity: str,
    object_id: str,
) -> dict:
    schema, schema_hash = load_graphql_schema(schema_path)
    raw = read_bytes(Path(capture_path), 8 * 1024 * 1024)
    entries = capture_entries(raw)
    if len(entries) > 100:
        raise ReportError("GraphQL import supports at most 100 exchanges")
    records, operations = [], []
    for index, item in enumerate(entries):
        request = item["request"]
        if request.get("method") != "POST":
            raise ReportError("first GraphQL capture profile requires POST JSON")
        body = request.get("postData", {}).get("text")
        if not isinstance(body, str):
            raise ReportError("GraphQL request body was not captured")
        value = parse_json(body.encode("utf-8"))
        if (
            not isinstance(value, dict)
            or set(value) - {"query", "variables", "operationName"}
            or not isinstance(value.get("query"), str)
        ):
            raise ReportError(
                "GraphQL batches and persisted-query-only inputs are unsupported"
            )
        operation = _operation(schema, value["query"], value.get("operationName"))
        binding = item.get("_whitehat", {})
        if not isinstance(binding, dict) or set(binding) - {
            "identityId",
            "objectId",
            "operationId",
        }:
            raise ReportError("invalid GraphQL capture labels")
        record = exchange(
            project,
            request,
            item.get("response") or {},
            identity=binding.get("identityId", identity),
            object_id=binding.get("objectId", object_id),
            operation=operation["operationId"],
            selected=selected,
        )
        records.append(record)
        operations.append({"entryIndex": index, **operation})
    return evidence_document(
        project,
        records,
        {
            "kind": "import",
            "format": "graphql-har",
            "schemaSha256": schema_hash,
            "captureSha256": hashlib.sha256(raw).hexdigest(),
            "graphqlCoreVersion": GRAPHQL_VERSION,
            "operations": operations,
            "executionVerified": False,
            "identityBinding": "operator-asserted",
        },
    )


def _input_projection(gql, declared, depth=0, seen=(), count=None):
    count = [0] if count is None else count
    count[0] += 1
    if depth > 5 or count[0] > 32:
        raise ReportError("GraphQL input projection exceeds five levels or 32 nodes")
    nullable = not isinstance(declared, gql.GraphQLNonNull)
    value = declared.of_type if not nullable else declared
    if isinstance(value, gql.GraphQLList):
        item = _input_projection(gql, value.of_type, depth + 1, seen, count)
        if item["type"] in ("array", "object"):
            raise ReportError("GraphQL lists currently require scalar or enum items")
        return {
            "type": "array",
            "items": item,
            "graphqlType": "list",
            "nullable": nullable,
        }
    if isinstance(value, gql.GraphQLInputObjectType):
        if value.name in seen or getattr(value, "is_one_of", False):
            raise ReportError(
                "recursive or oneOf input objects require a separate strategy"
            )
        properties = {
            name: _input_projection(
                gql, field.type, depth + 1, (*seen, value.name), count
            )
            for name, field in value.fields.items()
        }
        required = [
            name
            for name, field in value.fields.items()
            if isinstance(field.type, gql.GraphQLNonNull)
            and field.default_value is gql.Undefined
        ]
        return {
            "type": "object",
            "properties": properties,
            "required": required,
            "graphqlType": "input",
            "nullable": nullable,
        }
    if isinstance(value, gql.GraphQLEnumType):
        return {
            "type": "string",
            "enum": list(value.values),
            "graphqlType": "enum",
            "nullable": nullable,
        }
    kinds = {
        "Int": "integer",
        "Float": "number",
        "String": "string",
        "ID": "string",
        "Boolean": "boolean",
    }
    if value.name not in kinds:
        raise ReportError(
            "custom GraphQL scalars require an explicit reviewed strategy"
        )
    return {"type": kinds[value.name], "graphqlType": value.name, "nullable": nullable}


def graphql_mutation_plan(
    schema_path: str, request_path: str, output: str, project: str, identity: str
) -> dict:
    gql = graphql_module()
    schema, schema_hash = load_graphql_schema(schema_path)
    request = prepared_request(json_file(Path(request_path), 128 * 1024))
    _private_fields(request)
    body = parse_json((request["body"] or "").encode("utf-8"))
    if (
        not isinstance(body, dict)
        or not isinstance(body.get("variables"), dict)
        or not isinstance(body.get("query"), str)
    ):
        raise ReportError(
            "GraphQL preparation needs a captured query and explicit variables object"
        )
    operation = _operation(schema, body["query"], body.get("operationName"))
    mutations = []
    for name, declared in operation["variables"].items():
        if _SENSITIVE.search(name):
            continue
        projected_type = gql.type_from_ast(schema, gql.parse_type(declared))
        spec = mutation_schema(_input_projection(gql, projected_type))
        mutations.append(
            {
                "location": "json",
                "pointer": "/variables/" + name,
                "schema": spec,
                "values": [],
                "omit": name in operation["requiredVariables"],
                "unsupportedSchemaKeywords": [],
            }
        )
    if not 1 <= len(mutations) <= 16:
        raise ReportError("select 1-16 supported noncredential variables")
    request = copy.deepcopy(request)
    request["operationId"] = operation["operationId"]
    plan = {
        "schemaVersion": PLAN_SCHEMA,
        "projectId": label(project, "project"),
        "identityId": label(identity, "identity"),
        "seed": 1,
        "maxCases": 16,
        "samplesPerField": 4,
        "request": request,
        "mutations": mutations,
        "setup": [],
        "readback": [],
        "reset": [],
        "assertions": [],
        "positiveStatuses": [200],
        "negativeStatuses": [200, 400],
        "provenance": {
            "schemaSha256": schema_hash,
            "requestSha256": digest(request),
            "graphqlCoreVersion": GRAPHQL_VERSION,
            "graphqlOperation": operation,
            "interpretation": "GraphQL errors may use HTTP 200; add selected data/errors expectations and relational checks.",
        },
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
