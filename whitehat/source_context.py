"""Bounded source locations and tool-reported flows; never resolve source files."""

from .reports import ReportError, ReportLimitError, canonical, relative_path

SCHEMA = "whitehat-source-context-v1"
KINDS = frozenset(
    {
        "source",
        "sink",
        "sanitizer",
        "assignment",
        "call",
        "return",
        "branch",
        "condition",
    }
)
DIAGNOSTICS = frozenset(
    {
        "no-physical-location",
        "unresolved-artifact-index",
        "unresolved-uri-base",
        "unresolved-thread-location",
        "unsupported-native-call-trace",
        "missing-native-endpoint",
        "unrecognized-step-kind",
    }
)


def _object(value, name):
    if not isinstance(value, dict):
        raise ReportError(f"invalid {name}")
    return value


def _list(value, maximum, name):
    if not isinstance(value, list):
        raise ReportError(f"invalid {name}")
    if len(value) > maximum:
        raise ReportLimitError(f"{name} limit exceeded")
    return value


def _integer(value, name, minimum=1):
    if type(value) is not int or not minimum <= value <= 1000000000:
        raise ReportError(f"invalid {name}")
    return value


def _location(path, region, root):
    region = _object(region, "source region")
    value = {"path": relative_path(path, root)}
    for name in ("startLine", "startColumn", "endLine", "endColumn"):
        value[name] = _integer(region[name], name) if name in region else None
    if (
        value["endLine"] is not None
        and value["startLine"] is not None
        and value["endLine"] < value["startLine"]
    ):
        raise ReportError("source region ends before its start")
    if (
        value["endLine"] in (None, value["startLine"])
        and value["startColumn"] is not None
        and value["endColumn"] is not None
        and value["endColumn"] < value["startColumn"]
    ):
        raise ReportError("source region ends before its start")
    return value


def _base(origin):
    return {
        "schemaVersion": SCHEMA,
        "origin": origin,
        "validation": "unverified",
        "relatedLocations": [],
        "flows": [],
        "diagnostics": [],
        "representationComplete": True,
    }


def _finish(value):
    value["diagnostics"] = sorted(set(value["diagnostics"]))
    value["representationComplete"] = not value["diagnostics"]
    return validate_context(value)


def sarif_context(result, run, root=None):
    context = _base("sarif")
    diagnostics = context["diagnostics"]

    def location(value):
        value = _object(value, "SARIF location")
        if "physicalLocation" not in value:
            diagnostics.append("no-physical-location")
            return None
        physical = _object(value["physicalLocation"], "physical location")
        artifact = _object(physical.get("artifactLocation", {}), "artifact location")
        if "uri" not in artifact and "index" in artifact:
            index = _integer(artifact["index"], "artifact index", 0)
            artifacts = _list(run.get("artifacts", []), 10000, "SARIF artifacts")
            if index >= len(artifacts):
                diagnostics.append("unresolved-artifact-index")
                return None
            artifact = _object(
                _object(artifacts[index], "artifact").get("location", {}),
                "artifact location",
            )
        if "uriBaseId" in artifact:
            diagnostics.append("unresolved-uri-base")
            return None
        if "uri" not in artifact:
            diagnostics.append("no-physical-location")
            return None
        return _location(artifact["uri"], physical.get("region", {}), root)

    secondary = _list(result.get("locations", []), 33, "result locations")[1:] + _list(
        result.get("relatedLocations", []), 32, "related locations"
    )
    _list(secondary, 32, "secondary locations")
    context["relatedLocations"] = [location(v) for v in secondary]
    for code_flow in _list(result.get("codeFlows", []), 8, "code flows"):
        threads = _list(
            _object(code_flow, "code flow").get("threadFlows"), 8, "thread flows"
        )
        if not threads:
            raise ReportError("code flow must contain a thread flow")
        for thread in threads:
            if len(context["flows"]) >= 8:
                raise ReportLimitError("reported flow limit exceeded")
            steps = []
            for entry in _list(
                _object(thread, "thread flow").get("locations"), 64, "flow steps"
            ):
                entry = _object(entry, "thread location")
                if "index" in entry:
                    index = _integer(entry["index"], "thread location index", 0)
                    shared = _list(
                        run.get("threadFlowLocations", []),
                        10000,
                        "shared thread locations",
                    )
                    if index >= len(shared):
                        diagnostics.append("unresolved-thread-location")
                        steps.append(
                            {"location": None, "kinds": [], "executionOrder": None}
                        )
                        continue
                    base = _object(shared[index], "shared thread location")
                    if (
                        "index" in base
                        and _integer(base["index"], "cached thread index", 0) != index
                    ):
                        raise ReportError("cached thread location index mismatch")
                    if any(
                        k not in base or canonical(v) != canonical(base[k])
                        for k, v in entry.items()
                        if k != "index"
                    ):
                        raise ReportError(
                            "inline thread location conflicts with its cached object"
                        )
                    entry = {k: v for k, v in base.items() if k != "index"}
                kinds = _list(entry.get("kinds", []), 16, "step kinds")
                if any(not isinstance(k, str) for k in kinds):
                    raise ReportError("step kinds must be strings")
                if set(kinds) - KINDS:
                    diagnostics.append("unrecognized-step-kind")
                steps.append(
                    {
                        "location": location(entry.get("location", {})),
                        "kinds": sorted(set(kinds) & KINDS),
                        "executionOrder": _integer(
                            entry["executionOrder"], "execution order", 0
                        )
                        if "executionOrder" in entry
                        else None,
                    }
                )
            if not steps:
                raise ReportError("reported thread flow must contain a step")
            context["flows"].append({"steps": steps})
    return _finish(context)


def opengrep_context(trace, root=None):
    trace = _object(trace, "native dataflow trace")
    context = _base("opengrep")
    steps = []

    def location(value):
        value = _object(value, "native flow location")
        start = _object(value.get("start"), "native flow start")
        end = _object(value.get("end", {}), "native flow end")
        region = {
            name: obj[key]
            for obj, key, name in (
                (start, "line", "startLine"),
                (start, "col", "startColumn"),
                (end, "line", "endLine"),
                (end, "col", "endColumn"),
            )
            if key in obj
        }
        return _location(value.get("path"), region, root)

    def endpoint(value, kind):
        if value is None:
            context["diagnostics"].append("missing-native-endpoint")
            place = None
        elif isinstance(value, list) and len(value) == 2 and value[0] == "CliLoc":
            if not isinstance(value[1], list) or len(value[1]) != 2:
                raise ReportError("invalid native location tuple")
            place = location(value[1][0])
        elif isinstance(value, list) and len(value) == 2 and value[0] == "CliCall":
            context["diagnostics"].append("unsupported-native-call-trace")
            place = None
        else:
            raise ReportError("unsupported native trace representation")
        steps.append({"location": place, "kinds": [kind], "executionOrder": None})

    endpoint(trace.get("taint_source"), "source")
    for intermediate in _list(
        trace.get("intermediate_vars", []), 62, "native intermediate locations"
    ):
        steps.append(
            {
                "location": location(
                    _object(intermediate, "native intermediate").get("location")
                ),
                "kinds": ["assignment"],
                "executionOrder": None,
            }
        )
    endpoint(trace.get("taint_sink"), "sink")
    context["flows"] = [{"steps": steps}]
    return _finish(context)


def validate_context(value):
    if not isinstance(value, dict) or set(value) != {
        "schemaVersion",
        "origin",
        "validation",
        "relatedLocations",
        "flows",
        "diagnostics",
        "representationComplete",
    }:
        raise ReportError("invalid source context fields")
    if (
        value["schemaVersion"] != SCHEMA
        or value["origin"] not in ("sarif", "opengrep")
        or value["validation"] != "unverified"
    ):
        raise ReportError("invalid source context origin or claim")
    diagnostics = _list(value["diagnostics"], len(DIAGNOSTICS), "source diagnostics")
    if any(
        not isinstance(v, str) or v not in DIAGNOSTICS for v in diagnostics
    ) or diagnostics != sorted(set(diagnostics)):
        raise ReportError("invalid source diagnostics")
    if type(value["representationComplete"]) is not bool or value[
        "representationComplete"
    ] != (not diagnostics):
        raise ReportError("source representation completeness mismatch")

    def location(item):
        if item is None:
            if not diagnostics:
                raise ReportError("missing source location requires a diagnostic")
            return
        if not isinstance(item, dict) or set(item) != {
            "path",
            "startLine",
            "startColumn",
            "endLine",
            "endColumn",
        }:
            raise ReportError("invalid normalized source location")
        region = {k: v for k, v in item.items() if k != "path" and v is not None}
        if _location(item["path"], region, None) != item:
            raise ReportError("source location is not canonical")

    for item in _list(value["relatedLocations"], 32, "related locations"):
        location(item)
    for flow in _list(value["flows"], 8, "reported flows"):
        if not isinstance(flow, dict) or set(flow) != {"steps"}:
            raise ReportError("invalid normalized source flow")
        if not _list(flow["steps"], 64, "flow steps"):
            raise ReportError("reported flow must contain steps")
        for step in flow["steps"]:
            if not isinstance(step, dict) or set(step) != {
                "location",
                "kinds",
                "executionOrder",
            }:
                raise ReportError("invalid normalized flow step")
            location(step["location"])
            kinds = _list(step["kinds"], len(KINDS), "step kinds")
            if any(
                not isinstance(k, str) or k not in KINDS for k in kinds
            ) or kinds != sorted(set(kinds)):
                raise ReportError("invalid normalized step kinds")
            if step["executionOrder"] is not None:
                _integer(step["executionOrder"], "execution order", 0)
    return value


def context_lines(value):
    validate_context(value)

    def place(item):
        if item is None:
            return "location unavailable"
        if item["startLine"] is None:
            return item["path"] + (
                f" (column {item['startColumn']})"
                if item["startColumn"] is not None
                else ""
            )
        return (
            item["path"]
            + (f":{item['startLine']}" if item["startLine"] is not None else "")
            + (f":{item['startColumn']}" if item["startColumn"] is not None else "")
        )

    lines = ["Tool-reported source context (unverified)."]
    lines.extend(
        "Related location: " + place(item) for item in value["relatedLocations"]
    )
    for i, flow in enumerate(value["flows"], 1):
        lines.append(f"Reported flow {i}, supplied step order:")
        for j, step in enumerate(flow["steps"], 1):
            kinds = ", ".join(step["kinds"]) or "step"
            order = (
                f"; execution order {step['executionOrder']}"
                if step["executionOrder"] is not None
                else ""
            )
            lines.append(f"  {j}. {kinds}: {place(step['location'])}{order}")
    lines.extend("Representation diagnostic: " + code for code in value["diagnostics"])
    lines.append(
        "Review route reachability, caller control, guards/sanitizers, and a rejecting control at these locations."
    )
    return lines
