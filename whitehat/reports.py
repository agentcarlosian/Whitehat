"""Bounded, non-executing adapters for security tool reports.

Messages, snippets, request bodies, query strings, and secret values are never
copied to observations. Reported severity and provenance remain tool assertions.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

from .records import RecordError, load_result_document


class ReportError(RecordError):
    pass


class ReportLimitError(ReportError):
    exit_code = 4
    error_code = "limit-exceeded"


FORMATS = ("sarif", "opengrep", "osv", "zap", "nuclei", "betterleaks", "gitleaks")
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_OBSERVATIONS = 10_000
SCHEMA = "whitehat-research-result-v1"
CLAIMS = {
    "findingValidityEstablished": False,
    "impactEstablished": False,
    "severityEstablished": False,
    "submissionAuthorized": False,
}


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def seal(value: dict[str, Any]) -> dict[str, Any]:
    value["resultSha256"] = hashlib.sha256(canonical(value)).hexdigest()
    return value


def text(value: Any, label: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ReportError(f"{label} must be non-empty text up to {maximum} characters")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ReportError(f"{label} contains control characters")
    return value


def identifier(value: Any, label: str = "identifier") -> str:
    value = text(value, label)
    if not re.fullmatch(r"[A-Za-z0-9_@][A-Za-z0-9_.:/@+() -]{0,255}", value):
        raise ReportError(f"{label} contains unsupported characters")
    return value


def positive(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ReportError(f"{label} must be a positive integer")
    return value


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReportError("report contains duplicate JSON keys")
        result[key] = value
    return result


def parse_json(raw: bytes) -> Any:
    def reject_constant(_: str) -> None:
        raise ReportError("non-finite JSON number")
    try:
        return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_pairs,
                          parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ReportError("report must contain valid UTF-8 JSON") from exc


def read_bytes(path: Path, maximum: int = MAX_REPORT_BYTES) -> bytes:
    positive(maximum, "byte limit")
    if path.is_symlink() or not path.is_file():
        raise ReportError("input must be a regular file, not a link")
    try:
        before = path.stat()
        if before.st_size > maximum:
            raise ReportLimitError("report byte limit exceeded")
        with path.open("rb") as stream:
            content = stream.read(maximum + 1)
        after = path.stat()
    except OSError as exc:
        raise ReportError("cannot read report") from exc
    if len(content) > maximum:
        raise ReportLimitError("report byte limit exceeded")
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (
        after.st_size, after.st_mtime_ns, after.st_ino
    ) or len(content) != before.st_size:
        raise ReportError("report changed while reading")
    return content


def relative_path(value: Any, source_root: str | None = None) -> str:
    value = text(value, "source path", 4096).replace("\\", "/")
    if value.startswith("file:"):
        parsed = urlsplit(value)
        if parsed.netloc or parsed.query or parsed.fragment:
            raise ReportError("unsupported file URI")
        value = unquote(parsed.path)
        if re.match(r"^/[A-Za-z]:/", value):
            value = value[1:]
    if source_root:
        prefix = source_root.replace("\\", "/").rstrip("/") + "/"
        # A lexical report prefix, never an instruction to open an external path.
        if value.startswith(prefix):
            value = value[len(prefix):]
    while value.startswith("./"):
        value = value[2:]
    decoded = unquote(value)
    if (not value or value.startswith("/") or ":" in value or "?" in value
            or "#" in value or "\\" in decoded
            or any(p in {"", ".", ".."} for p in value.split("/"))
            or ".." in decoded.split("/") or decoded.startswith("/")):
        raise ReportError("source path must be relative and contained; use --source-root for absolute reports")
    return PurePosixPath(value).as_posix()


def endpoint(value: Any) -> str:
    value = text(value, "endpoint", 8192)
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None):
            raise ValueError
        host = parsed.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        port = f":{parsed.port}" if parsed.port is not None else ""
    except ValueError as exc:
        raise ReportError("endpoint must be HTTP(S) without credentials") from exc
    # Preserve the route, never the query, fragment, body, or authentication data.
    return f"{parsed.scheme}://{host}{port}{parsed.path or '/'}"


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReportError(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ReportError(f"{label} must be an array")
    if len(value) > MAX_OBSERVATIONS:
        raise ReportLimitError(f"{label} count limit exceeded")
    return value


def observation(tool: str, rule: str, *, path: str | None = None,
                line: int | None = None, url: str | None = None,
                severity: str | None = None, category: str = "tool-observation",
                context: dict[str, Any] | None = None,
                explanation: str | None = None, source_context: dict | None = None) -> dict[str, Any]:
    result = {
        "tool": identifier(tool, "tool"), "ruleId": identifier(rule, "rule"),
        "category": category, "path": path, "line": line, "endpoint": url,
        "severityReported": severity, "context": context or {},
        "explanation": explanation or "Tool-reported observation; inspect the referenced location and test a negative control.",
    }
    identity = {k: result[k] for k in ("tool", "ruleId", "path", "line", "endpoint", "context")}
    result["fingerprint"] = hashlib.sha256(canonical(identity)).hexdigest()
    if source_context is not None:
        from .source_context import validate_context

        result["sourceContext"] = validate_context(source_context)
    return result


def _severity(value: Any) -> str | None:
    if value is None:
        return None
    value = str(value).lower()
    return value if value in {"critical", "high", "medium", "low", "info", "informational", "warning", "error", "note", "none", "0", "1", "2", "3", "4"} else "unknown"


def _sarif(value: Any, root: str | None) -> list[dict[str, Any]]:
    from .source_context import sarif_context

    value = _object(value, "SARIF")
    if value.get("version") != "2.1.0":
        raise ReportError("only SARIF 2.1.0 is supported")
    out = []
    for run in _array(value.get("runs"), "SARIF runs"):
        run = _object(run, "SARIF run")
        driver = _object(_object(run.get("tool"), "SARIF tool").get("driver"), "driver")
        tool = identifier(driver.get("name"), "driver name").lower()
        rules = _array(driver.get("rules", []), "rules")
        for result in _array(run.get("results", []), "results"):
            result = _object(result, "result")
            rule = result.get("ruleId")
            if rule is None:
                index = result.get("ruleIndex")
                if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(rules):
                    raise ReportError("SARIF result needs a valid rule id/index")
                rule = _object(rules[index], "rule").get("id")
            locations = _array(result.get("locations", []), "locations")
            path = line = None
            if locations:
                physical = _object(_object(locations[0], "location").get("physicalLocation"), "physical location")
                artifact = _object(physical.get("artifactLocation"), "artifact location")
                path = relative_path(artifact.get("uri"), root)
                region = _object(physical.get("region", {}), "region")
                if "startLine" in region:
                    line = positive(region["startLine"], "line")
            source_context = sarif_context(result, run, root) if len(locations) > 1 or "relatedLocations" in result or "codeFlows" in result else None
            out.append(observation(tool, rule, path=path, line=line,
                                   severity=_severity(result.get("level")), source_context=source_context))
            if len(out) > MAX_OBSERVATIONS:
                raise ReportLimitError("observation count limit exceeded")
    return out


def _opengrep(value: Any, root: str | None) -> list[dict[str, Any]]:
    from .source_context import opengrep_context

    value = _object(value, "Opengrep report")
    if value.get("errors"):
        raise ReportError("Opengrep reported errors; incomplete scans cannot be imported as complete")
    out = []
    for result in _array(value.get("results"), "results"):
        result = _object(result, "Opengrep result")
        extra = _object(result.get("extra", {}), "extra")
        out.append(observation("opengrep", result.get("check_id"),
            path=relative_path(result.get("path"), root),
            line=positive(_object(result.get("start"), "start").get("line"), "line"),
            severity=_severity(extra.get("severity")), category="source-review",
            source_context=opengrep_context(extra["dataflow_trace"], root) if extra.get("dataflow_trace") is not None else None))
    return out


def _osv(value: Any, root: str | None) -> list[dict[str, Any]]:
    value = _object(value, "OSV-Scanner report")
    out = []
    for result in _array(value.get("results"), "OSV results"):
        result = _object(result, "OSV result")
        source = _object(result.get("source"), "source")
        path = relative_path(source.get("path"), root)
        for entry in _array(result.get("packages"), "packages"):
            entry = _object(entry, "package result")
            package = _object(entry.get("package"), "package")
            name = identifier(package.get("name"), "package name")
            ecosystem = identifier(package.get("ecosystem"), "ecosystem")
            version = identifier(package.get("version"), "version")
            for vulnerability in _array(entry.get("vulnerabilities", []), "vulnerabilities"):
                vulnerability = _object(vulnerability, "vulnerability")
                advisory = identifier(vulnerability.get("id"), "advisory")
                aliases = sorted({identifier(v, "alias") for v in _array(vulnerability.get("aliases", []), "aliases")})
                fixes: set[str] = set()
                for affected in _array(vulnerability.get("affected", []), "affected packages"):
                    affected = _object(affected, "affected")
                    affected_package = _object(affected.get("package", {}), "affected package")
                    if (affected_package.get("name"), affected_package.get("ecosystem")) != (name, ecosystem):
                        continue
                    for range_record in _array(affected.get("ranges", []), "ranges"):
                        for event in _array(_object(range_record, "range").get("events", []), "events"):
                            event = _object(event, "event")
                            if "fixed" in event:
                                fixes.add(identifier(event["fixed"], "fixed version"))
                out.append(observation("osv-scanner", advisory, path=path,
                    category="dependency-advisory", context={
                        "package": name, "ecosystem": ecosystem, "version": version,
                        "aliases": aliases, "fixedVersionsReported": sorted(fixes),
                        "matchStatus": "scanner-reported", "reachability": "unverified",
                        "withdrawn": vulnerability.get("withdrawn") is not None,
                    }, explanation="Verify the affected range, installed version, reachable code, and prior disclosure before treating this advisory match as a candidate."))
                if len(out) > MAX_OBSERVATIONS:
                    raise ReportLimitError("observation count limit exceeded")
    return out


def _zap(value: Any, root: str | None) -> list[dict[str, Any]]:
    value = _object(value, "ZAP report")
    out = []
    for site in _array(value.get("site"), "ZAP sites"):
        site = _object(site, "site")
        for alert in _array(site.get("alerts"), "alerts"):
            alert = _object(alert, "alert")
            rule = str(alert.get("alertRef", alert.get("pluginid", "")))
            instances = _array(alert.get("instances", []), "instances")
            if not instances:
                instances = [{"uri": site.get("@name")}]
            for instance in instances:
                instance = _object(instance, "instance")
                method = instance.get("method")
                if method is not None and (not isinstance(method, str) or not re.fullmatch(r"[A-Z]{3,16}", method)):
                    raise ReportError("invalid ZAP HTTP method")
                context = {"httpMethod": method, "parameter": text(instance["param"], "parameter") if instance.get("param") else None}
                out.append(observation("zap", rule, url=endpoint(instance.get("uri")),
                    severity=_severity(alert.get("riskcode")), category="web-observation", context=context))
                if len(out) > MAX_OBSERVATIONS:
                    raise ReportLimitError("observation count limit exceeded")
    return out


def _nuclei(value: Any, root: str | None) -> list[dict[str, Any]]:
    out = []
    for item in _array(value, "Nuclei results"):
        item = _object(item, "Nuclei result")
        info = _object(item.get("info"), "info")
        # This adapter deliberately supports HTTP(S) records; other protocols need a profile.
        out.append(observation("nuclei", item.get("template-id"),
            url=endpoint(item.get("matched-at", item.get("host"))),
            severity=_severity(info.get("severity")), category="web-observation"))
    return out


def _secrets(value: Any, root: str | None, tool: str) -> list[dict[str, Any]]:
    # Betterleaks 1.8.1 emits JSON null for a successful scan with no findings.
    if value is None:
        return []
    out = []
    for result in _array(value, "secret observations"):
        result = _object(result, "secret observation")
        out.append(observation(tool, result.get("RuleID"),
            path=relative_path(result.get("File"), root),
            line=positive(result.get("StartLine"), "line"), category="secret-candidate",
            explanation="Potential secret pattern. Value is omitted; no credential validation was performed."))
    return out


def normalize(raw: bytes, format_name: str, source_root: str | None = None) -> list[dict[str, Any]]:
    if len(raw) > MAX_REPORT_BYTES:
        raise ReportLimitError("report byte limit exceeded")
    if format_name not in FORMATS:
        raise ReportError("unsupported report format")
    if format_name == "nuclei":
        lines = [line for line in raw.splitlines() if line.strip()]
        if len(lines) > MAX_OBSERVATIONS:
            raise ReportLimitError("report record limit exceeded")
        value = [parse_json(line) for line in lines]
    else:
        value = parse_json(raw)
    parsers = {"sarif": _sarif, "opengrep": _opengrep, "osv": _osv,
               "zap": _zap, "nuclei": _nuclei}
    if format_name in {"gitleaks", "betterleaks"}:
        records = _secrets(value, source_root, format_name)
    else:
        records = parsers[format_name](value, source_root)
    if len(records) > MAX_OBSERVATIONS:
        raise ReportLimitError("observation count limit exceeded")
    _source_context_budget(records)
    return records


def _source_context_budget(records):
    count = 0
    for item in records:
        context = item.get("sourceContext")
        if "sourceContext" in item:
            from .source_context import validate_context

            validate_context(context)
            count += len(context["relatedLocations"]) + sum(len(flow["steps"]) for flow in context["flows"])
        if count > 10000:
            raise ReportLimitError("report source-context location limit exceeded")


def result_document(records: list[dict[str, Any]], provenance: dict[str, Any],
                    *, effects: dict[str, Any] | None = None) -> dict[str, Any]:
    by_id: dict[str, dict[str, Any]] = {}
    for item in records:
        previous = by_id.get(item["fingerprint"])
        if previous is not None and previous != item:
            raise ReportError("duplicate observation identity has conflicting metadata")
        by_id[item["fingerprint"]] = item
    observations = sorted(by_id.values(), key=lambda v: (v["tool"], v["path"] or v["endpoint"] or "", v["line"] or 0, v["ruleId"]))
    return seal({
        "schemaVersion": SCHEMA, "ok": True, "provenance": provenance,
        "observations": observations,
        "summary": {"observations": len(observations), "duplicatesRemoved": len(records) - len(observations),
                    "categories": dict(sorted(Counter(item["category"] for item in observations).items()))},
        "claims": dict(CLAIMS),
        "effects": effects or {"network": False, "processCreation": False, "sourceExecuted": False},
    })


def import_report(path: str, format_name: str, source_root: str | None = None) -> dict[str, Any]:
    raw = read_bytes(Path(path))
    return result_document(normalize(raw, format_name, source_root), {
        "kind": "import", "format": format_name, "reportSha256": hashlib.sha256(raw).hexdigest(),
        "executionVerified": False,
    })


def compare_results(before_path: str, after_path: str) -> dict[str, Any]:
    before = checked_research_result(before_path)
    after = checked_research_result(after_path)
    old = {v["fingerprint"]: v for v in before["observations"]}
    new = {v["fingerprint"]: v for v in after["observations"]}
    introduced, absent = sorted(new.keys() - old.keys()), sorted(old.keys() - new.keys())
    shared = sorted(new.keys() & old.keys())
    changed = [k for k in shared if old[k] != new[k]]
    unchanged = [k for k in shared if k not in changed]
    identity_keys = ("kind", "tool", "toolVersion", "configSha256", "format", "sourceSuffixes", "excludedDirectories", "analysisProfile")
    comparable = all(before["provenance"].get(k) == after["provenance"].get(k) for k in identity_keys)
    return seal({"schemaVersion": "whitehat-research-comparison-v1", "ok": True,
        "beforeSha256": before["resultSha256"], "afterSha256": after["resultSha256"],
        "summary": {"introduced": len(introduced), "absent": len(absent), "unchanged": len(unchanged), "metadataChanged": len(changed)},
        "introduced": [new[k] for k in introduced], "absent": [old[k] for k in absent],
        "unchanged": unchanged, "claims": dict(CLAIMS),
        "metadataChanged": [{"fingerprint": k, "before": old[k], "after": new[k]} for k in changed],
        "sameAnalysisProfile": comparable,
        "comparisonSuitability": "same-profile" if comparable else "not-comparable",
        "effects": {"network": False, "processCreation": False},
        "interpretation": "Absence is not proof of a fix; compare scan coverage and tool/rule identities. Fingerprints include source line numbers.",
    })


def checked_research_result(path: str) -> dict[str, Any]:
    result = load_result_document(path)
    if result["schemaVersion"] != SCHEMA:
        raise ReportError("expected a research result")
    if result.get("claims") != CLAIMS or not isinstance(result.get("provenance"), dict):
        raise ReportError("invalid research result claims or provenance")
    for item in _array(result.get("observations"), "observations"):
        item = _object(item, "observation")
        expected_fields = {"tool", "ruleId", "category", "path", "line", "endpoint",
                           "severityReported", "context", "explanation", "fingerprint"}
        if set(item) not in (expected_fields, expected_fields | {"sourceContext"}):
            raise ReportError("invalid observation fields")
        identifier(item["tool"], "tool")
        identifier(item["ruleId"], "rule")
        text(item["explanation"], "explanation", 1024)
        if item["path"] is not None:
            relative_path(item["path"])
        if item["line"] is not None:
            positive(item["line"], "line")
        if item["endpoint"] is not None and endpoint(item["endpoint"]) != item["endpoint"]:
            raise ReportError("research endpoint must omit query and fragment values")
        if not isinstance(item["context"], dict):
            raise ReportError("invalid observation context")
        fingerprint = item.get("fingerprint")
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[a-f0-9]{64}", fingerprint):
            raise ReportError("invalid observation fingerprint")
        identity = {k: item[k] for k in ("tool", "ruleId", "path", "line", "endpoint", "context")}
        if hashlib.sha256(canonical(identity)).hexdigest() != fingerprint:
            raise ReportError("observation fingerprint does not match its identity")
    _source_context_budget(result["observations"])
    return result
