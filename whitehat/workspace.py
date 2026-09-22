"""Explicit, bounded workspace indexes and read-only dependency inspection."""

from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path

from .candidates import candidate_history
from .evidence_links import contained_path, evidence_result, fields, sha256
from .http_evidence import digest, label
from .packets import check_packet
from .records import RecordError, load_result_document, write_json_document
from .reports import (
    CLAIMS,
    ReportError,
    ReportLimitError,
    parse_json,
    read_bytes,
    relative_path,
    seal,
)

SCHEMA = "whitehat-workspace-index-v1"
KINDS = ("input", "result", "packet", "candidate")
MAX_BYTES = 32 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024


def _root(path: Path) -> Path:
    if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
        raise ReportError("workspace root must not be a link or junction")
    if not path.is_dir():
        raise ReportError("workspace root must be an existing directory")
    return path.resolve(strict=True)


def _paths(root: Path, entry: dict) -> list[Path]:
    path = contained_path(root, entry["path"])
    if entry["kind"] != "candidate":
        return [path]
    decisions = contained_path(path, "decisions")
    if not decisions.is_dir():
        raise ReportError("candidate decisions directory is missing")
    paths = [contained_path(path, "candidate.json")]
    # Bound enumeration before delegating to the existing history validator.
    for item in decisions.iterdir():
        if len(paths) >= 1001:
            raise ReportLimitError("candidate exceeds 1000 decisions")
        paths.append(contained_path(path, "decisions/" + item.name))
    return paths


def _read(root: Path, entry: dict, budget: list[int]) -> tuple[str, dict | None]:
    paths = _paths(root, entry)
    for path in paths:
        if not path.is_file():
            raise ReportError("registered artifact is not a regular file")
        size = path.stat().st_size
        if size > MAX_FILE or budget[0] + size > MAX_BYTES:
            raise ReportLimitError("workspace exceeds 8 MiB/file or 32 MiB total")
        budget[0] += size
    path = contained_path(root, entry["path"])
    if entry["kind"] == "candidate":
        value = candidate_history(str(path))
        return digest(value), value
    raw = read_bytes(path, MAX_FILE)
    fingerprint = hashlib.sha256(raw).hexdigest()
    if entry["kind"] == "input":
        return fingerprint, None
    if entry["kind"] == "packet":
        value = parse_json(raw)
        if (
            not isinstance(value, dict)
            or value.get("schemaVersion") != "whitehat-report-manifest-v1"
        ):
            raise ReportError("registered packet must be a report manifest")
        return fingerprint, value
    value = load_result_document(path, MAX_FILE)
    provenance = value.get("provenance", {})
    if not isinstance(provenance, dict):
        raise ReportError("result provenance must be an object")
    if provenance.get("captureSha256") is not None:
        sha256(provenance["captureSha256"])
    if value["schemaVersion"] == "whitehat-research-comparison-v1":
        for side in ("before", "after"):
            sha256(value.get(side + "Sha256"))
    if value["schemaVersion"] in (
        "whitehat-http-evidence-v1",
        "whitehat-http-comparison-v1",
        "whitehat-research-result-v1",
    ):
        value = evidence_result(path)
    return fingerprint, value


def _references(value: dict) -> list[str]:
    schema = value["schemaVersion"]
    if schema == "whitehat-http-comparison-v1":
        return [sha256(value[side + "EvidenceSha256"]) for side in ("before", "after")]
    if schema == "whitehat-research-comparison-v1":
        return [sha256(value[side + "Sha256"]) for side in ("before", "after")]
    if schema == "whitehat-candidate-history-v1":
        return [sha256(d["evidence"]["resultSha256"]) for d in value["decisions"]]
    provenance = value.get("provenance", {})
    if isinstance(provenance, dict) and provenance.get("kind") in (
        "access-assessment",
        "relational-assessment",
    ):
        references = provenance.get("evidenceResults", [])
        if not isinstance(references, list) or len(references) > 100:
            raise ReportError("invalid workspace evidence references")
        return [sha256(v) for v in references]
    return []


def _links(root: Path, entries: dict, values: dict) -> tuple[dict, dict]:
    hashes: dict[str, set[str]] = {}
    for name, entry in entries.items():
        hashes.setdefault(entry["sha256"], set()).add(name)
    for name, value in values.items():
        if not value:
            continue
        if "resultSha256" in value:
            hashes.setdefault(value["resultSha256"], set()).add(name)
        if value["schemaVersion"] == "whitehat-http-evidence-v1":
            for exchange in value["exchanges"]:
                hashes.setdefault(exchange["evidenceSha256"], set()).add(name)
    links = {name: set(entry["dependsOn"]) for name, entry in entries.items()}
    issues = {name: [] for name in entries}
    for name, value in values.items():
        if not value:
            continue
        for hash_value in _references(value):
            matches = hashes.get(hash_value, set()) - {name}
            if not matches:
                issues[name].append(
                    {"code": "missing-linked-artifact", "item": hash_value}
                )
            links[name].update(matches)
        # Connect a supplied capture without requiring raw capture retention.
        provenance = value.get("provenance", {})
        if not isinstance(provenance, dict):
            raise ReportError("artifact provenance must be an object")
        capture = provenance.get("captureSha256")
        if capture is not None:
            sha256(capture)
        links[name].update(hashes.get(capture, set()) - {name})
        if entries[name]["kind"] == "packet":
            refs = value.get("evidence")
            if not isinstance(refs, list) or len(refs) > 20:
                raise ReportError("packet requires a bounded evidence list")
            for ref in refs:
                fields(ref, {"id", "path", "resultSha256", "select"}, "packet evidence")
                target = contained_path(contained_path(root, name).parent, ref["path"])
                target_name = target.relative_to(root).as_posix()
                if (
                    target_name not in entries
                    or entries[target_name]["kind"] != "result"
                ):
                    issues[name].append(
                        {"code": "unregistered-packet-evidence", "item": target_name}
                    )
                else:
                    links[name].add(target_name)
    return links, issues


def _validate_index(value: dict, root: Path) -> dict:
    fields(value, {"schemaVersion", "projectId", "artifacts"}, "workspace index")
    if value["schemaVersion"] != SCHEMA:
        raise ReportError("unsupported workspace index")
    label(value["projectId"], "project")
    if (
        not isinstance(value["artifacts"], list)
        or not 1 <= len(value["artifacts"]) <= 100
    ):
        raise ReportError("workspace index requires 1-100 artifacts")
    entries = {}
    aliases = set()
    for entry in value["artifacts"]:
        fields(entry, {"path", "kind", "sha256", "dependsOn"}, "workspace artifact")
        name = relative_path(entry["path"])
        if (
            name != entry["path"]
            or not isinstance(entry["kind"], str)
            or entry["kind"] not in KINDS
        ):
            raise ReportError("invalid workspace artifact path/kind")
        path = contained_path(root, name)
        if path in aliases:
            raise ReportError("duplicate workspace artifact path")
        aliases.add(path)
        sha256(entry["sha256"])
        deps = entry["dependsOn"]
        if (
            not isinstance(deps, list)
            or len(deps) > 100
            or any(not isinstance(v, str) for v in deps)
        ):
            raise ReportError("invalid workspace dependencies")
        if len(deps) != len(set(deps)):
            raise ReportError("duplicate workspace dependency")
        entries[name] = entry
    for name, entry in entries.items():
        if name in entry["dependsOn"] or set(entry["dependsOn"]) - entries.keys():
            raise ReportError(
                "workspace dependency is self-referential or unregistered"
            )
    _order({name: set(e["dependsOn"]) for name, e in entries.items()})
    return entries


def _order(links: dict[str, set[str]]) -> list[str]:
    remaining, done = dict(links), []
    while remaining:
        ready = sorted(
            name for name, deps in remaining.items() if not deps.intersection(remaining)
        )
        if not ready:
            raise ReportError("workspace dependencies contain a cycle")
        done.extend(ready)
        for name in ready:
            del remaining[name]
    return done


def index_workspace(
    directory: str,
    output: str,
    project: str,
    artifacts: dict[str, list[str]],
    dependencies: list[str],
) -> dict:
    root = _root(Path(directory))
    destination = Path(output)
    if destination.parent.resolve(strict=True) != root:
        raise ReportError(
            "workspace index must be written directly inside its workspace"
        )
    entries, values, budget = {}, {}, [0]
    total = sum(len(paths) for paths in artifacts.values())
    if not 1 <= total <= 100:
        raise ReportError("workspace index requires 1-100 artifacts")
    for kind in KINDS:
        for name in artifacts.get(kind, []):
            name = relative_path(name)
            if name in entries:
                raise ReportError("duplicate workspace artifact")
            entry = {"path": name, "kind": kind, "sha256": "0" * 64, "dependsOn": []}
            entry["sha256"], values[name] = _read(root, entry, budget)
            entries[name] = entry
    for link in dependencies:
        child, separator, parent = link.partition("=")
        if not separator or child not in entries or parent not in entries:
            raise ReportError("dependency must be registered-child=registered-parent")
        entries[child]["dependsOn"].append(parent)
    value = {
        "schemaVersion": SCHEMA,
        "projectId": label(project, "project"),
        "artifacts": list(entries.values()),
    }
    _validate_index(value, root)
    links, _ = _links(root, entries, values)
    _order(links)
    for name, entry in entries.items():
        entry["dependsOn"] = sorted(links[name])
    value["artifacts"].sort(key=lambda entry: entry["path"])
    write_json_document(value, destination)
    return seal(
        {
            "schemaVersion": "whitehat-workspace-indexed-v1",
            "ok": True,
            "projectId": project,
            "indexSha256": digest(value),
            "artifacts": total,
            "effects": {"network": False, "filesystemWrite": True},
        }
    )


def workspace_status(path: str) -> dict:
    source = Path(path)
    root = _root(source.parent)
    source = contained_path(root, source.name)
    value = parse_json(read_bytes(source, 256 * 1024))
    entries = _validate_index(value, root)
    values, rows, budget = {}, {}, [0]
    for name, entry in sorted(entries.items()):
        row = {
            "path": name,
            "kind": entry["kind"],
            "status": "current",
            "issues": [],
            "staleBecause": [],
        }
        rows[name] = row
        if not contained_path(root, name).exists():
            row["status"] = "missing"
            continue
        try:
            actual, document = _read(root, entry, budget)
            if actual != entry["sha256"]:
                row["status"] = "changed"
            values[name] = document
            project = (document or {}).get("projectId") or (document or {}).get(
                "provenance", {}
            ).get("projectId")
            if entry["kind"] == "candidate":
                project = document["candidate"]["projectId"]
                row["decision"] = (
                    document["decisions"][-1]["decision"]
                    if document["decisions"]
                    else "open"
                )
            if project is not None and project != value["projectId"]:
                row["status"] = "invalid"
                row["issues"].append({"code": "project-mismatch", "item": name})
        except ReportLimitError:
            raise
        except (OSError, RecordError, ValueError, TypeError, KeyError):
            row["status"] = "invalid"
            row["issues"].append({"code": "invalid-artifact", "item": name})
    links, issues = _links(root, entries, values)
    for name, row in rows.items():
        row["issues"].extend(issues[name])
        if issues[name] and row["status"] == "current":
            row["status"] = "invalid"
        if entries[name]["kind"] == "packet" and name in values and not issues[name]:
            try:
                packet = check_packet(str(contained_path(root, name)))
                row["contentComplete"] = packet["contentComplete"]
                row["issues"].extend(packet["issues"])
                if (
                    any(i["code"] != "missing-content" for i in packet["issues"])
                    and row["status"] == "current"
                ):
                    row["status"] = "invalid"
            except (OSError, RecordError, ValueError, TypeError, KeyError):
                row["status"] = "invalid"
                row["issues"].append({"code": "invalid-packet", "item": name})
    for name in _order(links):
        row = rows[name]
        row["staleBecause"] = sorted(
            dep for dep in links[name] if rows[dep]["status"] != "current"
        )
        structural = any(
            i["code"] in ("invalid-artifact", "invalid-packet", "project-mismatch")
            for i in row["issues"]
        )
        if (
            row["staleBecause"]
            and row["status"] in ("current", "invalid")
            and not structural
        ):
            row["status"] = "stale"
        row["dependsOn"] = sorted(links[name])
        row["nextAction"] = {
            "current": "Complete packet content."
            if row.get("contentComplete") is False
            else "No integrity repair needed.",
            "changed": "Review this change and rebuild dependent results before creating a new index.",
            "missing": "Restore the registered artifact or explicitly create a replacement index.",
            "invalid": "Repair the named artifact or supply its missing registered evidence.",
            "stale": "Rebuild or reassess this artifact after resolving stale dependencies.",
        }[row["status"]]
    return seal(
        {
            "schemaVersion": "whitehat-workspace-status-v1",
            "ok": True,
            "projectId": value["projectId"],
            "indexSha256": digest(value),
            "consistent": all(r["status"] == "current" for r in rows.values()),
            "summary": dict(
                sorted(Counter(r["status"] for r in rows.values()).items())
            ),
            "artifacts": list(rows.values()),
            "claims": dict(CLAIMS),
            "effects": {"network": False, "filesystemWrite": False},
        }
    )
