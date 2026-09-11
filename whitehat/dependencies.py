from __future__ import annotations

import hashlib
import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class DependencyError(Exception):
    """Base error for local dependency manifest comparison."""

    exit_code = 3
    error_code = "invalid-input"


class DependencyLimitError(DependencyError):
    exit_code = 4
    error_code = "limit-exceeded"


@dataclass(frozen=True)
class DependencyLimits:
    max_manifest_bytes: int = 16 * 1024 * 1024
    max_dependencies: int = 20_000

    def validate(self) -> None:
        for name, value in self.as_dict().items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise DependencyLimitError(f"{name} must be a positive integer")

    def as_dict(self) -> dict[str, int]:
        return {
            "maxManifestBytes": self.max_manifest_bytes,
            "maxDependencies": self.max_dependencies,
        }


@dataclass(frozen=True)
class DependencyManifest:
    ecosystem: str
    format: str
    content_sha256: str
    records: dict[str, dict[str, Any]]
    details: dict[str, Any]

    def summary(self) -> dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "format": self.format,
            "contentSha256": self.content_sha256,
            "dependencies": len(self.records),
            **self.details,
        }


_PYTHON_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")
_EXTRA_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _normalize_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _read_manifest(
    path_value: str | Path, limits: DependencyLimits
) -> tuple[Path, bytes]:
    path = Path(path_value)
    if path.is_symlink():
        raise DependencyError("dependency manifest must not be a symbolic link")
    try:
        resolved = path.resolve(strict=True)
        before = resolved.stat(follow_symlinks=False)
    except (OSError, RuntimeError) as exc:
        raise DependencyError(f"dependency manifest is unavailable: {exc}") from exc
    if not resolved.is_file():
        raise DependencyError("dependency manifest must be a regular file")
    if before.st_size > limits.max_manifest_bytes:
        raise DependencyLimitError("dependency manifest byte limit exceeded")
    try:
        content = resolved.read_bytes()
        after = resolved.stat(follow_symlinks=False)
    except OSError as exc:
        raise DependencyError(f"cannot read dependency manifest: {exc}") from exc
    if len(content) != before.st_size:
        raise DependencyError("dependency manifest changed while reading")
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise DependencyError("dependency manifest changed while reading")
    return resolved, content


def _decode_utf8(content: bytes) -> str:
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DependencyError("dependency manifest must be UTF-8") from exc


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DependencyError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _parse_json(content: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            _decode_utf8(content), object_pairs_hook=_reject_duplicate_json_keys
        )
    except DependencyError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise DependencyError(f"invalid JSON dependency manifest: {exc}") from exc
    if not isinstance(value, dict):
        raise DependencyError("JSON dependency manifest must be an object")
    return value


def _add_record(
    records: dict[str, dict[str, Any]],
    key: str,
    record: dict[str, Any],
    limits: DependencyLimits,
) -> None:
    if key in records:
        raise DependencyError(f"duplicate dependency identity: {key}")
    if len(records) + 1 > limits.max_dependencies:
        raise DependencyLimitError("dependency count limit exceeded")
    records[key] = record


def _python_requirement_record(
    requirement: Any, scope: str
) -> tuple[str, str, dict[str, Any]]:
    if not isinstance(requirement, str) or not requirement.strip():
        raise DependencyError(
            f"Python dependency in {scope} must be a non-empty string"
        )
    normalized_requirement = requirement.strip()
    match = _PYTHON_NAME.match(normalized_requirement)
    if match is None:
        raise DependencyError(f"Python dependency in {scope} has no package name")
    name = _normalize_name(match.group(0))
    return f"{scope}:{name}", normalized_requirement, {"name": name, "scope": scope}


def _add_python_requirement(
    records: dict[str, dict[str, Any]],
    requirement: Any,
    scope: str,
    limits: DependencyLimits,
) -> None:
    key, normalized_requirement, identity = _python_requirement_record(
        requirement, scope
    )
    existing = records.get(key)
    if existing is None:
        _add_record(
            records,
            key,
            {**identity, "requirements": [normalized_requirement]},
            limits,
        )
        return
    requirements = existing["requirements"]
    if normalized_requirement not in requirements:
        requirements.append(normalized_requirement)
        requirements.sort()


def _load_pyproject(content: bytes, limits: DependencyLimits) -> DependencyManifest:
    try:
        value = tomllib.loads(_decode_utf8(content))
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        raise DependencyError(f"invalid pyproject.toml: {exc}") from exc
    project = value.get("project")
    if not isinstance(project, dict):
        raise DependencyError("pyproject.toml must contain a [project] table")
    dynamic = project.get("dynamic", [])
    if not isinstance(dynamic, list) or any(
        not isinstance(item, str) for item in dynamic
    ):
        raise DependencyError("project.dynamic must be a string array")
    if "dependencies" in dynamic:
        raise DependencyError("dynamic Python dependencies are unsupported")

    records: dict[str, dict[str, Any]] = {}
    main_dependencies = project.get("dependencies", [])
    if not isinstance(main_dependencies, list):
        raise DependencyError("project.dependencies must be an array")
    for requirement in main_dependencies:
        _add_python_requirement(records, requirement, "main", limits)

    optional = project.get("optional-dependencies", {})
    if not isinstance(optional, dict):
        raise DependencyError("project.optional-dependencies must be a table")
    for extra in sorted(optional):
        dependencies = optional[extra]
        if not isinstance(extra, str) or _EXTRA_NAME.fullmatch(extra) is None:
            raise DependencyError(
                "Python optional dependency group has an invalid name"
            )
        if not isinstance(dependencies, list):
            raise DependencyError(f"optional dependency group {extra} must be an array")
        scope = f"extra:{_normalize_name(extra)}"
        for requirement in dependencies:
            _add_python_requirement(records, requirement, scope, limits)

    return DependencyManifest(
        ecosystem="python",
        format="pyproject.toml",
        content_sha256=hashlib.sha256(content).hexdigest(),
        records=records,
        details={},
    )


def _npm_direct_requirements(root_package: dict[str, Any]) -> dict[str, dict[str, Any]]:
    requirements: dict[str, dict[str, Any]] = {}
    sections = (
        ("runtime", "dependencies"),
        ("optional", "optionalDependencies"),
        ("development", "devDependencies"),
        ("peer", "peerDependencies"),
    )
    for scope, section in sections:
        values = root_package.get(section, {})
        if not isinstance(values, dict):
            raise DependencyError(f"npm root {section} must be an object")
        for name, requested in values.items():
            if not isinstance(name, str) or not name:
                raise DependencyError(f"npm root {section} contains an invalid name")
            if not isinstance(requested, str):
                raise DependencyError(
                    f"npm root {section} requirements must be strings"
                )
            requirements.setdefault(name, {"scope": scope, "requested": requested})
    return requirements


def _npm_package_name(package_path: str, entry: dict[str, Any]) -> str:
    if "\\" in package_path or package_path.startswith("/"):
        raise DependencyError(f"invalid npm package path: {package_path}")
    segments = package_path.split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        raise DependencyError(f"invalid npm package path: {package_path}")
    marker = "node_modules/"
    if marker in package_path:
        name = package_path.rsplit(marker, 1)[1]
    else:
        name = entry.get("name")
    if not isinstance(name, str) or not name:
        raise DependencyError(f"npm package has no name: {package_path}")
    return name


def _npm_record(
    package_path: str,
    entry: dict[str, Any],
    direct_requirements: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    name = _npm_package_name(package_path, entry)
    version = entry.get("version")
    integrity = entry.get("integrity")
    link = entry.get("link", False)
    if version is not None and not isinstance(version, str):
        raise DependencyError(f"npm package version must be a string: {package_path}")
    if integrity is not None and not isinstance(integrity, str):
        raise DependencyError(f"npm package integrity must be a string: {package_path}")
    if not isinstance(link, bool):
        raise DependencyError(f"npm package link flag must be boolean: {package_path}")
    top_level_path = f"node_modules/{name}"
    direct = direct_requirements.get(name) if package_path == top_level_path else None
    return {
        "name": name,
        "path": package_path,
        "version": version,
        "integrity": integrity,
        "direct": direct is not None,
        "scope": direct["scope"] if direct is not None else "transitive",
        "requested": direct["requested"] if direct is not None else None,
        "link": link,
    }


def _load_npm_packages(
    packages: dict[str, Any],
    limits: DependencyLimits,
) -> dict[str, dict[str, Any]]:
    root_package = packages.get("", {})
    if not isinstance(root_package, dict):
        raise DependencyError("npm root package must be an object")
    direct_requirements = _npm_direct_requirements(root_package)
    records: dict[str, dict[str, Any]] = {}
    for package_path in sorted(packages):
        if package_path == "":
            continue
        entry = packages[package_path]
        if not isinstance(package_path, str) or not isinstance(entry, dict):
            raise DependencyError("npm packages must map paths to objects")
        _add_record(
            records,
            package_path,
            _npm_record(package_path, entry, direct_requirements),
            limits,
        )
    return records


def _load_npm_v1_dependencies(
    dependencies: dict[str, Any],
    limits: DependencyLimits,
) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}

    def visit(values: dict[str, Any], parent_path: str, depth: int) -> None:
        if depth > 64:
            raise DependencyLimitError("npm dependency nesting limit exceeded")
        for name in sorted(values):
            entry = values[name]
            if not isinstance(name, str) or not name or not isinstance(entry, dict):
                raise DependencyError("npm dependencies must map names to objects")
            package_path = f"{parent_path}node_modules/{name}"
            direct_requirements = (
                {name: {"scope": "runtime", "requested": None}}
                if not parent_path
                else {}
            )
            _add_record(
                records,
                package_path,
                _npm_record(package_path, entry, direct_requirements),
                limits,
            )
            nested = entry.get("dependencies", {})
            if not isinstance(nested, dict):
                raise DependencyError(
                    f"nested npm dependencies must be an object: {package_path}"
                )
            visit(nested, f"{package_path}/", depth + 1)

    visit(dependencies, "", 0)
    return records


def _load_package_lock(content: bytes, limits: DependencyLimits) -> DependencyManifest:
    value = _parse_json(content)
    lockfile_version = value.get("lockfileVersion")
    if isinstance(lockfile_version, bool) or lockfile_version not in (1, 2, 3):
        raise DependencyError("package-lock.json lockfileVersion must be 1, 2, or 3")
    packages = value.get("packages")
    if packages is not None:
        if not isinstance(packages, dict):
            raise DependencyError("package-lock.json packages must be an object")
        records = _load_npm_packages(packages, limits)
    else:
        dependencies = value.get("dependencies")
        if not isinstance(dependencies, dict):
            raise DependencyError(
                "package-lock.json must contain packages or dependencies"
            )
        records = _load_npm_v1_dependencies(dependencies, limits)
    return DependencyManifest(
        ecosystem="npm",
        format="package-lock.json",
        content_sha256=hashlib.sha256(content).hexdigest(),
        records=records,
        details={"lockfileVersion": lockfile_version},
    )


def load_dependency_manifest(
    path_value: str | Path,
    limits: DependencyLimits | None = None,
) -> DependencyManifest:
    active_limits = limits or DependencyLimits()
    active_limits.validate()
    path, content = _read_manifest(path_value, active_limits)
    if path.name == "pyproject.toml" or path.suffix.lower() == ".toml":
        return _load_pyproject(content, active_limits)
    if path.name == "package-lock.json" or path.suffix.lower() == ".json":
        return _load_package_lock(content, active_limits)
    raise DependencyError(
        "supported dependency manifests are pyproject.toml and package-lock.json"
    )


def compare_dependency_manifests(
    before: str | Path,
    after: str | Path,
    limits: DependencyLimits | None = None,
) -> dict[str, Any]:
    active_limits = limits or DependencyLimits()
    active_limits.validate()
    before_manifest = load_dependency_manifest(before, active_limits)
    after_manifest = load_dependency_manifest(after, active_limits)
    if before_manifest.ecosystem != after_manifest.ecosystem:
        raise DependencyError("dependency manifests must use the same ecosystem")

    summary = {"added": 0, "removed": 0, "changed": 0, "unchanged": 0}
    changes: list[dict[str, Any]] = []
    keys = before_manifest.records.keys() | after_manifest.records.keys()
    for key in sorted(keys):
        old = before_manifest.records.get(key)
        new = after_manifest.records.get(key)
        if old is None and new is not None:
            summary["added"] += 1
            changes.append({"kind": "added", "key": key, "after": new})
        elif old is not None and new is None:
            summary["removed"] += 1
            changes.append({"kind": "removed", "key": key, "before": old})
        elif old == new:
            summary["unchanged"] += 1
        else:
            summary["changed"] += 1
            changes.append({"kind": "changed", "key": key, "before": old, "after": new})

    result: dict[str, Any] = {
        "schemaVersion": "whitehat-dependency-comparison-v1",
        "ok": True,
        "ecosystem": before_manifest.ecosystem,
        "limits": active_limits.as_dict(),
        "manifests": {
            "before": before_manifest.summary(),
            "after": after_manifest.summary(),
        },
        "summary": summary,
        "changes": changes,
        "effects": {
            "filesystemWrite": False,
            "network": False,
            "processCreation": False,
        },
    }
    canonical = json.dumps(
        result, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )
    result["resultSha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return result
