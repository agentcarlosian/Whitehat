"""Reviewed native tools: literal release identities, fixed arguments, copied inputs."""
from __future__ import annotations

import hashlib
import os
import platform
import stat
from pathlib import Path
from typing import Any

from .reports import ReportError, ReportLimitError, canonical, normalize, parse_json, result_document
from .runner import execute_fixed_profile
from .scanner import ScannerLimits
from .security_rules import SECRET_CONFIG
from .source_profiles import PROFILES


# Release asset SHA-256s from GitHub's official release API, verified 2026-09-14.
# Member SHA-256s are verified against those archives during explicit setup.
TOOLS = {
    "oasdiff": {
        "version": "1.32.0", "license": "Apache-2.0", "repo": "oasdiff/oasdiff",
        "platforms": {
            "windows-x64": {"asset": "oasdiff_1.32.0_windows_amd64.tar.gz",
                "sha256": "163fde638f5ad8381e0d09d380cdb5c00ef496c6bd3a8fcefd2608f649aa72f4",
                "executable": "oasdiff.exe", "members": {"oasdiff.exe": "61deb49f5ea72d64928456abf4bc79cca12747f3f4ef742ff238dc11e3985ee8"}},
            "linux-x64": {"asset": "oasdiff_1.32.0_linux_amd64.tar.gz",
                "sha256": "5b2050787cfee2a9a3ba7b25cb50fe2c5cc45cdf5b96fbc51a4a60107f8b4aad",
                "executable": "oasdiff", "members": {"oasdiff": "602607fe1356edce5665c54eed41325425860e973fc4c72833a5440334fa70ab"}},
        },
    },
    "opengrep": {
        "version": "1.30.0", "license": "LGPL-2.1", "repo": "opengrep/opengrep",
        "platforms": {
            "windows-x64": {
                "asset": "opengrep-core_windows_x86.zip",
                "sha256": "d21382af5eb1a99c637af08abc1e45ff0d35f7e749c66f12534207479abc780f",
                "executable": "opengrep-core.exe",
                "members": {
                    "opengrep-core.exe": "3562aa61fcbb79ad4a1a2771c45467f2c71ac8ba0c4dcbd94f53d3e7cf8b1ed7",
                    "libgcc_s_seh-1.dll": "645763b1b6f52c6a755444dfb781e6a606e1fda3061b2a3d9806780bb3dc54b4",
                    "libgmp-10.dll": "c188e570157c109181e6788c2837fcead79747a7b10209cd82ebf5365787f508",
                    "libstdc++-6.dll": "6244b77e3635c735ec7d463dcd748beef08a7e6facfa6e47e5463f388fa3b178",
                    "libpcre2-8-0.dll": "c108236a48d51608fe2afc4178fed846f517bf7058dc34955646c54decafd7f4",
                    "libwinpthread-1.dll": "fe0259c7c8bf875cce79dc63f7af2c350138e77e60c51cb44d35aaee4d45e3ee",
                    "libzstd-1.dll": "bbf5c934a2a80cf28b944e2e493aef3b4886fa6f9b4b026f42531f3f53c62907",
                },
            },
            "linux-x64": {
                "asset": "opengrep-core_linux_x86.tar.gz",
                "sha256": "2a8a6c2f87541b9af04a3902eae6e17e5a87865f05b0eaf3955a5ae0e47ad432",
                "executable": "opengrep-core",
                "members": {"opengrep-core": "09b70ad77f2c1ae147080eb5ee611e40021c5f3cee3726c48178bfd7017a8320"},
            },
        },
    },
    "betterleaks": {
        "version": "1.8.1", "license": "MIT", "repo": "betterleaks/betterleaks",
        "platforms": {
            "windows-x64": {
                "asset": "betterleaks_1.8.1_windows_x64.zip",
                "sha256": "94310d028285a1bcce7f160bc19eb62f87de6460c95bfd4319151ef5b501ed3f",
                "executable": "betterleaks.exe",
                "members": {"betterleaks.exe": "727820f1a9f9264319cc50458b99f01acbb93e93df7a39b8eaa2715a7b1aaed5"},
            },
            "linux-x64": {
                "asset": "betterleaks_1.8.1_linux_x64.tar.gz",
                "sha256": "efa407244e1ea8e35f582b8a42becdeac08bdead04f68eb752adda722d583c2a",
                "executable": "betterleaks",
                "members": {"betterleaks": "380a770d9ea9215e7d3b964246a72d8698b2975496addef2627d0e82b174a1f8"},
            },
        },
    },
}
_EXCLUDED = frozenset({".git", ".venv", "venv", "node_modules", "vendor", "__pycache__", ".whitehat", "build", "dist"})
_LANGUAGES = {".py": "python", ".js": "javascript"}
_TEXT_SUFFIXES = frozenset({".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".toml", ".yaml", ".yml", ".env", ".txt", ".ini", ".cfg", ".sh", ".md", ".xml", ".properties"})


def platform_key() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if machine not in {"amd64", "x86_64"} or system not in {"windows", "linux"}:
        raise ReportError("native adapters support Windows/Linux x64; report imports support other platforms")
    return f"{system}-x64"


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def verify_tool(tool: str, executable_value: str | Path) -> tuple[Path, dict[str, Any]]:
    if tool not in TOOLS:
        raise ReportError("unknown native adapter")
    spec = TOOLS[tool]["platforms"][platform_key()]
    candidate = Path(executable_value)
    if candidate.is_symlink() or not candidate.is_file():
        raise ReportError("tool executable is missing or is a link; run the explicit tool setup")
    executable = candidate.resolve()
    if executable.name != spec["executable"]:
        raise ReportError("tool executable filename does not match the reviewed profile")
    try:
        if platform_key() == "windows-x64":
            unknown_dlls = {p.name for p in executable.parent.iterdir() if p.suffix.lower() == ".dll"} - set(spec["members"])
            if unknown_dlls:
                raise ReportError("native tool directory contains an unreviewed DLL")
        for name, digest in spec["members"].items():
            member = executable.parent / name
            if member.is_symlink() or not member.is_file() or file_hash(member) != digest:
                raise ReportError(f"{tool} binary or companion hash mismatch: {name}")
    except OSError as exc:
        raise ReportError("cannot verify native tool") from exc
    return executable, spec


def _is_link(path: Path) -> bool:
    return path.is_symlink() or getattr(path, "is_junction", lambda: False)()


def copy_inputs(root: Path, destination: Path, tool: str, limits: ScannerLimits,
                languages: dict[str, str] | None = None) -> list[dict[str, Any]]:
    languages = languages or _LANGUAGES
    records = []
    pending = [root]
    entries_seen = total = 0
    while pending:
        directory = pending.pop()
        if _is_link(directory):
            raise ReportError("source directory links are unsupported")
        with os.scandir(directory) as iterator:
            entries = []
            for entry in iterator:
                entries_seen += 1
                if entries_seen > limits.max_entries:
                    raise ReportLimitError("source entry limit exceeded")
                entries.append(entry)
        for entry in sorted(entries, key=lambda v: v.name):
            path = Path(entry.path)
            if _is_link(path):
                raise ReportError("source links are unsupported")
            if entry.is_dir(follow_symlinks=False):
                if entry.name not in _EXCLUDED:
                    pending.append(path)
                continue
            if not entry.is_file(follow_symlinks=False):
                raise ReportError("source contains a non-regular entry")
            suffix = path.suffix.lower()
            if tool == "opengrep" and suffix not in languages:
                continue
            if tool == "betterleaks" and suffix not in _TEXT_SUFFIXES and path.name != ".env":
                continue
            relative = path.relative_to(root).as_posix()
            initial = path.stat(follow_symlinks=False)
            if len(records) >= limits.max_source_files or initial.st_size > limits.max_file_bytes:
                raise ReportLimitError("source file/count limit exceeded")
            with path.open("rb") as stream:
                opened = os.fstat(stream.fileno())
                if not stat.S_ISREG(opened.st_mode) or (opened.st_ino, opened.st_size) != (initial.st_ino, initial.st_size):
                    raise ReportError("source changed before reading")
                raw = stream.read(limits.max_file_bytes + 1)
                final = os.fstat(stream.fileno())
            after = path.stat(follow_symlinks=False)
            def identity(s: os.stat_result) -> tuple[int, int, int]:
                return (s.st_ino, s.st_size, s.st_mtime_ns)
            if len(raw) != initial.st_size or identity(initial) != identity(final) or identity(final) != identity(after):
                raise ReportError("source changed while reading")
            total += len(raw)
            if total > limits.max_total_bytes:
                raise ReportLimitError("source aggregate byte limit exceeded")
            copied = destination / relative
            copied.parent.mkdir(parents=True, exist_ok=True)
            copied.write_bytes(raw)
            records.append({"path": relative, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    if not records:
        raise ReportError("no supported source files; see tools compatibility")
    return sorted(records, key=lambda v: v["path"])


def scan_native(source: str, tool: str, tool_path: str | None = None,
                limits: ScannerLimits | None = None, *, profile: str = "basic") -> dict[str, Any]:
    if profile not in PROFILES or (tool != "opengrep" and profile != "basic"):
        raise ReportError("unsupported source analysis profile")
    selected = PROFILES[profile]
    languages = selected["languages"]
    limits = limits or ScannerLimits()
    limits.validate()
    # The shared process supervisor currently enforces a 30-second upper bound.
    if limits.timeout_seconds > 30:
        raise ReportLimitError("native scan timeout must be at most 30 seconds")
    if tool not in {"opengrep", "betterleaks"}:
        raise ReportError("unsupported native scanner")
    spec = TOOLS[tool]["platforms"][platform_key()]
    executable, _ = verify_tool(tool, tool_path or Path(".whitehat/tools") / tool / spec["executable"])
    source_path = Path(source)
    if _is_link(source_path) or not source_path.is_dir():
        raise ReportError("source must be an existing directory, not a link")
    source_root = source_path.resolve()
    records: list[dict[str, Any]] = []
    copied_root: Path | None = None
    config = canonical({"rules": selected["rules"]}) if tool == "opengrep" else SECRET_CONFIG.encode("utf-8")

    def prepare(workspace: Path) -> None:
        nonlocal records, copied_root
        copied_root = workspace / "source"
        copied_root.mkdir()
        records = copy_inputs(source_root, copied_root, tool, limits, languages)
        (workspace / "rules.json" if tool == "opengrep" else workspace / "secrets.toml").write_bytes(config)
        if tool == "opengrep":
            targets = [["CodeTarget", {"path": str(copied_root / r["path"]),
                "analyzer": languages[Path(r["path"]).suffix.lower()], "products": ["sast"]}] for r in records]
            (workspace / "targets.json").write_bytes(canonical(targets))

    def arguments(workspace: Path) -> list[str]:
        if tool == "opengrep":
            return ["-rules", str(workspace / "rules.json"), "-targets", str(workspace / "targets.json"),
                    "-json_nodots", "-j", "1", "-timeout", "3", "-max_memory", "512"]
        return ["dir", str(workspace / "source"), "--config", str(workspace / "secrets.toml"),
                "--report-format", "json", "--report-path", "-", "--redact=100", "--no-banner", "--no-color",
                "--log-level", "error", "--validation=false", "--max-archive-depth", "0",
                "--max-decode-depth", "0", "--ignore-gitleaks-allow", "--timeout", "25"]

    try:
        execution = execute_fixed_profile(profile=f"scanner.{tool}.research", executable=executable,
            arguments=arguments, prepare=prepare, limits=limits.process_limits(),
            accepted_exit_codes=frozenset({0}) if tool == "opengrep" else frozenset({0, 1}))
        verify_tool(tool, executable)
    except OSError as exc:
        raise ReportError("native scan file operation failed") from exc
    assert copied_root is not None
    parsed = parse_json(execution.stdout)
    if tool == "opengrep":
        if not isinstance(parsed, dict) or parsed.get("version") != TOOLS[tool]["version"]:
            raise ReportError("Opengrep result version mismatch")
        scanned = parsed.get("paths", {}).get("scanned", [])
        expected_paths = {str(copied_root / r["path"]).replace("\\", "/") for r in records}
        if (not isinstance(scanned, list) or {v.replace("\\", "/") for v in scanned} != expected_paths
                or parsed.get("skipped_rules") or parsed.get("paths", {}).get("skipped")):
            raise ReportError("Opengrep scan coverage was incomplete")
    observations = normalize(execution.stdout, tool, str(copied_root))
    if len(observations) > limits.max_observations:
        raise ReportLimitError("native observation limit exceeded")
    if tool == "betterleaks" and ((execution.exit_code == 0 and observations) or (execution.exit_code == 1 and not observations)):
        raise ReportError("secret detector exit/result mismatch")
    for item in observations:
        if tool == "opengrep":
            if item["ruleId"] not in selected["explanations"]:
                raise ReportError("Opengrep emitted an unreviewed rule")
            item["explanation"] = selected["explanations"][item["ruleId"]]
            item["severityReported"] = "warning"
            if item["path"] not in {r["path"] for r in records}:
                raise ReportError("native observation references an uncopied file")
            context = item.get("sourceContext", {})
            locations = context.get("relatedLocations", []) + [step["location"] for flow in context.get("flows", []) for step in flow["steps"]]
            if any(loc is not None and loc["path"] not in {r["path"] for r in records} for loc in locations):
                raise ReportError("native flow references an uncopied file")
    return result_document(observations, {
        "kind": "native-scan", "tool": tool, "toolVersion": TOOLS[tool]["version"],
        "executableSha256": spec["members"][spec["executable"]],
        "configSha256": hashlib.sha256(config).hexdigest(), "rulesVersion": selected["rulesVersion"] if tool == "opengrep" else "1",
        **({"analysisProfile": selected["rulesVersion"], "taintScope": "single-function"} if profile != "basic" else {}),
        "sourceTreeSha256": hashlib.sha256(canonical(records)).hexdigest(),
        "sourceFiles": len(records), "sourceBytes": sum(r["bytes"] for r in records),
        "sourceSuffixes": sorted(languages if tool == "opengrep" else _TEXT_SUFFIXES),
        "excludedDirectories": sorted(_EXCLUDED), "process": execution.receipt(),
        "executionVerified": True, "osSandboxEnforced": False,
    }, effects={"network": False, "processCreation": True, "sourceExecuted": False,
                "sourceCopied": True, "workspaceCleaned": execution.workspace_cleaned,
                "credentialValidation": False})


def toolkit_status() -> dict[str, Any]:
    return {"schemaVersion": "whitehat-toolkit-v1", "ok": True,
        "native": [{"tool": name, "version": spec["version"], "license": spec["license"],
                    "platforms": sorted(spec["platforms"])} for name, spec in TOOLS.items()],
        "imports": ["opengrep", "osv", "sarif", "zap", "nuclei", "betterleaks", "gitleaks"],
        "pythonExtras": [
            {"tool": "hypothesis", "version": "6.168.0", "extra": "fuzz", "platforms": ["core-python"]},
            {"tool": "graphql-core", "version": "3.2.12", "extra": "graphql", "platforms": ["core-python"]},
            {"tool": "atheris", "version": "3.1.0", "extra": "source-fuzz", "platforms": ["linux-x64-python3.12-3.14"]}],
        "concreteRequestBatches": True,
        "sourceProfiles": {name: {"rulesVersion": value["rulesVersion"], "sourceSuffixes": sorted(value["languages"])} for name, value in PROFILES.items()},
        "setup": "python scripts/setup_tools.py --destination .whitehat/tools",
        "networkScanning": False}
