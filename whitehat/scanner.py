from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import stat
import sys
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .runner import ProcessLimits, RunnerError, RunnerLimitError, execute_fixed_profile


class ScannerError(Exception):
    """Base error for reviewed local scanner adapters."""

    exit_code = 3
    error_code = "invalid-input"


class ScannerLimitError(ScannerError):
    exit_code = 4
    error_code = "limit-exceeded"


@dataclass(frozen=True)
class ScannerLimits:
    max_entries: int = 20_000
    max_source_files: int = 1_000
    max_file_bytes: int = 1024 * 1024
    max_total_bytes: int = 16 * 1024 * 1024
    max_observations: int = 1_000
    timeout_seconds: float = 30.0
    max_stdout_bytes: int = 8 * 1024 * 1024
    max_stderr_bytes: int = 64 * 1024

    def validate(self) -> None:
        if isinstance(self.timeout_seconds, bool) or not isinstance(
            self.timeout_seconds, (int, float)
        ):
            raise ScannerLimitError("timeoutSeconds must be numeric")
        if not 0.05 <= float(self.timeout_seconds) <= 120.0:
            raise ScannerLimitError("timeoutSeconds must be between 0.05 and 120")
        for name, value in self.as_dict().items():
            if name == "timeoutSeconds":
                continue
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ScannerLimitError(f"{name} must be a positive integer")

    def as_dict(self) -> dict[str, int | float]:
        return {
            "maxEntries": self.max_entries,
            "maxSourceFiles": self.max_source_files,
            "maxFileBytes": self.max_file_bytes,
            "maxTotalBytes": self.max_total_bytes,
            "maxObservations": self.max_observations,
            "timeoutSeconds": self.timeout_seconds,
            "maxStdoutBytes": self.max_stdout_bytes,
            "maxStderrBytes": self.max_stderr_bytes,
        }

    def process_limits(self) -> ProcessLimits:
        return ProcessLimits(
            timeout_seconds=self.timeout_seconds,
            max_input_bytes=1,
            max_stdout_bytes=self.max_stdout_bytes,
            max_stderr_bytes=self.max_stderr_bytes,
        )


RUFF_VERSION = "0.14.14"
_SOURCE_SUFFIXES = frozenset({".py", ".pyi"})
_EXCLUDED_DIRECTORIES = frozenset({".git", ".venv", "__pycache__", "venv"})


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _checked_source_root(value: str | os.PathLike[str]) -> Path:
    path = Path(value)
    if path.is_symlink():
        raise ScannerError("scanner source root must not be a symbolic link")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ScannerError(f"scanner source root is unavailable: {exc}") from exc
    if not resolved.is_dir():
        raise ScannerError("scanner source root must be a directory")
    return resolved


def _ruff_distribution_identity() -> str:
    try:
        distribution = importlib.metadata.distribution("ruff")
    except importlib.metadata.PackageNotFoundError as exc:
        raise ScannerError(
            f"Ruff {RUFF_VERSION} is required but is not installed"
        ) from exc
    if distribution.version != RUFF_VERSION:
        raise ScannerError(f"Ruff version must be exactly {RUFF_VERSION}")
    record = distribution.read_text("RECORD")
    if not record:
        raise ScannerError("Ruff distribution RECORD is unavailable")
    return hashlib.sha256(record.encode("utf-8")).hexdigest()


def _verify_ruff_version(executable: Path, workspace_root: Path | None) -> str:
    try:
        execution = execute_fixed_profile(
            profile="scanner.ruff.version",
            executable=executable,
            arguments=["-I", "-m", "ruff", "--version"],
            limits=ProcessLimits(
                timeout_seconds=5.0,
                max_input_bytes=1,
                max_stdout_bytes=1_024,
                max_stderr_bytes=1_024,
            ),
            workspace_root=workspace_root,
        )
    except (RunnerError, RunnerLimitError) as exc:
        raise ScannerError(str(exc)) from exc
    if execution.stderr:
        raise ScannerError("Ruff version check returned stderr")
    try:
        version_text = execution.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ScannerError("Ruff version output must be UTF-8") from exc
    expected = f"ruff {RUFF_VERSION}"
    if version_text != expected:
        raise ScannerError(f"Ruff version must be exactly {RUFF_VERSION}")
    return execution.executable_sha256


def _stable_file_bytes(path: Path, metadata: os.stat_result) -> bytes:
    try:
        content = path.read_bytes()
        after = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise ScannerError(f"cannot read scanner source: {path.name}: {exc}") from exc
    if len(content) != metadata.st_size:
        raise ScannerError(f"scanner source changed while reading: {path.name}")
    if (metadata.st_size, metadata.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ScannerError(f"scanner source changed while reading: {path.name}")
    return content


def _copy_sources(
    source_root: Path, destination: Path, limits: ScannerLimits
) -> dict[str, Any]:
    entry_count = 0
    file_count = 0
    total_bytes = 0
    records: list[dict[str, Any]] = []
    pending: deque[Path] = deque([source_root])

    while pending:
        directory = pending.popleft()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except OSError as exc:
            raise ScannerError(f"cannot enumerate scanner source: {exc}") from exc
        child_directories: list[Path] = []
        for entry in entries:
            entry_count += 1
            if entry_count > limits.max_entries:
                raise ScannerLimitError("scanner source entry limit exceeded")
            relative = Path(entry.path).relative_to(source_root)
            relative_text = relative.as_posix()
            try:
                if entry.is_symlink():
                    raise ScannerError(
                        f"scanner source link is unsupported: {relative_text}"
                    )
                if entry.is_dir(follow_symlinks=False):
                    if entry.name not in _EXCLUDED_DIRECTORIES:
                        child_directories.append(Path(entry.path))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise ScannerError(
                        f"scanner source contains an unsupported entry: {relative_text}"
                    )
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise ScannerError(
                    f"cannot inspect scanner source: {relative_text}: {exc}"
                ) from exc
            if relative.suffix.lower() not in _SOURCE_SUFFIXES:
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ScannerError(f"scanner source must be regular: {relative_text}")
            file_count += 1
            if file_count > limits.max_source_files:
                raise ScannerLimitError("scanner source file limit exceeded")
            if metadata.st_size > limits.max_file_bytes:
                raise ScannerLimitError(
                    f"scanner per-file byte limit exceeded: {relative_text}"
                )
            total_bytes += metadata.st_size
            if total_bytes > limits.max_total_bytes:
                raise ScannerLimitError("scanner aggregate byte limit exceeded")
            content = _stable_file_bytes(Path(entry.path), metadata)
            copied = destination / relative
            copied.parent.mkdir(parents=True, exist_ok=True)
            try:
                copied.write_bytes(content)
            except OSError as exc:
                raise ScannerError(
                    f"cannot prepare scanner workspace: {relative_text}: {exc}"
                ) from exc
            records.append(
                {
                    "path": relative_text,
                    "size": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
            )
        pending.extend(child_directories)

    if not records:
        raise ScannerError("scanner source contains no Python files")
    records.sort(key=lambda item: item["path"])
    tree_sha256 = hashlib.sha256(_canonical_json(records)).hexdigest()
    return {
        "files": file_count,
        "bytes": total_bytes,
        "treeSha256": tree_sha256,
        "records": records,
    }


def _positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ScannerError(f"Ruff {label} must be a positive integer")
    return value


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ScannerError(f"Ruff output contains a duplicate JSON key: {key}")
        value[key] = item
    return value


def normalize_ruff_output(
    output: bytes,
    copied_source_root: Path,
    max_observations: int,
) -> list[dict[str, Any]]:
    try:
        values = json.loads(
            output.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except ScannerError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ScannerError("Ruff output must be a UTF-8 JSON array") from exc
    if not isinstance(values, list):
        raise ScannerError("Ruff output must be a JSON array")
    if len(values) > max_observations:
        raise ScannerLimitError("Ruff observation limit exceeded")
    source_root = copied_source_root.resolve(strict=False)
    observations: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for value in values:
        if not isinstance(value, dict):
            raise ScannerError("Ruff observation must be an object")
        code = value.get("code")
        filename = value.get("filename")
        location = value.get("location")
        end_location = value.get("end_location")
        if not isinstance(code, str) or not code or not isinstance(filename, str):
            raise ScannerError("Ruff observation identity is invalid")
        if not isinstance(location, dict) or not isinstance(end_location, dict):
            raise ScannerError("Ruff observation location is invalid")
        try:
            observed_path = Path(filename).resolve(strict=False)
            relative = observed_path.relative_to(source_root).as_posix()
        except (OSError, RuntimeError, ValueError) as exc:
            raise ScannerError(
                "Ruff observation path escaped the copied source root"
            ) from exc
        row = _positive_integer(location.get("row"), "row")
        column = _positive_integer(location.get("column"), "column")
        end_row = _positive_integer(end_location.get("row"), "end row")
        end_column = _positive_integer(end_location.get("column"), "end column")
        identity = (relative, row, column, end_row, end_column, code)
        if identity in seen:
            raise ScannerError("Ruff output contains a duplicate observation")
        seen.add(identity)
        observations.append(
            {
                "code": code,
                "path": relative,
                "location": {
                    "row": row,
                    "column": column,
                    "endRow": end_row,
                    "endColumn": end_column,
                },
                "fixAvailable": value.get("fix") is not None,
            }
        )
    observations.sort(
        key=lambda item: (
            item["path"],
            item["location"]["row"],
            item["location"]["column"],
            item["code"],
        )
    )
    return observations


def scan_with_ruff(
    source: str | os.PathLike[str],
    limits: ScannerLimits | None = None,
    workspace_root: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    active_limits = limits or ScannerLimits()
    active_limits.validate()
    source_root = _checked_source_root(source)
    try:
        workspace_parent = (
            Path(workspace_root).resolve(strict=True)
            if workspace_root is not None
            else None
        )
    except (OSError, RuntimeError) as exc:
        raise ScannerError(f"workspace root is unavailable: {exc}") from exc
    if workspace_parent is not None and not workspace_parent.is_dir():
        raise ScannerError("workspace root must be a directory")
    distribution_sha256 = _ruff_distribution_identity()
    executable = Path(sys.executable).resolve(strict=True)
    executable_sha256 = _verify_ruff_version(executable, workspace_parent)
    source_summary: dict[str, Any] = {}
    copied_root: Path | None = None

    def prepare(workspace: Path) -> None:
        nonlocal source_summary, copied_root
        copied_root = workspace / "source"
        copied_root.mkdir()
        source_summary = _copy_sources(source_root, copied_root, active_limits)

    def arguments(workspace: Path) -> list[str]:
        return [
            "-I",
            "-m",
            "ruff",
            "check",
            "--isolated",
            "--no-cache",
            "--output-format",
            "json",
            "--no-fix",
            "--no-preview",
            "--select",
            "E4,E7,E9,F",
            "--target-version",
            "py311",
            str(workspace / "source"),
        ]

    try:
        execution = execute_fixed_profile(
            profile="scanner.ruff.check",
            executable=executable,
            arguments=arguments,
            limits=active_limits.process_limits(),
            workspace_root=workspace_parent,
            prepare=prepare,
            accepted_exit_codes=frozenset({0, 1}),
        )
    except RunnerLimitError as exc:
        raise ScannerLimitError(str(exc)) from exc
    except RunnerError as exc:
        raise ScannerError(str(exc)) from exc
    if execution.executable_sha256 != executable_sha256:
        raise ScannerError("Ruff executable identity changed after version check")
    if execution.stderr:
        raise ScannerError("Ruff scan returned stderr")
    if copied_root is None:
        raise ScannerError("Ruff workspace was not prepared")
    observations = normalize_ruff_output(
        execution.stdout,
        copied_root,
        active_limits.max_observations,
    )
    code_counts = dict(sorted(Counter(item["code"] for item in observations).items()))
    source_summary.pop("records")
    result: dict[str, Any] = {
        "schemaVersion": "whitehat-scanner-result-v1",
        "ok": True,
        "adapter": {
            "id": "ruff",
            "adapterVersion": "1",
            "toolVersion": RUFF_VERSION,
            "executableSha256": executable_sha256,
            "distributionRecordSha256": distribution_sha256,
            "rules": ["E4", "E7", "E9", "F"],
            "targetVersion": "py311",
        },
        "limits": active_limits.as_dict(),
        "source": source_summary,
        "summary": {"observations": len(observations), "codes": code_counts},
        "observations": observations,
        "process": execution.receipt(),
        "claims": {
            "findingValidityEstablished": False,
            "impactEstablished": False,
            "severityEstablished": False,
            "submissionAuthorized": False,
        },
        "effects": {
            "arbitraryCommand": False,
            "network": False,
            "processCreation": True,
            "sourceCopied": True,
            "sourceExecuted": False,
            "workspaceCleaned": execution.workspace_cleaned,
        },
    }
    result["resultSha256"] = hashlib.sha256(_canonical_json(result)).hexdigest()
    return result
