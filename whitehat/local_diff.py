from __future__ import annotations

import hashlib
import json
import os
import stat
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class DiffError(Exception):
    """Base error for bounded local directory comparison."""

    exit_code = 3
    error_code = "invalid-input"


class DiffLimitError(DiffError):
    exit_code = 4
    error_code = "limit-exceeded"


@dataclass(frozen=True)
class DiffLimits:
    max_entries: int = 20_000
    max_files: int = 10_000
    max_file_bytes: int = 64 * 1024 * 1024
    max_total_bytes: int = 512 * 1024 * 1024

    def validate(self) -> None:
        for name, value in self.as_dict().items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise DiffLimitError(f"{name} must be a positive integer")

    def as_dict(self) -> dict[str, int]:
        return {
            "maxEntries": self.max_entries,
            "maxFiles": self.max_files,
            "maxFileBytes": self.max_file_bytes,
            "maxTotalBytes": self.max_total_bytes,
        }


@dataclass(frozen=True)
class FileRecord:
    size: int
    sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {"size": self.size, "sha256": self.sha256}


def _checked_root(value: str | os.PathLike[str], label: str) -> Path:
    path = Path(value)
    if path.is_symlink():
        raise DiffError(f"{label} root must not be a symbolic link")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise DiffError(f"{label} root is unavailable: {exc}") from exc
    if not resolved.is_dir():
        raise DiffError(f"{label} root must be a directory")
    return resolved


def _hash_regular_file(path: Path, initial: os.stat_result) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise DiffError(f"unsupported file type: {path.name}")
            if not _same_file_state(initial, opened):
                raise DiffError(f"file changed before hashing: {path.name}")
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
            final_open = os.fstat(stream.fileno())
    except OSError as exc:
        raise DiffError(f"cannot read {path.name}: {exc}") from exc

    try:
        final_path = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise DiffError(f"cannot recheck {path.name}: {exc}") from exc
    if not _same_file_state(initial, final_open):
        raise DiffError(f"file changed while hashing: {path.name}")
    if not _same_file_state(final_open, final_path):
        raise DiffError(f"file changed after hashing: {path.name}")
    return digest.hexdigest()


def _same_file_state(left: os.stat_result, right: os.stat_result) -> bool:
    if (left.st_size, left.st_mtime_ns) != (right.st_size, right.st_mtime_ns):
        return False
    for field in ("st_dev", "st_ino"):
        left_value = getattr(left, field, 0)
        right_value = getattr(right, field, 0)
        if left_value and right_value and left_value != right_value:
            return False
    return True


def _scan(root: Path, limits: DiffLimits) -> dict[str, FileRecord]:
    records: dict[str, FileRecord] = {}
    total_bytes = 0
    entry_count = 0
    pending: deque[Path] = deque([root])

    while pending:
        directory = pending.popleft()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except OSError as exc:
            raise DiffError(f"cannot enumerate a directory: {exc}") from exc

        child_directories: list[Path] = []
        for entry in entries:
            entry_count += 1
            if entry_count > limits.max_entries:
                raise DiffLimitError("directory entry limit exceeded")
            relative = Path(entry.path).relative_to(root).as_posix()
            try:
                if entry.is_symlink():
                    raise DiffError(f"symbolic links are unsupported: {relative}")
                if entry.is_dir(follow_symlinks=False):
                    child_directories.append(Path(entry.path))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise DiffError(f"unsupported filesystem entry: {relative}")
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise DiffError(f"cannot inspect {relative}: {exc}") from exc
            if not stat.S_ISREG(metadata.st_mode):
                raise DiffError(f"unsupported file type: {relative}")
            if len(records) + 1 > limits.max_files:
                raise DiffLimitError("file count limit exceeded")
            if metadata.st_size > limits.max_file_bytes:
                raise DiffLimitError(f"per-file byte limit exceeded: {relative}")
            total_bytes += metadata.st_size
            if total_bytes > limits.max_total_bytes:
                raise DiffLimitError("aggregate byte limit exceeded")
            records[relative] = FileRecord(
                size=metadata.st_size,
                sha256=_hash_regular_file(Path(entry.path), metadata),
            )
        pending.extend(child_directories)
    return records


def _tree_sha256(records: dict[str, FileRecord]) -> str:
    canonical = [
        {"path": path, "sha256": records[path].sha256, "size": records[path].size}
        for path in sorted(records)
    ]
    payload = json.dumps(canonical, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compare_directories(
    before: str | os.PathLike[str],
    after: str | os.PathLike[str],
    limits: DiffLimits | None = None,
) -> dict[str, Any]:
    active_limits = limits or DiffLimits()
    active_limits.validate()
    before_root = _checked_root(before, "before")
    after_root = _checked_root(after, "after")
    if before_root == after_root:
        raise DiffError("before and after roots must be different")

    before_records = _scan(before_root, active_limits)
    after_records = _scan(after_root, active_limits)
    changes: list[dict[str, Any]] = []
    summary = {"added": 0, "deleted": 0, "modified": 0, "unchanged": 0}

    for path in sorted(before_records.keys() | after_records.keys()):
        old = before_records.get(path)
        new = after_records.get(path)
        if old is None and new is not None:
            summary["added"] += 1
            changes.append({"kind": "added", "path": path, "after": new.as_dict()})
        elif old is not None and new is None:
            summary["deleted"] += 1
            changes.append({"kind": "deleted", "path": path, "before": old.as_dict()})
        elif old == new:
            summary["unchanged"] += 1
        else:
            summary["modified"] += 1
            assert old is not None and new is not None
            changes.append(
                {
                    "kind": "modified",
                    "path": path,
                    "before": old.as_dict(),
                    "after": new.as_dict(),
                }
            )

    result: dict[str, Any] = {
        "schemaVersion": "whitehat-local-diff-v1",
        "ok": True,
        "limits": active_limits.as_dict(),
        "summary": summary,
        "trees": {
            "before": {"files": len(before_records), "sha256": _tree_sha256(before_records)},
            "after": {"files": len(after_records), "sha256": _tree_sha256(after_records)},
        },
        "changes": changes,
        "effects": {"filesystemWrite": False, "network": False, "processCreation": False},
    }
    canonical = json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    result["resultSha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return result
