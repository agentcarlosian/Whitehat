from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class RecordError(Exception):
    """Base error for explicit local result and review storage."""

    exit_code = 3
    error_code = "invalid-input"


class RecordLimitError(RecordError):
    exit_code = 4
    error_code = "limit-exceeded"


SUPPORTED_RESULT_SCHEMAS = frozenset(
    {
        "whitehat-dependency-comparison-v1",
        "whitehat-local-diff-v1",
        "whitehat-local-inventory-v1",
        "whitehat-network-session-validation-v1",
        "whitehat-scanner-result-v1",
        "whitehat-synthetic-run-v1",
    }
)
REVIEW_DECISIONS = frozenset({"accepted", "dismissed", "needs-work"})
MAX_RESULT_BYTES = 64 * 1024 * 1024
MAX_NOTE_CHARACTERS = 4_000
MAX_AUTHOR_CHARACTERS = 200


def _canonical_json(document: dict[str, Any]) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RecordError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _parse_document(content: bytes) -> dict[str, Any]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RecordError("record must be UTF-8 JSON") from exc
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)
    except RecordError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise RecordError(f"invalid record JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise RecordError("record must be a JSON object")
    return value


def validate_result_document(document: dict[str, Any]) -> dict[str, Any]:
    schema_version = document.get("schemaVersion")
    if schema_version not in SUPPORTED_RESULT_SCHEMAS:
        raise RecordError("unsupported analysis result schema")
    if document.get("ok") is not True:
        raise RecordError("analysis result must have ok=true")
    result_sha256 = document.get("resultSha256")
    if not isinstance(result_sha256, str) or len(result_sha256) != 64:
        raise RecordError("analysis result has an invalid resultSha256")
    try:
        int(result_sha256, 16)
    except ValueError as exc:
        raise RecordError("analysis result has an invalid resultSha256") from exc
    payload = dict(document)
    del payload["resultSha256"]
    calculated = hashlib.sha256(_canonical_json(payload)).hexdigest()
    if calculated != result_sha256:
        raise RecordError("analysis result hash does not match its content")
    return document


def load_result_document(
    path_value: str | os.PathLike[str],
    max_bytes: int = MAX_RESULT_BYTES,
) -> dict[str, Any]:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise RecordLimitError("max result bytes must be a positive integer")
    path = Path(path_value)
    if path.is_symlink():
        raise RecordError("result path must not be a symbolic link")
    try:
        resolved = path.resolve(strict=True)
        before = resolved.stat(follow_symlinks=False)
    except (OSError, RuntimeError) as exc:
        raise RecordError(f"result is unavailable: {exc}") from exc
    if not resolved.is_file():
        raise RecordError("result must be a regular file")
    if before.st_size > max_bytes:
        raise RecordLimitError("result byte limit exceeded")
    try:
        content = resolved.read_bytes()
        after = resolved.stat(follow_symlinks=False)
    except OSError as exc:
        raise RecordError(f"cannot read result: {exc}") from exc
    if len(content) != before.st_size:
        raise RecordError("result changed while reading")
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise RecordError("result changed while reading")
    return validate_result_document(_parse_document(content))


def write_json_document(
    document: dict[str, Any],
    output_value: str | os.PathLike[str],
) -> Path:
    output = Path(output_value)
    if output.exists() or output.is_symlink():
        raise RecordError("output already exists")
    try:
        parent = output.parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RecordError(f"output parent is unavailable: {exc}") from exc
    if not parent.is_dir():
        raise RecordError("output parent must be a directory")
    destination = parent / output.name
    content = _canonical_json(document) + b"\n"
    created = False
    try:
        with destination.open("xb") as stream:
            created = True
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if destination.read_bytes() != content:
            raise RecordError("stored record failed readback verification")
    except RecordError:
        if created:
            destination.unlink(missing_ok=True)
        raise
    except OSError as exc:
        if created:
            destination.unlink(missing_ok=True)
        raise RecordError(f"cannot store record: {exc}") from exc
    return destination


def save_result_document(
    document: dict[str, Any],
    output_value: str | os.PathLike[str],
) -> Path:
    validate_result_document(document)
    if len(_canonical_json(document)) + 1 > MAX_RESULT_BYTES:
        raise RecordLimitError("stored result byte limit exceeded")
    return write_json_document(document, output_value)


def _bounded_text(value: str, label: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise RecordError(f"{label} must be text")
    normalized = value.strip()
    if not normalized:
        raise RecordError(f"{label} must not be empty")
    if len(normalized) > maximum:
        raise RecordLimitError(f"{label} character limit exceeded")
    if any(
        ord(character) < 32 and character not in "\n\r\t" for character in normalized
    ):
        raise RecordError(f"{label} contains unsupported control characters")
    return normalized


def _review_timestamp(value: datetime | None) -> str:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise RecordError("review timestamp must include a timezone")
    return (
        current.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def create_review_document(
    result: dict[str, Any],
    decision: str,
    note: str,
    author: str | None = None,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    validate_result_document(result)
    if decision not in REVIEW_DECISIONS:
        raise RecordError("review decision must be accepted, dismissed, or needs-work")
    review: dict[str, Any] = {
        "schemaVersion": "whitehat-local-review-v1",
        "reviewOf": {
            "schemaVersion": result["schemaVersion"],
            "resultSha256": result["resultSha256"],
        },
        "decision": decision,
        "note": _bounded_text(note, "review note", MAX_NOTE_CHARACTERS),
        "authorAssertion": (
            _bounded_text(author, "review author", MAX_AUTHOR_CHARACTERS)
            if author is not None
            else None
        ),
        "createdAt": _review_timestamp(created_at),
        "claims": {
            "authorityEstablished": False,
            "findingValidityEstablished": False,
            "impactEstablished": False,
            "submissionAuthorized": False,
        },
        "effects": {
            "externalAction": False,
            "localRecordWrite": True,
            "network": False,
            "resultMutation": False,
        },
    }
    review["reviewSha256"] = hashlib.sha256(_canonical_json(review)).hexdigest()
    return review
