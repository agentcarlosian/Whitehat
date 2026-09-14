from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


class NetworkSessionError(Exception):
    """Invalid local design contract for a future network session."""

    exit_code = 3
    error_code = "invalid-input"


class NetworkSessionLimitError(NetworkSessionError):
    exit_code = 4
    error_code = "limit-exceeded"


MAX_SESSION_BYTES = 256 * 1024
MAX_SESSION_DURATION = timedelta(hours=8)
_SESSION_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
_HOST = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
_STOP_CODE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_CAPABILITIES = frozenset({"http.observe"})
_METHODS = frozenset({"GET", "HEAD"})
_REQUIRED_STOPS = frozenset(
    {
        "budget-exhausted",
        "policy-expired",
        "rate-limited",
        "scope-mismatch",
        "session-expired",
        "unexpected-address",
        "unexpected-redirect",
        "user-stop",
    }
)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise NetworkSessionError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise NetworkSessionError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise NetworkSessionError(
            f"{label} fields do not match: missing={missing}, unexpected={unexpected}"
        )
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise NetworkSessionError(f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise NetworkSessionError(f"{label} must be an RFC3339 UTC timestamp") from exc
    if parsed.tzinfo != timezone.utc:
        raise NetworkSessionError(f"{label} must use UTC")
    return parsed


def _positive_integer(value: Any, label: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise NetworkSessionLimitError(f"{label} must be between 1 and {maximum}")
    return value


def _nonnegative_integer(value: Any, label: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= maximum
    ):
        raise NetworkSessionLimitError(f"{label} must be between 0 and {maximum}")
    return value


def _bounded_text(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise NetworkSessionError(f"{label} must be non-empty text")
    normalized = value.strip()
    if len(normalized) > maximum:
        raise NetworkSessionLimitError(f"{label} character limit exceeded")
    return normalized


def _policy_url(value: Any) -> str:
    if not isinstance(value, str):
        raise NetworkSessionError("authority.policyUrl must be text")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
    except ValueError as exc:
        raise NetworkSessionError(
            "authority.policyUrl must be a clean HTTPS URL"
        ) from exc
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise NetworkSessionError("authority.policyUrl must be a clean HTTPS URL")
    return value


def _validate_authority(value: Any) -> dict[str, Any]:
    authority = _exact_keys(
        value,
        {
            "policyUrl",
            "policyReviewedAt",
            "policyExpiresAt",
            "approverAssertion",
            "approvedAt",
        },
        "authority",
    )
    _policy_url(authority["policyUrl"])
    _bounded_text(authority["approverAssertion"], "authority.approverAssertion", 200)
    _timestamp(authority["policyReviewedAt"], "authority.policyReviewedAt")
    _timestamp(authority["policyExpiresAt"], "authority.policyExpiresAt")
    _timestamp(authority["approvedAt"], "authority.approvedAt")
    return authority


def _validate_target(value: Any, index: int, mode: str) -> dict[str, Any]:
    label = f"targets[{index}]"
    target = _exact_keys(
        value,
        {"scheme", "host", "port", "pathPrefixes", "methods"},
        label,
    )
    expected_scheme = "http" if mode == "owned-loopback" else "https"
    if target["scheme"] != expected_scheme:
        raise NetworkSessionError(f"{label}.scheme must be {expected_scheme}")
    host = target["host"]
    if mode == "owned-loopback":
        if host != "127.0.0.1":
            raise NetworkSessionError(f"{label}.host must be exact IPv4 loopback")
    elif (
        not isinstance(host, str)
        or host != host.lower()
        or "*" in host
        or _HOST.fullmatch(host) is None
        or ".." in host
        or any(len(label_part) > 63 for label_part in host.split("."))
    ):
        raise NetworkSessionError(f"{label}.host must be an exact lowercase DNS name")
    _positive_integer(target["port"], f"{label}.port", 65_535)
    prefixes = target["pathPrefixes"]
    if not isinstance(prefixes, list) or not 1 <= len(prefixes) <= 32:
        raise NetworkSessionLimitError(
            f"{label}.pathPrefixes must contain 1 to 32 paths"
        )
    if len(prefixes) != len(set(prefixes)):
        raise NetworkSessionError(f"{label}.pathPrefixes must be unique")
    for prefix in prefixes:
        if (
            not isinstance(prefix, str)
            or not prefix.startswith("/")
            or "\\" in prefix
            or "?" in prefix
            or "#" in prefix
            or any(ord(character) > 127 for character in prefix)
            or any(segment == ".." for segment in prefix.split("/"))
        ):
            raise NetworkSessionError(f"{label} contains an invalid path prefix")
    methods = target["methods"]
    if (
        not isinstance(methods, list)
        or not methods
        or len(methods) != len(set(methods))
        or any(method not in _METHODS for method in methods)
    ):
        raise NetworkSessionError(
            f"{label}.methods may contain unique GET and HEAD values"
        )
    return target


def _validate_budgets(value: Any) -> dict[str, Any]:
    budgets = _exact_keys(
        value,
        {
            "maxRequests",
            "maxConcurrency",
            "minDelayMs",
            "maxRequestBytes",
            "maxResponseBytes",
            "requestTimeoutSeconds",
            "maxWallSeconds",
        },
        "budgets",
    )
    _positive_integer(budgets["maxRequests"], "budgets.maxRequests", 10_000)
    _positive_integer(budgets["maxConcurrency"], "budgets.maxConcurrency", 16)
    _nonnegative_integer(budgets["minDelayMs"], "budgets.minDelayMs", 60_000)
    _positive_integer(
        budgets["maxRequestBytes"], "budgets.maxRequestBytes", 1024 * 1024
    )
    _positive_integer(
        budgets["maxResponseBytes"],
        "budgets.maxResponseBytes",
        64 * 1024 * 1024,
    )
    _positive_integer(
        budgets["requestTimeoutSeconds"],
        "budgets.requestTimeoutSeconds",
        60,
    )
    _positive_integer(budgets["maxWallSeconds"], "budgets.maxWallSeconds", 8 * 60 * 60)
    if budgets["maxConcurrency"] > budgets["maxRequests"]:
        raise NetworkSessionError("maxConcurrency cannot exceed maxRequests")
    if budgets["requestTimeoutSeconds"] > budgets["maxWallSeconds"]:
        raise NetworkSessionError("requestTimeoutSeconds cannot exceed maxWallSeconds")
    return budgets


def _validate_transport(value: Any, mode: str) -> dict[str, Any]:
    transport = _exact_keys(
        value,
        {
            "allowRedirects",
            "allowProxyEnvironment",
            "requireTlsVerification",
            "dnsPolicy",
        },
        "transport",
    )
    expected = (
        {
            "allowRedirects": False,
            "allowProxyEnvironment": False,
            "requireTlsVerification": False,
            "dnsPolicy": "loopback-address-only",
        }
        if mode == "owned-loopback"
        else {
            "allowRedirects": False,
            "allowProxyEnvironment": False,
            "requireTlsVerification": True,
            "dnsPolicy": "resolve-public-once-and-pin",
        }
    )
    if transport != expected:
        raise NetworkSessionError(
            "transport must use the fixed initial network boundary"
        )
    return transport


def _validate_effects(value: Any) -> dict[str, Any]:
    effects = _exact_keys(
        value,
        {"credentials", "targetMutation", "thirdPartyData", "contact", "submission"},
        "effects",
    )
    if any(item is not False for item in effects.values()):
        raise NetworkSessionError("all initial network-session effects must be false")
    return effects


def validate_network_session(
    document: dict[str, Any],
    evaluation_time: datetime | None = None,
) -> dict[str, Any]:
    session = _exact_keys(
        document,
        {
            "schemaVersion",
            "sessionId",
            "mode",
            "validFrom",
            "expiresAt",
            "authority",
            "capabilities",
            "targets",
            "budgets",
            "transport",
            "effects",
            "stopConditions",
        },
        "session",
    )
    if session["schemaVersion"] != "whitehat-network-session-v1":
        raise NetworkSessionError("unsupported network-session schemaVersion")
    if (
        not isinstance(session["sessionId"], str)
        or _SESSION_ID.fullmatch(session["sessionId"]) is None
    ):
        raise NetworkSessionError("sessionId is invalid")
    if session["mode"] not in {
        "owned-loopback",
        "owned-synthetic",
        "human-reviewed-program",
    }:
        raise NetworkSessionError("mode is invalid")

    valid_from = _timestamp(session["validFrom"], "validFrom")
    expires_at = _timestamp(session["expiresAt"], "expiresAt")
    if valid_from >= expires_at or expires_at - valid_from > MAX_SESSION_DURATION:
        raise NetworkSessionLimitError(
            "session duration must be positive and at most 8 hours"
        )

    authority = _validate_authority(session["authority"])
    reviewed_at = _timestamp(
        authority["policyReviewedAt"], "authority.policyReviewedAt"
    )
    policy_expires_at = _timestamp(
        authority["policyExpiresAt"], "authority.policyExpiresAt"
    )
    approved_at = _timestamp(authority["approvedAt"], "authority.approvedAt")
    if reviewed_at > approved_at or approved_at > valid_from:
        raise NetworkSessionError(
            "policy review and approval must precede session validity"
        )
    if policy_expires_at < expires_at:
        raise NetworkSessionError("policy expiry must cover the complete session")

    capabilities = session["capabilities"]
    if (
        not isinstance(capabilities, list)
        or not capabilities
        or len(capabilities) != len(set(capabilities))
        or any(capability not in _CAPABILITIES for capability in capabilities)
    ):
        raise NetworkSessionError("capabilities must contain only unique http.observe")

    targets = session["targets"]
    if not isinstance(targets, list) or not 1 <= len(targets) <= 16:
        raise NetworkSessionLimitError("targets must contain 1 to 16 exact targets")
    for index, target in enumerate(targets):
        _validate_target(target, index, session["mode"])
    target_identities = [
        (target["scheme"], target["host"], target["port"]) for target in targets
    ]
    if len(target_identities) != len(set(target_identities)):
        raise NetworkSessionError("target origins must be unique")

    budgets = _validate_budgets(session["budgets"])
    if budgets["maxWallSeconds"] > (expires_at - valid_from).total_seconds():
        raise NetworkSessionLimitError(
            "maxWallSeconds cannot exceed the session duration"
        )
    _validate_transport(session["transport"], session["mode"])
    _validate_effects(session["effects"])

    stop_conditions = session["stopConditions"]
    if (
        not isinstance(stop_conditions, list)
        or len(stop_conditions) != len(set(stop_conditions))
        or any(
            not isinstance(item, str) or _STOP_CODE.fullmatch(item) is None
            for item in stop_conditions
        )
    ):
        raise NetworkSessionError("stopConditions must be unique bounded codes")
    if not _REQUIRED_STOPS.issubset(stop_conditions):
        raise NetworkSessionError("stopConditions are missing a required boundary")

    evaluated_at = evaluation_time or datetime.now(timezone.utc)
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise NetworkSessionError("evaluation time must include a timezone")
    evaluated_at = evaluated_at.astimezone(timezone.utc)
    if not valid_from <= evaluated_at < expires_at:
        raise NetworkSessionError(
            "network session is not active at the evaluation time"
        )
    if evaluated_at >= policy_expires_at:
        raise NetworkSessionError("network session policy is expired")

    session_sha256 = hashlib.sha256(_canonical_json(session)).hexdigest()
    result: dict[str, Any] = {
        "schemaVersion": "whitehat-network-session-validation-v1",
        "ok": True,
        "status": "valid-design-contract",
        "sessionId": session["sessionId"],
        "sessionSha256": session_sha256,
        "evaluatedAt": evaluated_at.isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        "summary": {
            "capabilities": len(capabilities),
            "targets": len(targets),
            "maxRequests": budgets["maxRequests"],
            "maxConcurrency": budgets["maxConcurrency"],
            "expiresAt": session["expiresAt"],
        },
        "claims": {
            "legalAuthorityEstablished": False,
            "networkEngineImplemented": session["mode"] == "owned-loopback",
            "networkExecutionAuthorized": False,
            "networkExecutionPerformed": False,
        },
        "effects": {
            "filesystemWrite": False,
            "network": False,
            "processCreation": False,
        },
    }
    result["resultSha256"] = hashlib.sha256(_canonical_json(result)).hexdigest()
    return result


def load_network_session_document(path_value: str | Path) -> dict[str, Any]:
    path = Path(path_value)
    if path.is_symlink():
        raise NetworkSessionError("network-session path must not be a symbolic link")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat(follow_symlinks=False)
    except (OSError, RuntimeError) as exc:
        raise NetworkSessionError(
            f"network-session document is unavailable: {exc}"
        ) from exc
    if not resolved.is_file():
        raise NetworkSessionError("network-session document must be a regular file")
    if metadata.st_size > MAX_SESSION_BYTES:
        raise NetworkSessionLimitError("network-session document byte limit exceeded")
    try:
        content = resolved.read_bytes()
        after = resolved.stat(follow_symlinks=False)
    except OSError as exc:
        raise NetworkSessionError(
            f"cannot read network-session document: {exc}"
        ) from exc
    if len(content) != metadata.st_size:
        raise NetworkSessionError("network-session document changed while reading")
    if (metadata.st_size, metadata.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise NetworkSessionError("network-session document changed while reading")
    try:
        document = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except NetworkSessionError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise NetworkSessionError(
            f"network-session document must be UTF-8 JSON: {exc}"
        ) from exc
    if not isinstance(document, dict):
        raise NetworkSessionError("network-session document must be a JSON object")
    return document


def load_and_validate_network_session(
    path_value: str | Path,
    evaluation_time: datetime | None = None,
) -> dict[str, Any]:
    return validate_network_session(
        load_network_session_document(path_value),
        evaluation_time,
    )


def parse_evaluation_time(value: str | None) -> datetime | None:
    return _timestamp(value, "evaluation time") if value is not None else None
