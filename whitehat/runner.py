from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence


class RunnerError(Exception):
    """Base error for fixed-profile local process execution."""

    exit_code = 3
    error_code = "invalid-input"


class RunnerLimitError(RunnerError):
    exit_code = 4
    error_code = "limit-exceeded"


@dataclass(frozen=True)
class ProcessLimits:
    timeout_seconds: float = 5.0
    max_input_bytes: int = 64 * 1024
    max_stdout_bytes: int = 1024 * 1024
    max_stderr_bytes: int = 64 * 1024

    def validate(self) -> None:
        if isinstance(self.timeout_seconds, bool) or not isinstance(
            self.timeout_seconds, (int, float)
        ):
            raise RunnerLimitError("timeoutSeconds must be numeric")
        if not 0.05 <= float(self.timeout_seconds) <= 30.0:
            raise RunnerLimitError("timeoutSeconds must be between 0.05 and 30")
        for name, value in self.as_dict().items():
            if name == "timeoutSeconds":
                continue
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise RunnerLimitError(f"{name} must be a positive integer")

    def as_dict(self) -> dict[str, int | float]:
        return {
            "timeoutSeconds": self.timeout_seconds,
            "maxInputBytes": self.max_input_bytes,
            "maxStdoutBytes": self.max_stdout_bytes,
            "maxStderrBytes": self.max_stderr_bytes,
        }


@dataclass(frozen=True)
class ProcessExecution:
    profile: str
    executable_sha256: str
    arguments_sha256: str
    input_sha256: str
    exit_code: int
    elapsed_ms: int
    stdout: bytes
    stderr: bytes
    workspace_cleaned: bool

    def receipt(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "executableSha256": self.executable_sha256,
            "argumentsSha256": self.arguments_sha256,
            "inputSha256": self.input_sha256,
            "exitCode": self.exit_code,
            "elapsedMs": self.elapsed_ms,
            "stdoutBytes": len(self.stdout),
            "stdoutSha256": hashlib.sha256(self.stdout).hexdigest(),
            "stderrBytes": len(self.stderr),
            "stderrSha256": hashlib.sha256(self.stderr).hexdigest(),
            "workspaceCleaned": self.workspace_cleaned,
        }


_PROFILE = re.compile(r"^[a-z][a-z0-9.-]{0,63}$")
_ENVIRONMENT_KEYS = (
    "COMSPEC",
    "LD_LIBRARY_PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise RunnerError(f"cannot hash fixed executable: {exc}") from exc
    return digest.hexdigest()


def _sanitized_environment(workspace: Path) -> dict[str, str]:
    environment = {
        "HOME": str(workspace),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        "TEMP": str(workspace),
        "TMP": str(workspace),
        "TMPDIR": str(workspace),
        "WHITEHAT_WORKSPACE": str(workspace),
    }
    for key in _ENVIRONMENT_KEYS:
        value = os.environ.get(key)
        if value:
            environment[key] = value
    return environment


def _validated_executable(value: str | os.PathLike[str]) -> Path:
    try:
        executable = Path(value).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RunnerError(f"fixed executable is unavailable: {exc}") from exc
    if not executable.is_file():
        raise RunnerError("fixed executable must be a regular file")
    return executable


def _validated_arguments(arguments: Sequence[str]) -> list[str]:
    if len(arguments) > 64:
        raise RunnerLimitError("fixed argument count limit exceeded")
    validated: list[str] = []
    total_characters = 0
    for argument in arguments:
        if not isinstance(argument, str) or "\x00" in argument:
            raise RunnerError("fixed process arguments must be NUL-free text")
        total_characters += len(argument)
        if total_characters > 16_384:
            raise RunnerLimitError("fixed argument character limit exceeded")
        validated.append(argument)
    return validated


def _read_bounded(
    stream: Any,
    limit: int,
    buffer: bytearray,
    overflow: threading.Event,
    process: subprocess.Popen[bytes],
) -> None:
    try:
        while chunk := stream.read(8192):
            remaining = limit + 1 - len(buffer)
            if remaining > 0:
                buffer.extend(chunk[:remaining])
            if len(buffer) > limit or len(chunk) > remaining:
                overflow.set()
                process.kill()
                break
    finally:
        stream.close()


def _run_process(
    executable: Path,
    arguments: list[str],
    input_bytes: bytes,
    workspace: Path,
    limits: ProcessLimits,
) -> tuple[int, int, bytes, bytes]:
    command = [str(executable), *arguments]
    creation_flags = 0
    if os.name == "nt":
        creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            cwd=workspace,
            env=_sanitized_environment(workspace),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creation_flags,
            start_new_session=os.name != "nt",
        )
    except OSError as exc:
        raise RunnerError(f"fixed process could not start: {exc}") from exc
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None

    stdout = bytearray()
    stderr = bytearray()
    stdout_overflow = threading.Event()
    stderr_overflow = threading.Event()
    readers = [
        threading.Thread(
            target=_read_bounded,
            args=(
                process.stdout,
                limits.max_stdout_bytes,
                stdout,
                stdout_overflow,
                process,
            ),
            daemon=True,
        ),
        threading.Thread(
            target=_read_bounded,
            args=(
                process.stderr,
                limits.max_stderr_bytes,
                stderr,
                stderr_overflow,
                process,
            ),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()
    try:
        process.stdin.write(input_bytes)
        process.stdin.close()
    except (BrokenPipeError, OSError):
        process.stdin.close()
    try:
        exit_code = process.wait(timeout=float(limits.timeout_seconds))
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait(timeout=5)
        for reader in readers:
            reader.join(timeout=5)
        raise RunnerLimitError("fixed process timeout exceeded") from exc
    for reader in readers:
        reader.join(timeout=5)
        if reader.is_alive():
            process.kill()
            raise RunnerError("fixed process output reader did not stop")
    elapsed_ms = max(0, round((time.monotonic() - started) * 1000))
    if stdout_overflow.is_set():
        raise RunnerLimitError("fixed process stdout limit exceeded")
    if stderr_overflow.is_set():
        raise RunnerLimitError("fixed process stderr limit exceeded")
    return exit_code, elapsed_ms, bytes(stdout), bytes(stderr)


def execute_fixed_profile(
    *,
    profile: str,
    executable: str | os.PathLike[str],
    arguments: Sequence[str] | Callable[[Path], Sequence[str]],
    input_bytes: bytes = b"",
    limits: ProcessLimits | None = None,
    workspace_root: str | os.PathLike[str] | None = None,
    prepare: Callable[[Path], None] | None = None,
    accepted_exit_codes: frozenset[int] = frozenset({0}),
) -> ProcessExecution:
    if _PROFILE.fullmatch(profile) is None:
        raise RunnerError("fixed process profile is invalid")
    active_limits = limits or ProcessLimits()
    active_limits.validate()
    if not isinstance(input_bytes, bytes):
        raise RunnerError("fixed process input must be bytes")
    if len(input_bytes) > active_limits.max_input_bytes:
        raise RunnerLimitError("fixed process input limit exceeded")
    if not accepted_exit_codes or any(
        isinstance(code, bool) or not isinstance(code, int)
        for code in accepted_exit_codes
    ):
        raise RunnerError("accepted exit codes must be integers")
    checked_executable = _validated_executable(executable)

    workspace_parent: Path | None = None
    if workspace_root is not None:
        try:
            workspace_parent = Path(workspace_root).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise RunnerError(f"workspace root is unavailable: {exc}") from exc
        if not workspace_parent.is_dir():
            raise RunnerError("workspace root must be a directory")

    execution_data: tuple[int, int, bytes, bytes] | None = None
    validated_arguments: list[str] = []
    with tempfile.TemporaryDirectory(
        prefix="whitehat-run-", dir=workspace_parent
    ) as temporary:
        workspace = Path(temporary)
        if prepare is not None:
            prepare(workspace)
        candidate_arguments = arguments(workspace) if callable(arguments) else arguments
        validated_arguments = _validated_arguments(candidate_arguments)
        execution_data = _run_process(
            checked_executable,
            validated_arguments,
            input_bytes,
            workspace,
            active_limits,
        )

    assert execution_data is not None
    exit_code, elapsed_ms, stdout, stderr = execution_data
    if exit_code not in accepted_exit_codes:
        raise RunnerError(f"fixed process exited with code {exit_code}")
    return ProcessExecution(
        profile=profile,
        executable_sha256=_file_sha256(checked_executable),
        arguments_sha256=hashlib.sha256(
            _canonical_json(validated_arguments)
        ).hexdigest(),
        input_sha256=hashlib.sha256(input_bytes).hexdigest(),
        exit_code=exit_code,
        elapsed_ms=elapsed_ms,
        stdout=stdout,
        stderr=stderr,
        workspace_cleaned=True,
    )


def run_synthetic(
    message: str,
    repeat: int = 1,
    delay_ms: int = 0,
    limits: ProcessLimits | None = None,
    workspace_root: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(message, str) or not message:
        raise RunnerError("synthetic message must be non-empty text")
    if len(message) > 4_096:
        raise RunnerLimitError("synthetic message character limit exceeded")
    if (
        isinstance(repeat, bool)
        or not isinstance(repeat, int)
        or not 1 <= repeat <= 100
    ):
        raise RunnerLimitError("synthetic repeat must be between 1 and 100")
    if (
        isinstance(delay_ms, bool)
        or not isinstance(delay_ms, int)
        or not 0 <= delay_ms <= 2_000
    ):
        raise RunnerLimitError("synthetic delayMs must be between 0 and 2000")
    request = {
        "schemaVersion": "whitehat-synthetic-request-v1",
        "message": message,
        "repeat": repeat,
        "delayMs": delay_ms,
    }
    request_bytes = _canonical_json(request)
    child = Path(__file__).with_name("synthetic_child.py").resolve(strict=True)
    execution = execute_fixed_profile(
        profile="python.synthetic.echo",
        executable=sys.executable,
        arguments=["-I", "-B", str(child)],
        input_bytes=request_bytes,
        limits=limits,
        workspace_root=workspace_root,
    )
    try:
        response = json.loads(execution.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise RunnerError("synthetic child returned invalid JSON") from exc
    expected_payload = message * repeat
    if not isinstance(response, dict) or response != {
        "schemaVersion": "whitehat-synthetic-response-v1",
        "payload": expected_payload,
        "environmentKeys": sorted(_sanitized_environment(Path(".")).keys()),
    }:
        raise RunnerError("synthetic child response did not match the fixed request")

    result: dict[str, Any] = {
        "schemaVersion": "whitehat-synthetic-run-v1",
        "ok": True,
        "profile": execution.profile,
        "limits": (limits or ProcessLimits()).as_dict(),
        "request": {
            "messageCharacters": len(message),
            "messageSha256": hashlib.sha256(message.encode("utf-8")).hexdigest(),
            "repeat": repeat,
            "delayMs": delay_ms,
        },
        "output": {
            "payloadBytes": len(expected_payload.encode("utf-8")),
            "payloadSha256": hashlib.sha256(
                expected_payload.encode("utf-8")
            ).hexdigest(),
            "environmentKeys": response["environmentKeys"],
        },
        "process": execution.receipt(),
        "effects": {
            "arbitraryCommand": False,
            "filesystemWrite": True,
            "network": False,
            "processCreation": True,
            "workspaceCleaned": execution.workspace_cleaned,
        },
    }
    result["resultSha256"] = hashlib.sha256(_canonical_json(result)).hexdigest()
    return result
