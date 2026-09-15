"""Optional pinned source fuzzer; no caller executable/module inputs."""

from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import platform
import sys
from pathlib import Path

from .evidence_links import sha256
from .fuzz_contracts import integer, write_tree
from .reports import ReportError, canonical, parse_json, read_bytes, seal
from .runner import ProcessLimits, execute_fixed_profile

ATHERIS_VERSION = "3.1.0"
SOURCE_PROFILES = ("capture-parser", "request-parser", "owned-fixed", "owned-broken")


def source_fuzz(
    profile: str,
    directory: str,
    *,
    runs: int = 1000,
    seed: int = 1,
    corpus_path: str | None = None,
) -> dict:
    destination = Path(directory)
    if (
        destination.exists()
        or destination.is_symlink()
        or not destination.parent.resolve(strict=True).is_dir()
    ):
        raise ReportError(
            "source fuzzer needs a new artifact directory beneath an existing parent"
        )
    if profile not in SOURCE_PROFILES:
        raise ReportError("select a reviewed fixed source profile")
    if (
        sys.platform != "linux"
        or platform.machine() != "x86_64"
        or not (3, 12) <= sys.version_info[:2] <= (3, 14)
    ):
        raise ReportError(
            "Atheris 3.1.0 profile requires Linux x64 with Python 3.12-3.14"
        )
    integer(runs, "runs", 1, 10000)
    integer(seed, "seed", 0, 2**31 - 1)
    try:
        distribution = importlib.metadata.distribution("atheris")
    except importlib.metadata.PackageNotFoundError as exc:
        raise ReportError(
            "install the source-fuzz extra before source execution"
        ) from exc
    if distribution.version != ATHERIS_VERSION or not distribution.read_text("RECORD"):
        raise ReportError("source fuzzer distribution identity mismatch")
    corpus = [b"{}", b'{"quantity":1}', b'{"quantity":-1}']
    if corpus_path is not None:
        root = Path(corpus_path)
        if root.is_symlink() or not root.is_dir():
            raise ReportError("source corpus must be an ordinary directory")
        paths = sorted(root.iterdir())
        if not 1 <= len(paths) <= 20:
            raise ReportError("source corpus requires 1-20 seed files")
        corpus = [read_bytes(path, 8192) for path in paths]
    request = {
        "profile": profile,
        "runs": runs,
        "seed": seed,
        "corpus": [base64.b64encode(raw).decode("ascii") for raw in corpus],
    }
    execution = execute_fixed_profile(
        profile="source.atheris." + profile,
        executable=sys.executable,
        arguments=["-I", "-B", str(Path(__file__).with_name("atheris_worker.py"))],
        input_bytes=canonical(request),
        limits=ProcessLimits(
            timeout_seconds=25,
            max_input_bytes=256 * 1024,
            max_stdout_bytes=65536,
            max_stderr_bytes=128 * 1024,
        ),
        # Atheris/libFuzzer exits 77 when SystemExit stops the fixed callback.
        # Accept it only when the bounded structured stdout below validates.
        accepted_exit_codes=frozenset({0, 77}),
    )
    value = parse_json(execution.stdout)
    if (
        not isinstance(value, dict)
        or value.get("schemaVersion") != "whitehat-atheris-worker-v1"
        or value.get("toolVersion") != ATHERIS_VERSION
        or value.get("profile") != profile
    ):
        raise ReportError("invalid source fuzzer result")
    integer(value.get("callbacks"), "callbacks", 0, runs + 1)
    failure = value.get("failure")
    artifact = None
    documents = {}
    if failure is not None:
        if not isinstance(failure, dict) or set(failure) != {"class", "dataBase64"}:
            raise ReportError("invalid source failure")
        try:
            raw = base64.b64decode(failure["dataBase64"], validate=True)
        except (ValueError, TypeError) as exc:
            raise ReportError("invalid source reproducer encoding") from exc
        if (
            len(raw) > 8192
            or not isinstance(failure["class"], str)
            or len(failure["class"]) > 100
        ):
            raise ReportError("source failure exceeds limits")
        artifact = hashlib.sha256(raw).hexdigest()
        sha256(artifact)
        documents["source-case.json"] = {
            "schemaVersion": "whitehat-source-case-v1",
            "profile": profile,
            "inputSha256": artifact,
            "dataBase64": failure["dataBase64"],
            "failureClass": failure["class"],
            "seed": seed,
            "toolVersion": ATHERIS_VERSION,
        }
    result = seal(
        {
            "schemaVersion": "whitehat-source-fuzz-result-v1",
            "ok": True,
            "profile": profile,
            "toolVersion": ATHERIS_VERSION,
            "distributionRecordSha256": hashlib.sha256(
                distribution.read_text("RECORD").encode()
            ).hexdigest(),
            "targetSha256": {
                name: hashlib.sha256(
                    Path(__file__).with_name(name).read_bytes()
                ).hexdigest()
                for name in (
                    "atheris_worker.py",
                    "http_evidence.py",
                    "http_replay.py",
                    "reports.py",
                )
            },
            "seed": seed,
            "requestedRuns": runs,
            "callbacks": value["callbacks"],
            "failureInputSha256": artifact,
            "failureClass": failure["class"] if failure else None,
            "process": execution.receipt(),
            "claims": {
                "findingValidityEstablished": False,
                "coverageCompletenessEstablished": False,
            },
            "effects": {
                "network": False,
                "processCreation": True,
                "filesystemWrite": True,
                "workspaceCleaned": execution.workspace_cleaned,
            },
        }
    )
    documents["result.json"] = result
    write_tree(directory, documents)
    return result
