from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


class ReleaseAuditError(Exception):
    """The technical release audit could not establish its bounded claims."""

    exit_code = 3
    error_code = "release-audit-failed"


APACHE_2_LICENSE_SHA256 = (
    "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
)
BUILD_VERSION = "1.4.2"
SETUPTOOLS_VERSION = "80.10.2"
MAX_TRACKED_FILE_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 8 * 1024 * 1024
_FORBIDDEN_RELEASE_PREFIXES = (".git/", "artifacts/", "private/", "tmp/")
_SECRET_PATTERNS = (
    ("private-key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "github-token",
        re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    ),
    ("openai-key", re.compile(rb"sk-[A-Za-z0-9]{20,}")),
    ("aws-access-key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("slack-token", re.compile(rb"xox[baprs]-[A-Za-z0-9-]{20,}")),
    ("pypi-token", re.compile(rb"pypi-[A-Za-z0-9_-]{20,}")),
)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _run(
    arguments: list[str],
    *,
    cwd: Path,
    timeout: float = 180.0,
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            arguments,
            cwd=cwd,
            check=False,
            capture_output=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseAuditError(
            f"fixed release command failed to run: {arguments[0]}"
        ) from exc
    if completed.returncode != 0:
        raise ReleaseAuditError(
            f"fixed release command exited with code {completed.returncode}: {arguments[0]}"
        )
    return completed


def _git(root: Path, *arguments: str) -> bytes:
    return _run(["git", *arguments], cwd=root, timeout=30.0).stdout


def _safe_relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise ReleaseAuditError(f"unsafe release path: {value}")
    return path.as_posix()


def _release_inventory(root: Path) -> list[str]:
    inventory_path = root / "release-files.txt"
    try:
        values = [
            line.strip()
            for line in inventory_path.read_text(encoding="utf-8").splitlines()
        ]
    except OSError as exc:
        raise ReleaseAuditError(f"cannot read release-files.txt: {exc}") from exc
    if not values or any(not value for value in values):
        raise ReleaseAuditError(
            "release-files.txt must contain only non-empty literal paths"
        )
    normalized = [_safe_relative_path(value) for value in values]
    if normalized != sorted(normalized) or len(normalized) != len(set(normalized)):
        raise ReleaseAuditError("release-files.txt must be sorted and unique")
    for value in normalized:
        if value.startswith(_FORBIDDEN_RELEASE_PREFIXES):
            raise ReleaseAuditError(f"forbidden release path: {value}")
        path = root / PurePosixPath(value)
        if path.is_symlink() or not path.is_file():
            raise ReleaseAuditError(
                f"release path must be a regular non-link file: {value}"
            )
    package_files = sorted(
        path.relative_to(root).as_posix() for path in (root / "whitehat").rglob("*.py")
    )
    inventoried_package_files = [
        value for value in normalized if value.startswith("whitehat/")
    ]
    if package_files != inventoried_package_files:
        raise ReleaseAuditError(
            "release-files.txt does not exactly cover Python package files"
        )
    return normalized


def _tracked_files(root: Path) -> tuple[str, list[str]]:
    status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise ReleaseAuditError("release audit requires a clean tracked working tree")
    commit = _git(root, "rev-parse", "HEAD").decode("ascii").strip()
    tracked = [
        item.decode("utf-8")
        for item in _git(root, "ls-files", "-z").split(b"\0")
        if item
    ]
    modes = _git(root, "ls-files", "-s").decode("utf-8").splitlines()
    if any(line.startswith("120000 ") for line in modes):
        raise ReleaseAuditError("tracked symbolic links are not releaseable")
    if any(path.startswith(_FORBIDDEN_RELEASE_PREFIXES) for path in tracked):
        raise ReleaseAuditError("tracked private or generated path is not releaseable")
    return commit, tracked


def _scan_content_for_secrets(label: str, content: bytes) -> None:
    if len(content) > MAX_TRACKED_FILE_BYTES:
        raise ReleaseAuditError(f"tracked text exceeds audit byte limit: {label}")
    for pattern_id, pattern in _SECRET_PATTERNS:
        if pattern.search(content):
            raise ReleaseAuditError(f"secret pattern {pattern_id} matched: {label}")


def _scan_tracked_files(root: Path, tracked: Iterable[str]) -> int:
    count = 0
    for relative in tracked:
        path = root / PurePosixPath(relative)
        if not path.is_file():
            raise ReleaseAuditError(f"tracked path is not a file: {relative}")
        content = path.read_bytes()
        if b"\0" in content:
            raise ReleaseAuditError(
                f"binary tracked file requires explicit review: {relative}"
            )
        _scan_content_for_secrets(relative, content)
        count += 1
    return count


def _tool_versions() -> dict[str, str]:
    try:
        build_version = importlib.metadata.version("build")
        setuptools_version = importlib.metadata.version("setuptools")
    except importlib.metadata.PackageNotFoundError as exc:
        raise ReleaseAuditError(
            "install the release extra before running the audit"
        ) from exc
    if build_version != BUILD_VERSION or setuptools_version != SETUPTOOLS_VERSION:
        raise ReleaseAuditError(
            f"release tools must be build {BUILD_VERSION} and setuptools {SETUPTOOLS_VERSION}"
        )
    return {"build": build_version, "setuptools": setuptools_version}


def _copy_release_source(
    root: Path, source: Path, inventory: list[str]
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for relative in inventory:
        source_path = root / PurePosixPath(relative)
        destination = source / PurePosixPath(relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        content = source_path.read_bytes()
        destination.write_bytes(content)
        if destination.read_bytes() != content:
            raise ReleaseAuditError(f"release export readback failed: {relative}")
        records.append(
            {"path": relative, "size": len(content), "sha256": _sha256(content)}
        )
    return records


def _archive_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ReleaseAuditError(f"archive contains an unsafe path: {value}")
    return path


def _sdist_files(path: Path) -> tuple[str, dict[str, bytes]]:
    files: dict[str, bytes] = {}
    with tarfile.open(path, mode="r:gz") as archive:
        roots: set[str] = set()
        for member in archive.getmembers():
            member_path = _archive_path(member.name)
            roots.add(member_path.parts[0])
            if member.issym() or member.islnk():
                raise ReleaseAuditError(f"sdist contains a link: {member.name}")
            if member.isdir():
                continue
            if not member.isfile() or member.size > MAX_ARCHIVE_MEMBER_BYTES:
                raise ReleaseAuditError(
                    f"sdist contains an unsupported member: {member.name}"
                )
            stream = archive.extractfile(member)
            if stream is None:
                raise ReleaseAuditError(f"cannot read sdist member: {member.name}")
            files[member_path.as_posix()] = stream.read()
    if len(roots) != 1:
        raise ReleaseAuditError("sdist must contain one root directory")
    return next(iter(roots)), files


def _wheel_files(path: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            member_path = _archive_path(info.filename)
            unix_mode = info.external_attr >> 16
            if unix_mode and (unix_mode & 0o170000) == 0o120000:
                raise ReleaseAuditError(
                    f"wheel contains a symbolic link: {info.filename}"
                )
            if info.is_dir():
                continue
            if info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                raise ReleaseAuditError(
                    f"wheel member exceeds byte limit: {info.filename}"
                )
            files[member_path.as_posix()] = archive.read(info)
    return files


def _verify_sdist(
    artifact: Path,
    inventory: list[str],
    source_records: list[dict[str, Any]],
) -> dict[str, Any]:
    root_name, files = _sdist_files(artifact)
    relative_files = {
        str(PurePosixPath(path).relative_to(root_name)): content
        for path, content in files.items()
    }
    required = set(inventory) | {"PKG-INFO"}
    if not required.issubset(relative_files):
        raise ReleaseAuditError("sdist is missing a required release file")
    allowed_generated = {
        "PKG-INFO",
        "setup.cfg",
        "whitehat.egg-info/PKG-INFO",
        "whitehat.egg-info/SOURCES.txt",
        "whitehat.egg-info/dependency_links.txt",
        "whitehat.egg-info/entry_points.txt",
        "whitehat.egg-info/requires.txt",
        "whitehat.egg-info/top_level.txt",
    }
    unexpected = set(relative_files) - set(inventory) - allowed_generated
    if unexpected:
        raise ReleaseAuditError(
            f"sdist contains unexpected files: {sorted(unexpected)}"
        )
    for record in source_records:
        content = relative_files.get(record["path"])
        if (
            content is None
            or len(content) != record["size"]
            or _sha256(content) != record["sha256"]
        ):
            raise ReleaseAuditError(
                f"sdist source bytes do not match: {record['path']}"
            )
    for relative, content in relative_files.items():
        _scan_content_for_secrets(f"sdist:{relative}", content)
    return {
        "filename": artifact.name,
        "sha256": _sha256(artifact.read_bytes()),
        "files": len(relative_files),
    }


def _verify_wheel(
    artifact: Path,
    root: Path,
    inventory: list[str],
) -> dict[str, Any]:
    files = _wheel_files(artifact)
    package_files = [value for value in inventory if value.startswith("whitehat/")]
    for relative in package_files:
        if files.get(relative) != (root / PurePosixPath(relative)).read_bytes():
            raise ReleaseAuditError(f"wheel source bytes do not match: {relative}")
    dist_info = {path.split("/", 1)[0] for path in files if ".dist-info/" in path}
    if len(dist_info) != 1:
        raise ReleaseAuditError("wheel must contain one dist-info directory")
    prefix = next(iter(dist_info))
    required = {
        *package_files,
        f"{prefix}/METADATA",
        f"{prefix}/WHEEL",
        f"{prefix}/entry_points.txt",
        f"{prefix}/top_level.txt",
        f"{prefix}/RECORD",
        f"{prefix}/licenses/LICENSE",
    }
    if set(files) != required:
        raise ReleaseAuditError(
            f"wheel file inventory does not match: {sorted(set(files) ^ required)}"
        )
    for relative, content in files.items():
        _scan_content_for_secrets(f"wheel:{relative}", content)
    return {
        "filename": artifact.name,
        "sha256": _sha256(artifact.read_bytes()),
        "files": len(files),
    }


def _installed_smoke(wheel: Path, workspace: Path) -> dict[str, Any]:
    environment = workspace / "installed"
    venv.EnvBuilder(with_pip=True, clear=True).create(environment)
    if os.name == "nt":
        python = environment / "Scripts" / "python.exe"
        command = environment / "Scripts" / "whitehat.exe"
    else:
        python = environment / "bin" / "python"
        command = environment / "bin" / "whitehat"
    _run(
        [str(python), "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)],
        cwd=workspace,
        timeout=120.0,
    )
    completed = _run([str(command), "doctor", "--json"], cwd=workspace, timeout=30.0)
    try:
        result = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseAuditError("installed doctor output is invalid") from exc
    capabilities = result.get("capabilities", {})
    if (
        result.get("ok") is not True
        or capabilities.get("loopbackNetworkExecution") is not True
        or capabilities.get("externalNetwork") is not False
    ):
        raise ReleaseAuditError("installed doctor boundary check failed")
    return {
        "version": result["version"],
        "loopbackNetwork": True,
        "externalNetwork": False,
    }


def audit_release(root_value: str | os.PathLike[str]) -> dict[str, Any]:
    root = Path(root_value).resolve(strict=True)
    if not root.is_dir() or not (root / ".git").exists():
        raise ReleaseAuditError("release audit root must be a Git working tree")
    commit, tracked = _tracked_files(root)
    inventory = _release_inventory(root)
    missing_tracked = sorted(set(inventory) - set(tracked))
    if missing_tracked:
        raise ReleaseAuditError(
            f"release inventory contains untracked files: {missing_tracked}"
        )
    tracked_scanned = _scan_tracked_files(root, tracked)
    license_sha256 = _sha256((root / "LICENSE").read_bytes())
    if license_sha256 != APACHE_2_LICENSE_SHA256:
        raise ReleaseAuditError("LICENSE does not match the canonical Apache-2.0 text")
    tools = _tool_versions()

    with tempfile.TemporaryDirectory(prefix="whitehat-release-audit-") as temporary:
        workspace = Path(temporary)
        source = workspace / "source"
        distributions = workspace / "dist"
        source.mkdir()
        distributions.mkdir()
        source_records = _copy_release_source(root, source, inventory)
        _run(
            [
                sys.executable,
                "-m",
                "build",
                "--no-isolation",
                "--outdir",
                str(distributions),
                str(source),
            ],
            cwd=workspace,
            timeout=180.0,
        )
        sdists = list(distributions.glob("*.tar.gz"))
        wheels = list(distributions.glob("*.whl"))
        if len(sdists) != 1 or len(wheels) != 1:
            raise ReleaseAuditError(
                "release build must produce one sdist and one wheel"
            )
        sdist = _verify_sdist(sdists[0], inventory, source_records)
        wheel = _verify_wheel(wheels[0], root, inventory)
        installed = _installed_smoke(wheels[0], workspace)

    source_sha256 = _sha256(_canonical_json(source_records))
    result: dict[str, Any] = {
        "schemaVersion": "whitehat-release-audit-v1",
        "ok": True,
        "status": "technical-audit-passed",
        "commitSha": commit,
        "source": {
            "trackedFilesScanned": tracked_scanned,
            "releaseFiles": len(inventory),
            "releaseTreeSha256": source_sha256,
        },
        "license": {"spdx": "Apache-2.0", "sha256": license_sha256},
        "tools": tools,
        "packages": {"sdist": sdist, "wheel": wheel, "installed": installed},
        "secrets": {"matches": 0},
        "claims": {
            "legalClearanceEstablished": False,
            "originalityProven": False,
            "publicationAuthorized": False,
            "publicationPerformed": False,
        },
        "effects": {"network": False, "publication": False},
    }
    result["resultSha256"] = _sha256(_canonical_json(result))
    return result
