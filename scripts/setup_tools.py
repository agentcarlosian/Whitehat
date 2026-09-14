"""Explicit dev/operator setup. Download only literal reviewed assets, never run them."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from whitehat.native_tools import TOOLS, platform_key, verify_tool  # noqa: E402


def install(tool: str, destination: Path) -> dict[str, str]:
    spec = TOOLS[tool]
    asset = spec["platforms"][platform_key()]
    target = destination / tool
    if target.exists():
        verify_tool(tool, target / asset["executable"])
        return {"tool": tool, "version": spec["version"], "status": "already-verified"}
    url = f"https://github.com/{spec['repo']}/releases/download/v{spec['version']}/{asset['asset']}"
    with urllib.request.urlopen(url, timeout=60) as response:
        raw = response.read(64 * 1024 * 1024 + 1)
    if len(raw) > 64 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != asset["sha256"]:
        raise ValueError("release archive hash/size mismatch")
    with tempfile.TemporaryDirectory(prefix="whitehat-install-", dir=destination) as temp:
        staged = Path(temp) / tool
        staged.mkdir()
        if asset["asset"].endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                if len(archive.namelist()) != len(set(archive.namelist())):
                    raise ValueError("duplicate archive member")
                members = {name: archive.read(name) for name in asset["members"]}
        else:
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
                if len(archive.getnames()) != len(set(archive.getnames())):
                    raise ValueError("duplicate archive member")
                members = {}
                for name in asset["members"]:
                    member = archive.getmember(name)
                    if not member.isfile() or member.size > 256 * 1024 * 1024:
                        raise ValueError("invalid archive member")
                    stream = archive.extractfile(member)
                    assert stream is not None
                    members[name] = stream.read()
        for name, content in members.items():
            if hashlib.sha256(content).hexdigest() != asset["members"][name]:
                raise ValueError("executable/companion hash mismatch")
            (staged / name).write_bytes(content)
        if os.name != "nt":
            (staged / asset["executable"]).chmod(0o755)
        staged.rename(target)
    verify_tool(tool, target / asset["executable"])
    return {"tool": tool, "version": spec["version"], "status": "installed-and-verified"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Explicitly download pinned research tools (no execution or global installation).")
    parser.add_argument("--destination", required=True)
    parser.add_argument("--tool", choices=sorted(TOOLS), action="append")
    args = parser.parse_args()
    destination = Path(args.destination)
    if destination.is_symlink():
        parser.error("destination must not be a link")
    destination.mkdir(parents=True, exist_ok=True)
    results = [install(name, destination.resolve()) for name in (args.tool or sorted(TOOLS))]
    print(json.dumps({"ok": True, "tools": results}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
