# Quickstart

This is the shortest verified path through the Whitehat CLI on Windows, Linux, or
macOS with Python 3.11 or newer. No credentials, environment variables, services,
or external accounts are required.

From the repository root:

```powershell
python -B -m whitehat doctor --json
python -B -m whitehat analyze inventory .\examples\before --json
python -B -m whitehat analyze diff .\examples\before .\examples\after --json
python -B -m whitehat analyze dependencies .\examples\dependencies\before\pyproject.toml .\examples\dependencies\after\pyproject.toml --json
python -B -m whitehat run synthetic --message "owned fixture" --json
python -B scripts\validate.py
```

Inventory should report two files and 31 bytes. The directory comparison should
report one added path, one modified path, no deleted paths, and one unchanged
file. Dependency comparison should report one added, one removed, one changed,
and one unchanged declaration. Validation should finish with an `ok: true` JSON
result.

Optional local recording is explicit:

```powershell
New-Item -ItemType Directory .\tmp -Force
python -B -m whitehat analyze inventory .\examples\before --output .\tmp\inventory.json --json
python -B -m whitehat review .\tmp\inventory.json --decision needs-work --note "Add a controlled comparison." --output .\tmp\inventory.review.json --json
```

The two output paths must not already exist. They are ignored local artifacts;
ordinary analysis without `--output` remains write-free.

The synthetic runner needs no approval artifact and exposes no arbitrary command:

```powershell
python -B -m whitehat run synthetic --message "owned fixture" --repeat 2 --json
```

The result should report `python.synthetic.echo`, process creation, no network or
arbitrary command, and `workspaceCleaned: true` without returning the message.

Install and run the optional reviewed scanner:

```powershell
python -m pip install ".[scanner-ruff]"
python -B -m whitehat scan ruff .\examples\scanner\problem --json
python -B -m whitehat scan ruff .\examples\scanner\clean --json
```

The first command reports `F401` and `F841`; the clean twin reports zero
observations. Neither result establishes a security finding.

Validate the separate future-network design without opening a socket:

```powershell
python -B -m whitehat session validate .\examples\network-session.synthetic.json --evaluation-time 2026-09-11T01:30:00Z --json
```

The result must keep `networkEngineImplemented`, `networkExecutionAuthorized`,
and `networkExecutionPerformed` false. Offline commands never require this file.

From a clean commit, run the separate technical release audit:

```powershell
python -m pip install ".[release]"
python -B -m whitehat release audit --json
```

Success reports `technical-audit-passed` while keeping publication authorization
and publication performed false.

Owned-loopback execution requires a currently active copy of the checked-in
loopback template, a local HTTP server on its exact port, and a new ignored state
path:

```powershell
python -B -m whitehat network observe-loopback .\tmp\loopback-session.json --state .\tmp\loopback.sqlite3 --path /observe --json
python -B -m whitehat network stop .\tmp\loopback-session.json --state .\tmp\loopback.sqlite3 --json
```

The checked-in template is historical and intentionally not a standing grant.
External targets are unsupported.

If Python cannot import `whitehat`, confirm that the command is running from the
repository root. Use `python --version` to confirm Python 3.11 or newer.
