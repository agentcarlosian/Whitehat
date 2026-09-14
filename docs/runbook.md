# Runbook

## Scope

This runbook covers the local Whitehat alpha. It requires no credentials or
external services and has no persistent background process.

## Routine commands

| Task | Command | Notes |
| --- | --- | --- |
| Health check | `python -B -m whitehat doctor --json` | Reports implemented boundaries |
| Inventory directory | `python -B -m whitehat analyze inventory ROOT --json` | Returns paths, sizes, and hashes |
| Compare directories | `python -B -m whitehat analyze diff BEFORE AFTER --json` | Reads regular files only |
| Compare dependencies | `python -B -m whitehat analyze dependencies BEFORE AFTER --json` | Supports pyproject and package-lock |
| Save an analysis | Add `--output NEW_FILE` | Optional; refuses overwrite |
| Review a saved result | `python -B -m whitehat review RESULT --decision needs-work --note TEXT --output NEW_REVIEW --json` | Writes one hash-linked local note |
| Run synthetic profile | `python -B -m whitehat run synthetic --message TEXT --json` | Fixed child; disposable workspace |
| Install Ruff adapter | `python -m pip install ".[scanner-ruff]"` | Installs exact optional version |
| Scan Python source | `python -B -m whitehat scan ruff SOURCE --json` | Fixed rules; no fixes or source execution |
| Validate session design | `python -B -m whitehat session validate DOCUMENT --json` | Local validation only; no network authority |
| Install release tools | `python -m pip install ".[release]"` | Pinned build frontend/backend |
| Audit release | `python -B -m whitehat release audit --json` | Clean commit only; never publishes |
| Validate repository | `python -B scripts/validate.py` | Syntax, tests, and golden-path checks |
| Show version | `python -B -m whitehat --version` | Prints the package version |

## Failure handling

- Exit `2`: command-line usage is invalid. Check `--help`.
- Exit `3`: an input path is invalid, changed during inspection, or contains a
  link or unsupported entry. Stabilize the input and retry.
- Exit `4`: a configured resource limit was exceeded. Narrow the input or set a
  reviewed larger local limit.

The commands do not create a state database or background worker, so recovery is
normally just correcting the input and rerunning the command.

## Release boundary

Do not configure a public remote, tag, publish, or distribute the package until
the exact Apache-2.0 tree passes provenance, secret, packaging, and platform
review.
