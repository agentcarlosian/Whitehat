# Runbook

## Scope

This runbook covers the Whitehat research alpha. Analysis and imports require no
external account. Explicit native tool setup uses upstream release downloads.
There is no persistent background service.

## Routine commands

| Task | Command | Notes |
| --- | --- | --- |
| Health check | `python -B -m whitehat doctor --json` | Reports implemented boundaries |
| Toolkit compatibility | `python -m whitehat tools` | Lists pins, platforms, and import formats |
| Create research workspace | `python -m whitehat init NEW_DIRECTORY --title TITLE` | Creates inputs/results/notes/exports and case.json |
| Security source scan | `python -m whitehat scan opengrep SOURCE` | Authored Python/JavaScript rules; explicit tool setup required |
| Secret pattern scan | `python -m whitehat scan secrets SOURCE` | Betterleaks; no live credential validation |
| Import tool output | `python -m whitehat import REPORT --format FORMAT` | osv, sarif, zap, nuclei, opengrep, betterleaks, gitleaks |
| Compare research results | `python -m whitehat compare BEFORE AFTER` | New/absent/unchanged fingerprints, profile comparison |
| Export review | `python -m whitehat report RESULT --case CASE --review REVIEW --output NEW_MARKDOWN` | Case and review are optional; no external submission |
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
| Observe owned loopback | `python -B -m whitehat network observe-loopback SESSION --state SQLITE --path PATH --json` | Exact 127.0.0.1 GET only |
| Stop loopback session | `python -B -m whitehat network stop SESSION --state SQLITE --json` | Monotonic user stop |
| Validate repository | `python -B scripts/validate.py` | Syntax, tests, and golden-path checks |
| Show version | `python -B -m whitehat --version` | Prints the package version |

## Failure handling

For capture preparation, evidence packets, staged binding, candidate decisions
and access/scenario coverage, use [the complete bounty workflow](bounty-workflow.md).
`python -B scripts/evaluate_bounty.py` verifies this path with owned fixtures;
add `--output-dir NEW_DIRECTORY` to retain the example report and input artifacts.

If a packet reports changed evidence, inspect the source and deliberately update
the manifest's hash/selection only after review. Never silently refresh a pin.
If candidate history reports a gap or altered predecessor, recover the original
files from your own backup; do not delete prior decisions to manufacture a clean
history. New source lines, selectors or identity/object bindings can make a retest
not comparable even when the human believes it concerns the same candidate.

- Exit `2`: command-line usage is invalid. Check `--help`.
- Exit `3`: an input path is invalid, changed during inspection, or contains a
  link or unsupported entry. Stabilize the input and retry.
- Exit `4`: a configured resource limit was exceeded. Narrow the input or set a
  reviewed larger local limit.

Research commands store only explicitly requested artifacts. The owned-loopback
profile uses its explicit SQLite ledger. Recovery depends on the command: fix an
invalid report, narrow an oversized source set, or follow the loopback stop/recovery
procedure. Never interpret an incomplete scan as a clean result.

## Release boundary

Do not configure a public remote, tag, publish, or distribute the package until
the exact Apache-2.0 tree passes provenance, secret, packaging, and platform
review.
