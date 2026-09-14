# Whitehat alpha specification

## Product surface

The primary interface is `python -m whitehat`; installation also provides the
`whitehat` console command. Commands are non-interactive. Analysis results are
deterministic for stable inputs; process results additionally retain observed
runtime identity, byte counts, exit status, cleanup, and elapsed time.

## Research workflow

`scan opengrep` and `scan secrets` run the pinned native profiles documented in
`docs/toolkit.md`. `import REPORT --format FORMAT` normalizes existing OSV,
SARIF, ZAP, Nuclei, Opengrep, Betterleaks, and Gitleaks output into
`whitehat-research-result-v1`. Native and imported results share fingerprints,
relative source locations, explanations, reported context, and false finding claims.

`compare BEFORE AFTER` reports introduced, absent, and unchanged fingerprints in
`whitehat-research-comparison-v1`, plus whether the recorded analysis profiles
match. `init NEW_DIRECTORY` creates a portable workspace and
`whitehat-research-case-v1` notes. `report RESULT --case CASE --review REVIEW
--output NEW_MARKDOWN` exports a readable packet; the case/review arguments are
optional, and a supplied review must bind the exact result hash.

Cases record title, target/version, hypothesis, boundary, reproduction status,
negative control, duplicate assessment, next action, and relative evidence
references. Analyst assertions and scanner severity do not become validated
findings. External evidence references are never opened or embedded.

## Risk model

| Level | Activity | Initial behavior |
| --- | --- | --- |
| L0 | Local read-only and prepared offline analysis | Available without approval artifacts |
| L1 | Fixed synthetic and reviewed native analysis processes | Implemented with explicit invocation and bounded resources; no arbitrary executable profile |
| N0 | Owned IPv4 loopback observation | Implemented through exact session and local ledger |
| N1 | External network access to an authorized asset | Not implemented; requires remaining transport gates |
| H1 | Credentials, mutation, destructive work, money, contact, disclosure, submission | Not implemented; exact human authorization required |

## `doctor`

`whitehat doctor [--json]` reports the package version, Python runtime, platform,
implemented capabilities, and unavailable side-effect classes. It performs no
network action and reads no project or user configuration.

## `analyze diff`

```text
whitehat analyze diff BEFORE AFTER [--max-entries N] [--max-files N]
  [--max-file-bytes N] [--max-total-bytes N] [--json]
```

The command recursively compares two existing operator-controlled directories.
It hashes regular files and returns sorted metadata for added, deleted, and
modified paths. File contents and unchanged path names are not returned.

The command:

- never executes an input;
- performs no network action;
- rejects symbolic links and unsupported filesystem entries;
- stops when an entry, file, per-file byte, or aggregate byte limit is exceeded;
- detects common file replacement or mutation during hashing;
- returns deterministic summaries and a result hash.

## `analyze inventory`

```text
whitehat analyze inventory ROOT [--max-entries N] [--max-files N]
  [--max-file-bytes N] [--max-total-bytes N] [--json]
```

Inventory uses the same bounded scanner as directory comparison. It returns
sorted relative paths, byte sizes, SHA-256 identities, total file/byte counts,
and a deterministic tree identity. It does not return file contents, write an
artifact, start a process, or access a network.

## `analyze dependencies`

```text
whitehat analyze dependencies BEFORE AFTER
  [--max-manifest-bytes N] [--max-dependencies N] [--json]
```

Dependency comparison accepts two manifests from the same ecosystem:

- Python `pyproject.toml` static `[project].dependencies` and
  `[project.optional-dependencies]` declarations;
- npm `package-lock.json` lockfile versions 1, 2, and 3.

Python results compare normalized package names within their main or optional
group while preserving each declared requirement string. Dynamic dependencies
are rejected because their value is unavailable without running a build backend.

npm results compare resolved package locations, versions, integrity values,
link state, and direct/transitive classification. Registry `resolved` URLs,
scripts, and package content are not returned. The command never resolves,
downloads, installs, imports, or executes a dependency.

## Optional result storage

Each `whitehat analyze` command accepts `--output FILE`. Without that option, the
command writes nothing. With it, Whitehat validates the generated result hash and
writes the exact canonical JSON to a new file whose parent directory already
exists. It refuses symbolic-link destinations and existing paths, flushes the
file, and verifies the stored bytes. Stored results are capped at 64 MiB.

The result's `effects` object describes the analysis itself. The separately
requested record write is not folded into or allowed to change the analysis hash.
The output path is not embedded in JSON, avoiding accidental disclosure of an
absolute local path.

## `review`

```text
whitehat review RESULT --decision accepted|dismissed|needs-work --note TEXT
  --output REVIEW [--author TEXT] [--max-result-bytes N] [--json]
```

Review reloads one supported saved result, rejects duplicate JSON keys and hash
drift, and writes one new review document without changing the result. The note
is limited to 4,000 characters and the optional author is explicitly a caller
assertion, not authenticated identity. Reviews are UTC timestamped and bound to
the result schema and SHA-256.

`accepted` means only that the analyst accepts the local record for their own
workflow. All review decisions keep authority, finding validity, impact, external
action, and submission claims false. The review effects explicitly record the
requested local file write.

## `run synthetic`

```text
whitehat run synthetic --message TEXT [--repeat N] [--delay-ms N]
  [--timeout-seconds N] [--max-input-bytes N] [--max-stdout-bytes N]
  [--max-stderr-bytes N] [--workspace-root DIR] [--output FILE] [--json]
```

The initial runner exposes one profile, `python.synthetic.echo`. The caller
chooses typed message, repeat, delay, and resource values but cannot supply an
executable, module, script path, argument, environment variable, or command.

The parent launches the exact current Python interpreter with isolated mode and
the checked-in fixed child. The request is sent over bounded standard input. The
child receives a minimal environment with temporary/home paths redirected to its
disposable workspace and denies socket, subprocess, spawn, exec, and system audit
events. The parent reads stdout and stderr concurrently, kills the process on
timeout or retained-output overflow, and returns only after workspace cleanup.

The result contains input/output hashes and sizes, executable and argument
identities, elapsed time, exit code, sanitized environment-key names, and cleanup
status. It does not return the message or child payload. Process creation and the
temporary filesystem write are explicit; arbitrary commands and network remain
false. This profile is a pipeline proof, not an OS sandbox for untrusted code.

## `scan ruff`

```text
whitehat scan ruff SOURCE [--max-entries N] [--max-source-files N]
  [--max-file-bytes N] [--max-total-bytes N] [--max-observations N]
  [--timeout-seconds N] [--max-stdout-bytes N] [--max-stderr-bytes N]
  [--workspace-root DIR] [--output FILE] [--json]
```

The first reviewed scanner adapter requires Ruff exactly `0.14.14`. Whitehat
discovers it by the fixed name `ruff`; the caller cannot provide an executable or
arguments. A bounded version check and scan both run through the local process
runner. The executable identity must stay unchanged between them.

The adapter copies only bounded `.py` and `.pyi` regular files into a disposable
workspace and runs fixed isolated, no-cache, no-fix, no-preview rules `E4`, `E7`,
`E9`, and `F` for Python 3.11. Source is parsed by Ruff but never imported or
executed by Whitehat.

Normalized output contains only rule codes, relative paths, locations, and fix
availability. Raw messages, edit content, documentation URLs, source text,
absolute paths, and stderr are omitted. Exit `0` is clean, exit `1` represents
observations, and exit `2` or another status is failure. See
`docs/scanner-adapters.md` for the reviewed contract and provenance record.

## `session validate`

```text
whitehat session validate DOCUMENT [--evaluation-time RFC3339]
  [--output FILE] [--json]
```

This local-only command validates `whitehat-network-session-v1`. It checks strict
fields, duplicate keys, an eight-hour maximum, policy timing, approval timing,
exact HTTPS design targets or exact owned loopback, GET/HEAD methods, typed
capability, budgets, fixed transport, false consequential effects, required stop
conditions, and activity at the evaluation clock.

`--evaluation-time` exists only for offline fixtures and historical inspection.
A future engine must ignore it and use a trusted current clock. Successful output
is `valid-design-contract` with legal authority, network execution authorization,
and execution performed false. Engine implementation is true only for the
separately reviewed owned-loopback mode. See `docs/network-session-boundary.md`
and Decisions 0002 and 0004.

## `network observe-loopback`

```text
whitehat network observe-loopback SESSION --state SQLITE --path PATH
  [--output FILE] [--json]
whitehat network stop SESSION --state SQLITE [--json]
```

The only executable network profile accepts `owned-loopback` sessions and exact
IPv4 `127.0.0.1` targets. It uses the real UTC clock, HTTP GET, a direct
standard-library connection, no proxy, no redirect following, no request body,
and no credentials. Exact path scope and every session budget are checked before
or during the attempt.

The SQLite ledger binds the session hash and atomically records request
reservation, sequence, target, completion, response status/bytes, remaining
budget, and monotonic stop state. A failed request consumes its reservation and
is never automatically retried.

Responses are not retained. Complete bounded bodies produce only a SHA-256;
oversized bodies produce a partial-byte count and no body hash. HTTP 429 and 3xx
responses stop the session. Diagnostics report network and loopback execution
true while external network remains false. See Decision 0004.

## `release audit`

```text
whitehat release audit [--root DIR] [--output FILE] [--json]
```

The technical audit requires a clean Git commit and the pinned `release` optional
dependencies. It scans tracked text, validates the Apache license and literal
source inventory, builds one sdist and wheel from a disposable export, rejects
unexpected archive members, verifies packaged source bytes, performs a clean
wheel installation, and removes all temporary artifacts.

The result is hash-bound to the commit and release inventory. Success means
`technical-audit-passed`; it always keeps legal clearance, originality proof,
publication authorization, publication performed, and network effects false.
See `docs/release-readiness.md` and Decision 0003.

All commands in this specification exit `0` on success. Command-line usage
errors exit `2`, invalid inputs exit `3`, and configured limit failures exit `4`.
