# Whitehat development plan

Updated: 2026-09-14

Status: research toolkit and adoption implementation active. The baseline technical
publication audit and owned-loopback proof passed CI at `7e47505`.

Current acceptance criteria and execution order: [research toolkit](tasks/research-toolkit.md).
The foundation record below describes completed work and does not select new work.

Primary surface: `python -m whitehat`

## Product objective

Build one practical security research and bounty toolkit. Routine analysis
should be direct. Controls should become stricter only when an operation crosses
a meaningful side-effect boundary.

## Completed foundation

- [x] Initialize one independent repository with no inherited remote or history.
- [x] Establish one package, CLI, version, test suite, and CI workflow.
- [x] Record the clean-source and risk-tier decisions.
- [x] Implement `doctor` with machine-readable boundary reporting.
- [x] Implement bounded content-free directory comparison without approval files.
- [x] Add a quickstart, runbook, synthetic example, and full validation command.

## Completed local analysis expansion

- [x] Add deterministic bounded file inventory through `whitehat analyze`.
- [x] Compare static Python project dependency declarations.
- [x] Compare npm package-lock versions 1 through 3 without exporting registry URLs.
- [x] Reuse the existing resource limits, exit codes, JSON style, and no-effects boundary.

## Completed optional local records

- [x] Add opt-in `--output` storage to every local analysis command.
- [x] Store exact canonical JSON only after result-hash validation.
- [x] Refuse overwrite, missing parents, symbolic-link destinations, and oversized records.
- [x] Add hash-linked `accepted`, `dismissed`, and `needs-work` review notes.
- [x] Keep author identity caller-asserted and every authority/finding/external claim false.

## Completed bounded synthetic runner

- [x] Expose one fixed typed profile without caller-supplied commands or arguments.
- [x] Sanitize the child environment and redirect temporary/home paths.
- [x] Bound stdin, stdout, stderr, wall time, repeat count, delay, and message size.
- [x] Clean the disposable workspace on success, timeout, and output overflow.
- [x] Emit hashes and counts without returning the synthetic payload.
- [x] Support optional result storage and the existing local review flow.

## Completed first scanner adapter

- [x] Add Ruff `0.14.14` as one optional, pinned scanner dependency.
- [x] Run version and scan processes through the fixed local runner.
- [x] Copy only bounded Python source into a disposable workspace.
- [x] Fix Ruff configuration, rules, target version, and no-fix behavior.
- [x] Normalize observations without messages, URLs, snippets, or absolute paths.
- [x] Prove dirty and clean twins plus path, duplicate, identity, limit, and link rejection.

## Completed session-scoped network design

- [x] Define one immutable, short-lived session grant instead of per-request approvals.
- [x] Bind exact policy timing, capabilities, targets, methods, budgets, and stop conditions.
- [x] Keep all credential, mutation, third-party-data, contact, and submission effects false.
- [x] Specify a separate atomic local consumption ledger and restart behavior.
- [x] Specify resolve-once public-address pinning, TLS, proxy, redirect, and retry boundaries.
- [x] Implement local contract validation while keeping network execution absent.
- [x] Prove offline commands do not require or discover session state.

## Publication audit implementation

- [x] Add provenance and third-party tool records.
- [x] Add a literal release-source inventory covering every package module.
- [x] Add tracked and packaged high-confidence secret-pattern scanning.
- [x] Build sdist and wheel from a disposable tracked-file-only export.
- [x] Verify archive membership, package-source bytes, Apache license, and clean install.
- [x] Keep publication and legal/originality claims false.
- [x] Run the full audit from committed implementation `4798261`; zero secret
  matches, canonical Apache-2.0, bounded sdist/wheel, and clean install passed.

## Owned-loopback network execution

- [x] Add a distinct `owned-loopback` session mode with exact IPv4 loopback.
- [x] Add real-clock session/policy validation and exact GET path matching.
- [x] Reserve each request atomically in a session-hash-bound SQLite ledger.
- [x] Enforce request, concurrency, delay, timeout, response, wall-time, and stop budgets.
- [x] Refuse redirects, proxies, credentials, request bodies, mutation, and external hosts.
- [x] Return content-free response metadata and no hash for oversized bodies.
- [x] Stop monotonically on user stop, HTTP 429, and unexpected redirects.
- [x] Prove restart budget, pre-socket scope rejection, no retry, and offline independence.

## Next slices

Follow the ordered toolkit and adoption task linked above. External HTTPS
execution remains a separate capability design.

## Current verification

- Windows Python 3.13.12: syntax check and 71 tests pass, including release
  inventory, license, secret-pattern, and archive-path policy tests plus local network
  contract timing, scope, budget, effect, stop, and duplicate-key rejection. Two
  symbolic-link tests are skipped because the current account cannot create them.
- A fresh local clone of the root commit passes the same validation without
  ignored working-directory inputs.
- A clean temporary installation builds `0.6.0a1` with the optional Ruff extra;
  its synthetic runner, dirty/clean Ruff scans, and local-only session validator
  all pass their exact effect and claim checks.
- `0.7.0a1` technical audit passed locally at `4798261`. The `0.8.0a1` audit
  passed at `66f5264`: 61 tracked files, 20 release inputs, zero secret matches,
  canonical Apache-2.0, 28-file sdist, 19-file wheel, and clean installation.
- GitHub Actions passes validation and package installation on Ubuntu with Python
  3.11 and 3.13. Python 3.11 is not installed on the current Windows host.

## Definition of done for the alpha foundation

- One clean checkout runs the golden path on Python 3.11 and 3.13.
- `doctor` truthfully reports that no external action is implemented.
- Directory comparison is deterministic and rejects escapes, links, mutation,
  and resource-limit violations covered by tests.
- No credential, private evidence, real-target record, or unrelated history is
  present.
