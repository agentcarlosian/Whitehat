# Whitehat development plan

Updated: 2026-09-11

Status: clean foundation and optional local records slice implemented

Primary surface: `python -m whitehat`

## Product objective

Build one practical local-first security research toolkit. Routine local work
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

## Next slices

1. Add a bounded local synthetic process runner with disposable workspaces.
2. Add reviewed scanner adapters one at a time behind the local runner.
3. Design a session-scoped network boundary separately; do not make it a
   prerequisite for useful offline work.
4. Complete provenance, secret, package, and publication review before
   configuring a public remote. Apache-2.0 is selected.

## Current verification

- Windows Python 3.13.12: syntax check, 31 tests, `doctor`, inventory, directory
  diff, dependency comparison, result storage, and local review golden paths
  pass. The symbolic-link test is skipped because the current Windows account
  cannot create a test symlink.
- A fresh local clone of the root commit passes the same validation without
  ignored working-directory inputs.
- A clean temporary installation builds the `0.3.0a1` wheel and the installed
  CLI passes the explicit save/review path with local-write and false-claim checks.
- GitHub Actions passes validation and package installation on Ubuntu with Python
  3.11 and 3.13. Python 3.11 is not installed on the current Windows host.

## Definition of done for the alpha foundation

- One clean checkout runs the golden path on Python 3.11 and 3.13.
- `doctor` truthfully reports that no external action is implemented.
- Directory comparison is deterministic and rejects escapes, links, mutation,
  and resource-limit violations covered by tests.
- No credential, private evidence, real-target record, or unrelated history is
  present.
