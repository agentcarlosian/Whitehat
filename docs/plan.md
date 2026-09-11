# Whitehat development plan

Updated: 2026-09-11

Status: clean foundation and first local analysis slice implemented

Primary surface: `python -m whitehat`

## Product objective

Build one practical local-first security research toolkit. Routine local work
should be direct. Controls should become stricter only when an operation crosses
a meaningful side-effect boundary.

## Completed foundation

- [x] Initialize one disconnected repository with no remote.
- [x] Establish one package, CLI, version, test suite, and CI workflow.
- [x] Record the clean-source and risk-tier decisions.
- [x] Implement `doctor` with machine-readable boundary reporting.
- [x] Implement bounded content-free directory comparison without approval files.
- [x] Add a quickstart, runbook, synthetic example, and full validation command.

## Next slices

1. Add local file inventory and dependency comparison through the same analysis
   layer.
2. Add explicit local result storage and review notes without making receipts
   mandatory for ordinary analysis.
3. Add a bounded local synthetic process runner with disposable workspaces.
4. Add reviewed scanner adapters one at a time behind the local runner.
5. Design a session-scoped network boundary separately; do not make it a
   prerequisite for useful offline work.
6. Complete provenance, secret, package, and publication review before
   configuring a public remote. Apache-2.0 is selected.

## Current verification

- Windows Python 3.13.12: syntax check, 9 tests, `doctor`, and the directory-diff
  golden path pass. The symbolic-link test is skipped because the current Windows
  account cannot create a test symlink.
- A fresh local clone of the root commit passes the same validation without
  ignored working-directory inputs.
- A clean temporary installation builds a wheel and the installed `whitehat`
  console command passes `doctor --json`.
- Python 3.11 remains unverified locally and is covered by the pending CI matrix.

## Definition of done for the alpha foundation

- One clean checkout runs the golden path on Python 3.11 and 3.13.
- `doctor` truthfully reports that no external action is implemented.
- Directory comparison is deterministic and rejects escapes, links, mutation,
  and resource-limit violations covered by tests.
- No credential, private evidence, real-target record, or unrelated history is
  present.
