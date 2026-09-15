# Fuzzing workflows

Requested 2026-09-15: implement the five researched stages. Owner: Whitehat.
Base: merged PR #3, `73f4dee82cdfb86eee76660f5cecf3572901a8bf`.
Branch: `codex/fuzzing-workflows`; merge target: `main`.
Working checkout: temporary isolated clone `whitehat-fuzzing-20260915` because
this session no longer has direct write access to the canonical checkout.

## Acceptance

1. Versioned mutation plans from prepared capture/OpenAPI inputs; deterministic
   boundary and Hypothesis samples; concrete bounded request batches, unchanged
   origins/credentials, provenance and unapproved session drafts; ledger-backed run.
2. Typed relational assertions over hash-linked HTTP evidence, including
   unchanged/equality/delta/absence, with explicit identities/objects and missing
   evidence remaining inconclusive. Authoritative readback in owned twins.
3. Reproducible cases, reduction batches, selection of the smallest verified
   same-failure reproducer, corpus deduplication, and regression/retest results.
   Any request during reduction uses a previously approved exact hash and budget.
4. Finite-state sequence generation with explicit setup/reset and cleanup
   verification. Fixed seeds, bounded length and independent cases. No hidden
   login, runtime code expressions, response-driven destination changes or retries.
5. Offline GraphQL SDL/introspection inventory, operation-aware capture evidence
   and variable mutation planning; optional pinned Atheris source adapter with
   reviewed fixed parser/owned profiles, actual Linux CI execution and receipts.

Primary surface: `python -m whitehat`. Optional dependencies remain optional.
Execution verification uses only owned APIs and authored canaries. No third-party
target activity, real credentials, submission, publication or automatic merge.

## Progress

- [x] Inspect current contracts; create isolated branch.
- [x] Mutation planning and concrete-batch execution.
- [x] Relational assertions and readback fixtures.
- [x] Reduction, corpus and regression workflows.
- [x] Stateful generation and verified reset.
- [x] GraphQL and optional source adapter implementation; actual Linux engine check pending CI.
- [ ] Complete CLI examples, checks, package audit and reviewable PR.

## Verification checkpoint

- Owned CLI evaluation passes: six broken mutation/readback signals and two
  broken stateful signals; zero in both fixed twins; reset and corpus reproduction
  pass; 16 GraphQL variable cases generated without target traffic.
- 17 focused tests pass on Windows with the one optional Linux engine test
  skipped. Includes same-origin fixed-version corpus regression, query wire-type
  classification, pre-socket rejection, output collisions, noninterleaving ledger
  claims, input snapshots, missing readback and failed-reset behavior.
- Final Windows/Python 3.13.12 validation passes 150 tests with two existing
  symlink skips and the optional Linux Atheris skip. Ruff correctness, syntax,
  installed-package CLI, native research and Web/API regressions pass.
- Native executables under this temporary checkout require elevated validation
  access on this host; the sandbox run failed to stat them. The elevated complete
  run passed without changing test conditions or tool identities.
