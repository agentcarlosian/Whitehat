# Public release preparation

Updated: 2026-09-15

Status: active on `codex/release-0.1.0`.

## Objective

Publish the first public Whitehat source release as GitHub tag and release
`v0.1.0`, without using PyPI or uploading package artifacts.

## Acceptance criteria

- [x] Merge the public-repository preparation and reviewed-toolchain PRs.
- [x] Select `0.1.0` as the first public version and record the private alpha
  checkpoints as non-public development history.
- [x] Confirm the PyPI `whitehat` name belongs to an unrelated project and add a
  prominent source-install warning.
- [x] Select GitHub topics only when they map to implemented Whitehat surfaces
  and established repository ecosystems.
- [x] Update package/CLI version metadata, cumulative changelog, README, release
  notes, roadmap, GitHub presentation, and release runbook.
- [x] Validate the release branch locally.
- [ ] Validate the release branch in GitHub Actions.
- [ ] Merge the release branch and rerun the audit at the exact resulting `main`
  commit.
- [ ] Apply the reviewed GitHub description/topics and public-repository security
  settings.
- [ ] Make only `agentcarlosian/Whitehat` public.
- [ ] Create annotated tag and non-prerelease GitHub release `v0.1.0` with no
  attached package files.
- [ ] Verify the public source release from a signed-out view and fresh clone.

## Fixed boundary

This release is source-only on GitHub. Do not create or configure PyPI/TestPyPI,
trusted publishers, package-index credentials, wheels, sdists, or upload jobs.
Generated distributions remain temporary inputs to the technical release audit.
The `whitehat` package on PyPI is unrelated and must not be presented as this
project.

Repository visibility, tag creation, and GitHub release publication occur only
after the exact merged commit passes CI, the local clean-commit audit, tracked
history review, and the final owner publication decision.

## Current evidence

- Current private baseline: `d70805c45877be6eec8330141644057ba6baf89c`.
- PR #9 merged the reviewed Ruff `0.16.7`, build `1.6.1`, and setuptools
  `84.0.0` identities with complete platform and release-audit checks.
- No existing Git tags or GitHub releases were found.
- Current About topics: `security-research`, `bug-bounty`, `security-tools`,
  `static-analysis`, `python`, and `cli`.
- Added topic candidates have active GitHub indexes and direct implemented
  mappings: `api-security`, `api-testing`, `fuzzing`, `openapi`, `graphql`,
  `sarif`, and `secret-scanning`.
- Release implementation commit `5ca88cb` passed 151 tests, 70 syntax checks,
  version/link/lint checks, and the complete golden path.
- Its clean `0.1.0` audit passed with 160 tracked files, 45 release inputs, zero
  secret matches, verified Apache-2.0, and clean installed version `0.1.0`.

## Closure condition

The task closes only after the exact public `main` commit, `v0.1.0` tag, GitHub
release, source archives, repository settings, security-reporting path, and a
fresh source installation are verified. PyPI remains excluded.
