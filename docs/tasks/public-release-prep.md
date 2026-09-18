# Public release preparation

Updated: 2026-09-17

Status: `v0.1.0` is published. Release preparation is no longer the active
development task. The public release and CI evidence below supersede the
pre-publication state; administrative and local-only checks are not assumed
complete without their own records.

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
- [x] Validate the release branch in GitHub Actions.
- [x] Merge the release branch and pass CI, including the release audit, at the
  resulting `main` commit.
- [x] Apply the reviewed GitHub description and topics.
- [x] Make `agentcarlosian/Whitehat` public.
- [x] Create annotated tag and non-prerelease GitHub release `v0.1.0` with no
  attached package files.

## Evidence not reverified in the publication follow-up

The earlier checklist also called for owner-level repository/security settings,
a local clean-commit audit of the merge, and signed-out source-archive checks.
The public repository and CI results do not establish those historical actions.
A fresh source installation was verified during the documentation follow-up
below. Preserve original administrative and local audit evidence when available;
do not recreate the published release or mark checks complete by inference.

## Fixed boundary

This release is source-only on GitHub. Do not create or configure PyPI/TestPyPI,
trusted publishers, package-index credentials, wheels, sdists, or upload jobs.
Generated distributions remain temporary inputs to the technical release audit.
The `whitehat` package on PyPI is unrelated and must not be presented as this
project.

The original release gate required the exact merged commit to pass CI, the local
clean-commit audit, and tracked-history review before the owner's publication
decision. This paragraph records that gate; the public release now exists.

## Published release evidence

Rechecked on 2026-09-17:

- [Release `v0.1.0`](https://github.com/agentcarlosian/Whitehat/releases/tag/v0.1.0)
  was published on 2026-09-16 UTC and is neither draft nor prerelease.
- Annotated tag `v0.1.0` resolves to
  `b516e80540217c8c290a04b6d79b70fd9b811c96`, the merge of PR #10.
- [Run 35049516439](https://github.com/agentcarlosian/Whitehat/actions/runs/35049516439)
  passed all five platform cells, source-fuzz, and release-audit at that commit.
- The repository is public under Apache-2.0, and the release has no uploaded assets.
- The published description and topics match [GitHub presentation](../github-about.md).
- A fresh public-tag checkout installed successfully in a new virtual environment
  on Windows/Python 3.13.12. Installed `doctor`, `tools`, and all four README review
  commands passed and exported the expected synthetic advisory report.

## Historical preparation evidence (2026-09-15)

The following observations predate publication.

- Private preparation baseline: `d70805c45877be6eec8330141644057ba6baf89c`.
- PR #9 merged the reviewed Ruff `0.16.7`, build `1.6.1`, and setuptools
  `84.0.0` identities with complete platform and release-audit checks.
- No Git tags or GitHub releases existed at that preparation checkpoint.
- About topics at that preparation checkpoint: `security-research`, `bug-bounty`, `security-tools`,
  `static-analysis`, `python`, and `cli`.
- Added topic candidates have active GitHub indexes and direct implemented
  mappings: `api-security`, `api-testing`, `fuzzing`, `openapi`, `graphql`,
  `sarif`, and `secret-scanning`.
- Release implementation commit `5ca88cb` passed 151 tests, 70 syntax checks,
  version/link/lint checks, and the complete golden path.
- Its clean `0.1.0` audit passed with 160 tracked files, 45 release inputs, zero
  secret matches, verified Apache-2.0, and clean installed version `0.1.0`.
- PR #10 run `35048527174` passed all five platform cells, source-fuzz, installed
  package checks, and the release audit at `d0c8149`.

## Continuing maintenance

Use the [release record and future-release checklist](../release-readiness.md)
for subsequent releases. This historical task does not select new feature work,
authorize target testing, or include PyPI publication.
