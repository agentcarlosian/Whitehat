# Public release preparation

Updated: 2026-09-15

Status: active on `codex/public-release-prep`.

## Objective

Prepare the clean-room Whitehat repository for a deliberate public visibility
decision while keeping tags, GitHub releases, package-index uploads, and
announcements outside this task.

## Acceptance criteria

- [x] Confirm PR #4 is merged and every job in the exact `main` run passed.
- [x] Run the `0.12.0a1` tracked-source, secret, license, sdist, wheel, and
  installed-package audit from the exact clean commit.
- [x] Refresh the README, package metadata, About proposal, plan, changelog, and
  release-readiness record.
- [x] Add conduct guidance, a pull-request template, issue routing, and monthly
  Dependabot version updates.
- [x] Pin every external GitHub Action reference to a verified full commit SHA.
- [ ] Validate the changed branch locally and in GitHub Actions.
- [ ] Merge the preparation branch and rerun the release audit at the exact
  resulting `main` commit.
- [ ] Apply and verify the owner-controlled GitHub settings in the release-day
  checklist.

## Fixed boundary

The repository remains private throughout implementation and review. This task
does not create a tag, GitHub release, PyPI/TestPyPI project or publisher,
package upload, announcement, or visibility change. Public vulnerability
reporting can only be enabled after the repository is public. PyPI publication,
if selected later, should use Trusted Publishing with a protected GitHub
environment and no stored upload token.

## Current evidence

- Merged baseline: `eacad9fd2925e9eb17e90d193e07310404580ae6`.
- Post-merge Actions run: `35024649241`, all seven jobs passed.
- Local release audit: passed at the same commit with 154 tracked files, 45
  release inputs, zero secret matches, a 53-file sdist, and a 44-file wheel.
- Preparation branch validation: Python 3.13.12, 70 syntax files, 151 tests,
  three expected skips, and the complete golden path passed.
- GitHub snapshot: private; issues enabled; Discussions disabled; `main` has no
  branch protection; automatic branch deletion is disabled.

## Closure condition

The task closes when the preparation changes are merged, the exact merged commit
passes CI and the local release audit, and the remaining release-day owner actions
are reduced to an explicit visibility decision plus post-public settings checks.
