# Release readiness

Updated: 2026-09-15

## Release target

- Version: `0.1.0`.
- Git tag: `v0.1.0`.
- Channel: public GitHub release from `agentcarlosian/Whitehat`.
- Distribution: GitHub-generated source archives only.
- Release notes: [Whitehat 0.1.0](release-notes-0.1.0.md).
- PyPI, TestPyPI, wheels, sdists, package uploads, and trusted publishers: out of
  scope for this release.

The `whitehat` name on PyPI belongs to an unrelated project, currently listed as
version `1.2.3`. Whitehat documentation must never direct users to
`pip install whitehat`. The CLI and local package metadata may continue to use
the Whitehat name for installation from this repository's exact source tag.

## Current checkpoint

Private `main` is `d70805c45877be6eec8330141644057ba6baf89c`, including the
reviewed Ruff `0.16.7`, PyPA build `1.6.1`, setuptools `84.0.0`, and official
Actions v7 updates. No Git tags or GitHub releases exist. The GitHub repository
remains private.

The release branch changes the internal development version `0.12.0a1` to the
first public version `0.1.0`. The higher alpha numbers in the changelog were
private engineering checkpoints and were never published as a public upgrade
sequence.

Release implementation commit `5ca88cbd6a2f8621d9ef4192f44c51a71aeea685`
passed the complete local validation and technical audit with 160 tracked files,
45 release inputs, zero secret matches, a 53-file audit sdist, a 44-file audit
wheel, and clean installed version `0.1.0`. The final evidence-only commit and
eventual merge commit must repeat the audit.

## Technical audit

Install the pinned audit tools and run from a clean committed checkout:

```powershell
python -m pip install ".[release]"
python -B -m whitehat release audit --json
```

The audit requires clean Git state, rejects tracked links and private/generated
roots, scans tracked and packaged text for reviewed secret patterns, verifies the
Apache license, builds from the literal `release-files.txt` inventory, inspects
archive membership and source bytes, and installs the wheel without an index or
dependencies. Generated packages are audit inputs and are deleted after the
check; they are not release artifacts.

The audit records exact identities while keeping publication, legal clearance,
and originality claims false. Passing it is required but does not itself make the
repository or a release public.

## Release sequence

Complete these steps against one exact commit. Any source change returns the
process to validation and the clean audit.

### Prepare and merge

- [ ] Merge the `0.1.0` release-preparation PR after every matrix and release job
  passes.
- [ ] Verify the resulting `main` commit passes Ubuntu, Windows and macOS
  validation, source-fuzz, installed-package checks, and release-audit.
- [ ] Run the local clean-commit release audit and retain its content-free
  summary.
- [ ] Review `git ls-files` and the complete public diff. Confirm `.whitehat/`,
  credentials, target evidence, personal data, databases, caches, and generated
  artifacts are absent from every commit.
- [ ] Confirm README, security, conduct, contribution, provenance, third-party,
  issue-template, changelog, and release-note links render correctly.

### Prepare GitHub presentation

- [ ] Apply the description and evidence-backed topics in
  [GitHub presentation](github-about.md).
- [ ] Keep Issues enabled and Discussions disabled. Disable Wiki and Projects
  unless they have an active workflow. Enable automatic branch deletion.
- [ ] Confirm no release or package documentation suggests
  `pip install whitehat`.

### Publish the repository

- [ ] Change only `agentcarlosian/Whitehat` from private to public.
- [ ] Confirm public `main` is the exact audited commit and Apache-2.0, Actions,
  issues, description, and topics remain visible.
- [ ] Create a `main` ruleset that blocks deletion and force pushes and requires
  the `release-audit` status check, with a narrow owner recovery path.
- [ ] Enable private vulnerability reporting, dependency graph, Dependabot
  alerts and security updates, secret scanning, and push protection where GitHub
  makes them available.

### Publish `v0.1.0`

- [ ] Create and push annotated tag `v0.1.0` at the exact audited `main` commit.
- [ ] Create a non-draft, non-prerelease GitHub release titled `Whitehat 0.1.0`
  using `docs/release-notes-0.1.0.md` verbatim.
- [ ] Attach no package files. Use only GitHub's generated source archives.
- [ ] Verify the release tag, source archives, README badge, documentation links,
  issue routing, and security-reporting path while signed out.
- [ ] Clone `v0.1.0` into a new directory, install from source, and run
  `python -m whitehat doctor --json` plus the one-minute synthetic review.

## What remains unproven

The audit cannot prove copyright ownership, originality, trademark clearance,
absence of every possible secret, safety of future dependencies, support quality,
or that publication is advisable. It does not authorize target testing,
third-party data handling, hosted execution, disclosures, contact, or report
submission.

The active task and closure conditions are in
[public release preparation](tasks/public-release-prep.md).
