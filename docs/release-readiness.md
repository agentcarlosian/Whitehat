# Release readiness

Updated: 2026-09-15

## Current checkpoint

Whitehat `0.12.0a1` is merged on private `main` at
`eacad9fd2925e9eb17e90d193e07310404580ae6`. GitHub Actions run
[`35024649241`](https://github.com/agentcarlosian/Whitehat/actions/runs/35024649241)
passed the Ubuntu, Windows and macOS validation matrix, installed-package smoke
tests, the Linux Atheris job, and the release audit.

A fresh local audit at the same commit also passed:

- 154 tracked files scanned;
- 45 literal release-source files;
- zero high-confidence secret-pattern matches;
- canonical Apache-2.0 license SHA-256
  `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`;
- 53-file `whitehat-0.12.0a1.tar.gz` source distribution;
- 44-file `whitehat-0.12.0a1-py3-none-any.whl` wheel;
- clean installed diagnostics for version `0.12.0a1`.

Those results describe the exact merged commit before public-release-prep edits.
The preparation branch and its eventual merge commit must pass the same checks.

The repository remains private. No tag, GitHub release, package upload,
announcement, or visibility change is part of the technical audit.

## Audit command and coverage

Install the pinned audit tools and run from a clean committed checkout:

```powershell
python -m pip install ".[release]"
python -B -m whitehat release audit --json
```

The audit requires clean Git state, rejects tracked links and private/generated
roots, scans tracked and packaged text for reviewed secret patterns, verifies the
Apache license, builds from the literal `release-files.txt` inventory, inspects
archive membership and source bytes, and installs the wheel without an index or
dependencies. Its output records exact identities and keeps publication, legal
clearance, and originality claims false.

## Release-day owner checklist

Complete these actions against one exact audited commit. A failed or changed
commit returns the process to the audit step.

### Before changing visibility

- [ ] Merge the public-release-prep pull request and verify every required job on
  the resulting `main` commit.
- [ ] Run `python -B -m whitehat release audit --json` from that clean commit and
  retain its content-free summary.
- [ ] Review the public diff and `git ls-files` inventory; confirm `.whitehat/`,
  private evidence, credentials, personal data, local databases, and generated
  artifacts are absent from all commits.
- [ ] Confirm README links, issue forms, the security policy, conduct guidance,
  provenance, third-party notices, and package metadata render correctly.
- [ ] Decide whether the alpha should be repository-only or also receive a
  GitHub prerelease. Do not create a tag until that decision is explicit.

### Visibility action

- [ ] Change only `agentcarlosian/Whitehat` from private to public.
- [ ] Confirm the public repository still points to the audited `main` commit and
  retains issues, Actions history, Apache-2.0 detection, description, and topics.

### Immediately after visibility

- [ ] Create a `main` ruleset that blocks deletion and force pushes and requires
  the `release-audit` status check. Configure an owner recovery/bypass path that
  does not let ordinary contributors bypass checks.
- [ ] Enable private vulnerability reporting and verify the **Report a
  vulnerability** path from `SECURITY.md`.
- [ ] Enable the dependency graph, Dependabot alerts and security updates, secret
  scanning, and push protection where GitHub makes them available.
- [ ] Enable automatic deletion of merged branches. Disable the Wiki and Projects
  surfaces unless the project will actively use them; keep Discussions off until
  there is capacity to moderate it.
- [ ] Clone the public URL into a new directory, install without repository-local
  state, and run `whitehat doctor --json` plus the one-minute synthetic review.
- [ ] Recheck the badge, documentation links, issue routing, and public archive
  contents while signed out.

## Separate package-publication gate

There is no PyPI release. If package-index publication is selected later, use
PyPI Trusted Publishing from a dedicated GitHub Actions workflow and protected
GitHub environment with manual approval. Build distributions in a separate job,
grant `id-token: write` only to the publishing job, and do not store a long-lived
PyPI token. TestPyPI and PyPI remain separate owner decisions.

## What remains unproven

The audit cannot prove copyright ownership, originality, trademark clearance,
absence of every possible secret, safety of future dependencies, support quality,
or that publication is advisable. It also does not authorize target testing,
third-party data handling, hosted execution, disclosures, or report submission.

The exact preparation acceptance criteria are in
[public release preparation](tasks/public-release-prep.md).
