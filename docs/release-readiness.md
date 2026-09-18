# Release status and checklist

Updated: 2026-09-17

## Published release

[Whitehat 0.1.0](https://github.com/agentcarlosian/Whitehat/releases/tag/v0.1.0)
is the first public source release. It was published on 2026-09-16 UTC.

- Repository: public, Apache-2.0.
- Annotated tag: `v0.1.0`.
- Release commit: `b516e80540217c8c290a04b6d79b70fd9b811c96`.
- Release state: published, not a draft or prerelease.
- Distribution: GitHub-generated source archives; no uploaded package assets.
- Release notes: [Whitehat 0.1.0](release-notes-0.1.0.md).
- Installation: [source checkout and virtual environment](../README.md#install).

The `whitehat` project on PyPI is unrelated. Do not use
`pip install whitehat` to install this toolkit. PyPI, TestPyPI, uploaded wheels
and sdists, and trusted publishers are outside the current release channel.

The higher alpha versions in the changelog were private engineering checkpoints.
They were never public releases and do not define a public upgrade sequence.
The published `v0.1.0` tag remains fixed; later documentation and code changes
on `main` do not change that release.

## Verified release evidence

[Validation run 35049516439](https://github.com/agentcarlosian/Whitehat/actions/runs/35049516439)
completed successfully for the release commit:

- Ubuntu and Windows with Python 3.11 and 3.13.
- macOS with Python 3.13.
- Actual Linux Atheris source-fuzz checks.
- The release audit, after all validation and source-fuzz jobs passed.

The platform jobs include installed-package checks. The annotated tag resolves
to the same commit, and the GitHub release has no uploaded assets. These facts
were rechecked on 2026-09-17.

A fresh checkout of the published tag was also installed in a new virtual
environment on Windows/Python 3.13.12 on 2026-09-17. The installed version,
`doctor`, `tools`, and all four README review commands passed and produced the
expected synthetic advisory report.

The [release-preparation record](tasks/public-release-prep.md) retains earlier
local and branch evidence. Repository administration settings and historical
local-only release checks are not inferred from successful CI.

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
and originality claims false. Passing it does not publish anything.

## Checklist for a future source release

This is a reusable checklist, not unfinished work for `v0.1.0`. Choose a new
version and one exact candidate commit. Any source change requires validation and
a clean audit of the new candidate.

1. Update package and CLI versions, changelog, installation examples, and release
   notes consistently.
2. Run the supported platform matrix, native-engine and source-fuzz evaluations,
   installed-package checks, and release audit.
3. Review the tracked changes and release inventory for credentials, personal
   data, target evidence, generated artifacts, and license/provenance issues.
4. Verify documentation links and the supported installation path.
5. Review repository presentation and security settings using the
   [maintainer checklist](github-about.md).
6. After the maintainer's release decision, create a new annotated tag at the
   verified commit and publish the reviewed release notes.
7. Keep the source-only channel: upload no wheels or sdists and do not configure
   a package index as part of this procedure.
8. Verify the public release, tag, source archives, and security-reporting path.
   Install from the new tag in a fresh checkout and virtual environment, then run
   `python -m whitehat doctor --json` and the README's one-minute review.

Do not move or reuse a published tag.

## Limits of the evidence

The audit cannot prove copyright ownership, originality, trademark clearance,
absence of every possible secret, safety of future dependencies, or support
quality. Publication and successful tests do not authorize target testing,
third-party data handling, hosted execution, disclosures, contact, or report
submission.
