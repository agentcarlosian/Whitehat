# Decision 0003: technical publication audit

Date: 2026-09-14

Status: accepted

## Decision

Whitehat uses one fixed technical audit before any public visibility or package
release decision. The audit runs only from a clean Git commit and builds from a
literal tracked-file export in a disposable directory.

The audit verifies tracked-source hygiene, selected high-confidence secret
patterns, the canonical Apache-2.0 text, declared runtime and optional
dependencies, exact package-source bytes, bounded archive membership, and a
clean-wheel installation. It emits hashes and counts but retains no built
artifact by default.

Passing the audit does not authorize publication. Legal clearance, originality,
name/trademark clearance, account configuration, public visibility, tagging,
upload, announcement, and ongoing maintenance remain owner decisions.

## Consequences

- `release-files.txt` is the literal distribution-source inventory and must
  exactly cover every Python package file.
- Ruff, PyPA build, and setuptools remain optional pinned tools, not runtime
  dependencies or vendored source.
- CI runs the release audit separately after the normal Python matrix.
- The release result always keeps publication authorization and publication
  performed false.
