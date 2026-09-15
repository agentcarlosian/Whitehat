# Provenance

Whitehat begins from an independent Git history and contains newly authored
product source, documentation, and owned synthetic fixtures. No implementation
files, schemas, reports, target records, evidence, or Git objects were imported
from an earlier product repository.

The runtime uses only the Python standard library. Optional development and
operator tools are installed separately and are not vendored:

- Opengrep core `1.30.0` for the reviewed Python/JavaScript research adapter.
- Betterleaks `1.8.1` for redacted potential-secret detection without live validation.
- Ruff `0.14.14` for the correctness adapter and development checks.
- Hypothesis `6.168.0` and graphql-core `3.2.12` for optional fuzz generation and
  offline GraphQL understanding; Atheris `3.1.0` for reviewed fixed source profiles.
- PyPA build `1.4.2` and setuptools `80.10.2` for release-audit builds.

The security-review rules, report parsers, templates, and teaching fixtures were
newly authored for Whitehat. Upstream formats and native target serialization
were checked against primary documentation; no upstream implementation or rule
pack was copied. Exact native release/member hashes are in `whitehat/native_tools.py`.

The release audit exports only the literal paths in `release-files.txt`, scans
tracked and packaged text for high-confidence secret patterns, verifies the
canonical Apache-2.0 license hash, inspects source and wheel archive membership,
compares packaged Python bytes with the tracked source, and installs the wheel in
a disposable virtual environment.

This record and the automated audit do not prove originality, ownership of
third-party names, legal clearance, or authorization to publish. The repository
owner makes the final visibility and release decision.
