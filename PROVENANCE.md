# Provenance

Whitehat begins from an independent Git history and contains newly authored
product source, documentation, and owned synthetic fixtures. No implementation
files, schemas, reports, target records, evidence, or Git objects were imported
from an earlier product repository.

The runtime uses only the Python standard library. Optional development and
operator tools are installed separately and are not vendored:

- Ruff `0.14.14` for the reviewed local scanner adapter.
- PyPA build `1.4.2` and setuptools `80.10.2` for release-audit builds.

The release audit exports only the literal paths in `release-files.txt`, scans
tracked and packaged text for high-confidence secret patterns, verifies the
canonical Apache-2.0 license hash, inspects source and wheel archive membership,
compares packaged Python bytes with the tracked source, and installs the wheel in
a disposable virtual environment.

This record and the automated audit do not prove originality, ownership of
third-party names, legal clearance, or authorization to publish. The repository
owner makes the final visibility and release decision.
