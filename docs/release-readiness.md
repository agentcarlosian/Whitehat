# Release readiness

## Current boundary

The GitHub repository remains private. The current work implements a technical
audit; it does not change visibility, create a tag, upload a package, or announce
a release.

Install the pinned audit tools and run from a clean committed checkout:

```powershell
python -m pip install ".[release]"
python -B -m whitehat release audit --json
```

## Audit coverage

The audit:

1. Requires a clean Git working tree and records the exact commit.
2. Rejects tracked symbolic links and private/generated tracked roots.
3. Scans every tracked text file for bounded high-confidence private-key and
   provider-token patterns.
4. Requires the official Apache-2.0 license byte hash.
5. Requires the sorted, unique, literal `release-files.txt` inventory to cover
   every Python package source file.
6. Copies only that inventory into a disposable build context.
7. Requires pinned PyPA build and setuptools versions.
8. Builds one source distribution and one wheel without build isolation or
   network access.
9. Rejects unsafe, linked, oversized, missing, or unexpected archive members.
10. Verifies packaged Python and release-document bytes against the tracked
    inventory.
11. Scans packaged text for the same secret patterns.
12. Installs the wheel without an index or dependencies into a disposable virtual
    environment and checks `whitehat doctor --json` with network false.

The audit output includes the commit, release-tree identity, archive hashes,
member counts, installed version, tool versions, secret-match count, and false
publication claims. Temporary source, build, distribution, and installation
directories are removed when the command exits.

## What the audit cannot prove

- Copyright ownership or originality.
- Trademark or product-name clearance.
- Completeness beyond its reviewed secret patterns.
- Safety or correctness of future dependencies.
- That a private repository should become public.
- That a package should be tagged, uploaded, promoted, or supported.

Those remain explicit owner decisions based on the exact audited commit.

## Latest local checkpoint

The `0.8.0a1` audit passed at commit
`66f5264c0cf6d8dd9494c83e01f09803a0292c90` with:

- 61 tracked files scanned;
- 20 literal release-source files;
- zero high-confidence secret-pattern matches;
- canonical Apache-2.0 SHA-256
  `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`;
- 28 source-distribution files;
- 19 wheel files;
- clean installed `0.8.0a1` diagnostics with owned loopback true and external
  network false.

The generated distributions were temporary and were removed after inspection.
CI must rerun the audit for the final pushed commit.
