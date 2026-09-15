# Toolkit compatibility and maintenance

Reviewed 2026-09-15. Run `whitehat tools --json` for the shipped registry.

| Integration | Contract | Execution | Current compatibility evidence |
| --- | --- | --- | --- |
| Opengrep | 1.30.0 native core; pinned archive and executable/DLL hashes | Python and JavaScript source copy, five authored rules | Owned vulnerable/fixed/text controls; native evaluation required in CI |
| Betterleaks | 1.8.1; default rules plus an owned marker; pinned archive/binary | Text-source copy, no archive recursion, no live validation | Owned marker and clean native controls |
| OSV-Scanner | 2.x results/packages/vulnerabilities JSON, reviewed against 2.6.0 output docs | Import only | Owned synthetic report and adversarial parser checks; not a scanner-run attestation |
| SARIF | 2.1.0; rule IDs/indexes and primary physical locations | Import only | Synthetic CodeQL-shaped contract tests; arbitrary SARIF extensions omitted |
| ZAP | Traditional JSON site/alerts/instances | Import only | Owned report shape, query/evidence redaction |
| Nuclei | HTTP(S) JSONL template-id/info/matched-at | Import only | Owned report shape; other protocols require an adapter |
| Betterleaks/Gitleaks | JSON arrays; null is a clean result | Import only | Betterleaks native output plus owned cross-compatible report |
| oasdiff | 1.32.0; native release/member hashes | Prepared schema diff | Owned structural and inherited-security changes |
| Schemathesis | 4.27.1; optional Python extra | Owned mini-API only | Generated stateful run plus explicit lifecycle twins |
| Hypothesis | 6.168.0; optional fuzz extra | Bounded offline scalar and finite-state generation | Fixed seeds, owned API twins, concrete batch execution and reset checks |
| graphql-core | 3.2.12; optional graphql extra | Offline SDL/introspection/document parsing | Distinct operations/fragments, variable plans, negative/partial-response fixtures |
| Atheris | 3.1.0; optional source-fuzz extra | Reviewed fixed parser/owned profiles, Linux x64/Python 3.12–3.14 | Actual engine test is required in Linux/Python 3.13 CI; no Windows/macOS execution claim |
| Ruff | 0.14.14; E4,E7,E9,F | Python correctness check | Existing dirty/clean fixtures; not a security analyzer |

## Platforms

Core: Python 3.11+; CI targets Ubuntu and Windows with Python 3.11/3.13, and
macOS/Python 3.13 for imports/core checks. Native research tools are pinned for
Windows/Linux x64. macOS and ARM native execution are not yet supported by this
adapter release. CI configuration is not itself evidence that a run passed;
consult the linked run for a particular commit.
The Atheris profile is a separate optional Python/native integration with the
platform constraints above; it is not installed by `setup_tools.py`.

## Import behavior

Reports are bounded to 16 MiB and 10,000 observations. Duplicate JSON keys,
invalid structures, escaped source paths, non-finite numbers, and conflicting
duplicate identities fail with documented CLI errors. SARIF messages, source
snippets, HTTP query/fragment/body values, and secret values are omitted. Relative
paths and URL paths may still be sensitive: review before sharing.

Reported fix versions belong to the matching package/ecosystem. They are not
verified installed versions or proof that the vulnerable function is used. An
OSV import records withdrawn status and aliases; it does not evaluate arbitrary
version-range semantics, retrieve advisories, or establish bounty eligibility.

SARIF import uses the first physical location of each result. It does not resolve
external properties, fetch artifacts, execute queries, or interpret suppressions.
Baseline fingerprints include tool/rule/location/context; a line movement can
change a fingerprint. Compare tool/configuration and coverage before interpreting
an absent observation. `sameAnalysisProfile` helps expose profile drift.

## Update procedure

1. Select an exact upstream release and review changelog, CLI, output, and licenses.
2. Record official archive hashes and verify executable/companion member hashes.
3. Update the literal registry and fixtures in one reviewed change.
4. Run native vulnerable/fixed/negative evaluations on each supported platform.
5. Run malformed-output, timeout, redaction, package and full validation checks.
6. Update this table, THIRD_PARTY.md, and the changelog with actual evidence.

Updates never happen during a research scan. `scripts/setup_tools.py` only
installs exact reviewed assets. Engine versions and authored ruleset hashes appear
in scan provenance; imported results explicitly say execution is unverified.

See [web/API walkthrough](web-api-quickstart.md), [HTTP evidence](http-evidence.md),
and [replay sessions](http-replay.md) for the new capability contracts. The older
research-result v1 identity remains compatible; project-bound HTTP evidence has
a separate stable observation identity and mutable evidence hash.
