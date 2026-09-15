# Third-party tools and rule provenance

Whitehat's runtime has no third-party Python dependencies. Native tools are
explicit optional downloads; their binaries are not included in Whitehat's sdist
or wheel. Whitehat-authored rules and examples are Apache-2.0.

| Tool | Version | Purpose | Upstream license/source |
| --- | --- | --- | --- |
| Opengrep core | 1.30.0 | Native Python/JavaScript analysis | LGPL-2.1, https://github.com/opengrep/opengrep |
| Betterleaks | 1.8.1 | Potential-secret detection | MIT, https://github.com/betterleaks/betterleaks |
| oasdiff | 1.32.0 | Prepared OpenAPI differences | Apache-2.0, https://github.com/oasdiff/oasdiff |
| Schemathesis | 4.27.1 | Owned stateful API test profile | MIT, https://github.com/schemathesis/schemathesis |
| Hypothesis | 6.168.0 | Optional bounded generation and finite-state sequences | MPL-2.0, https://github.com/HypothesisWorks/hypothesis |
| graphql-core | 3.2.12 | Optional offline schema/document parsing | MIT, https://github.com/graphql-python/graphql-core |
| Atheris | 3.1.0 | Optional reviewed source fuzzing on Linux x64 | Apache-2.0, https://github.com/google/atheris |
| PyYAML | 6.0.3 | Optional OpenAPI YAML parsing | MIT, https://github.com/yaml/pyyaml |
| trustme | 1.2.1 | Test-only ephemeral TLS certificates | MIT, https://github.com/python-trio/trustme |
| Ruff | 0.14.14 | Correctness adapter and development checks | MIT, https://github.com/astral-sh/ruff |
| PyPA build | 1.4.2 | Release audit | MIT, https://github.com/pypa/build |
| setuptools | 80.10.2 | Release audit backend | MIT, https://github.com/pypa/setuptools |

The Opengrep adapter uses newly authored rules in `whitehat/security_rules.py`.
It does not download or bundle Semgrep's separately licensed community rules.
Betterleaks uses the rules embedded in its pinned upstream binary plus an owned
non-credential marker. Live validation is explicitly disabled. No third-party
rule or implementation source is copied into this repository.

OSV-Scanner (Apache-2.0), ZAP, Nuclei, Gitleaks, and SARIF-producing tools can be
used independently to prepare reports. Whitehat's independently authored parsers
accept bounded subsets of their output; format compatibility is not endorsement,
license transfer, execution verification, or a claim of complete tool coverage.

Release source and hashes are recorded in `whitehat/native_tools.py` and reviewed
in [toolkit maintenance](docs/toolkit.md). Setup is explicit and uses release
assets, not remote shell installers. The technical audit scans Whitehat's tracked
and packaged files; it does not establish independent provenance for external tools.

Schemathesis is an optional Python extra with Hypothesis 6.168.0, Requests 2.34.2,
and urllib3 2.7.0 pinned for this profile. Other transitive dependency constraints
follow those packages. Core imports and JSON analysis remain standard-library-only.
The owned fixture profile does not execute caller schemas or hooks.

Fuzzing reuses the pinned Hypothesis version. Atheris is installed only through
the explicit `source-fuzz` extra on its supported platform; no native binaries
or third-party source are bundled. Its version and installed distribution RECORD
identity are recorded, alongside owned target hashes. The reviewed PyPI 3.1.0
release supplies Linux x64 wheels for CPython 3.12/3.13/3.14. The initial adapter
does not claim upstream source-build/macOS compatibility. graphql-core patch
version 3.2.12 is pinned because its minor versions can change APIs.
