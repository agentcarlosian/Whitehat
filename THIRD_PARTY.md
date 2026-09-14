# Third-party tools and rule provenance

Whitehat's runtime has no third-party Python dependencies. Native tools are
explicit optional downloads; their binaries are not included in Whitehat's sdist
or wheel. Whitehat-authored rules and examples are Apache-2.0.

| Tool | Version | Purpose | Upstream license/source |
| --- | --- | --- | --- |
| Opengrep core | 1.30.0 | Native Python/JavaScript analysis | LGPL-2.1, https://github.com/opengrep/opengrep |
| Betterleaks | 1.8.1 | Potential-secret detection | MIT, https://github.com/betterleaks/betterleaks |
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
