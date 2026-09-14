# Whitehat

[![Validate](https://github.com/agentcarlosian/Whitehat/actions/workflows/validate.yml/badge.svg)](https://github.com/agentcarlosian/Whitehat/actions/workflows/validate.yml)

**Security research tools for investigating code, triaging scanner reports, and building reproducible bounty review packets.**

Whitehat connects focused analysis with the work that follows: compare results,
record a hypothesis and negative control, and export a readable research review.
It is built for independent researchers working on explicitly authorized targets.

## What you can do

| Task | Implemented support |
| --- | --- |
| Review risky source patterns | Opengrep 1.30.0 with five authored Python/JavaScript rules |
| Triage dependency advisories | Import OSV-Scanner JSON with package/version, aliases, and reported fixes |
| Bring your existing tools | Import SARIF 2.1.0, ZAP JSON, Nuclei HTTP JSONL, Opengrep JSON, Betterleaks/Gitleaks JSON |
| Detect potential secrets | Betterleaks 1.8.1, redacted results, live credential validation disabled |
| Track what changed | Compare source trees, dependency manifests, or normalized observation baselines |
| Build a review packet | Portable workspace, structured case notes, linked review decisions, Markdown export |

The native analyzers support Windows and Linux x64. Report imports and the core
Python CLI do not require native analyzers. See the [compatibility table](docs/toolkit.md).
This is an alpha: pattern matches and advisory matches are leads for human investigation.

## Install

Requires Python 3.11 or newer. From a checkout:

```sh
python -m pip install .
whitehat doctor
whitehat tools
```

Use a virtual environment for development; see [contributing](CONTRIBUTING.md).
There is no published PyPI release advertised here. The repository is currently
private; public visibility is a separate owner decision.

## Try a complete review in one minute

These commands work in PowerShell and POSIX shells from the repository root.
They use an owned synthetic report; no scanner installation is needed.

```sh
python -m whitehat init .whitehat-demo --title "Owned dependency review"
python -m whitehat import examples/reports/osv.json --format osv --output .whitehat-demo/results/advisories.json
python -m whitehat review .whitehat-demo/results/advisories.json --decision needs-work --note "Check affected code and negative controls." --output .whitehat-demo/notes/review.json
python -m whitehat report .whitehat-demo/results/advisories.json --case .whitehat-demo/case.json --review .whitehat-demo/notes/review.json --output .whitehat-demo/exports/review.md
```

The result contains one synthetic advisory for `whitehat-owned-demo` at `1.0.0`,
a reported fix at `1.0.1`, and unverified reachability. Edit `case.json` to record
what you investigated. Open `exports/review.md` to see the research packet.

For security analysis, explicitly install the reviewed native tools:

```sh
python scripts/setup_tools.py --destination .whitehat/tools
python -m whitehat scan opengrep examples/research/vulnerable
python -m whitehat scan opengrep examples/research/fixed
python -m whitehat scan secrets examples/research/secrets
```

Expected: five source observations, zero in the fixed twin, and one redacted
synthetic canary. The setup command downloads exact upstream release assets and
verifies archive, executable, and companion hashes. It does not run an installer,
modify global PATH, or automatically update tools.

Follow the [source-review walkthrough](docs/quickstart.md) for saved baselines,
false-positive controls, review notes, and export. Every research command supports
`--json`; saved results use explicit `--output` paths and refuse overwrite.

## Research boundaries

Importing a report never runs its scanner or contacts its target. Native scans
parse a bounded disposable copy of source. External target scanning, credential
use, and submission are not implemented; the existing network implementation is
an explicit owned-loopback test profile. Tool setup downloads are separate from
research execution. [Capabilities and limits](docs/constraints.md)

## Contribute

Start with [CONTRIBUTING.md](CONTRIBUTING.md), the [adapter guide](docs/adapter-guide.md),
and [starter tasks](docs/starter-tasks.md). Add useful fixtures and rejecting
controls alongside a tool or rule. Report bugs in Whitehat itself according to
[SECURITY.md](SECURITY.md).

[Roadmap](docs/plan.md) · [Command reference](docs/runbook.md) ·
[Changelog](CHANGELOG.md) · [Third-party tools](THIRD_PARTY.md)

Whitehat source, authored rules, and owned examples are [Apache-2.0](LICENSE).
External tools retain their own licenses and are not bundled in the package.
