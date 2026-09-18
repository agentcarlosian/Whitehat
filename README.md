# Whitehat

[![Validate](https://github.com/agentcarlosian/Whitehat/actions/workflows/validate.yml/badge.svg)](https://github.com/agentcarlosian/Whitehat/actions/workflows/validate.yml)

**Security research tools for investigating code, triaging scanner reports, and building reproducible bounty review packets.**

Whitehat connects focused analysis with the work that follows: compare results,
record a hypothesis and negative control, and export a readable research review.
It is built for independent researchers working on explicitly authorized targets.

The first public release is
[Whitehat 0.1.0](https://github.com/agentcarlosian/Whitehat/releases/tag/v0.1.0),
distributed as source on GitHub. It is an early release; the
[research methodology](docs/research-method.md) explains what the owned fixture
evaluations establish and what still requires human investigation.

## Choose a workflow

| Start here | What you will do |
| --- | --- |
| [One-minute review](#try-a-complete-review-in-one-minute) | Import a synthetic advisory and export a review without native tools or target access |
| [Source review](docs/quickstart.md) | Compare vulnerable, fixed, and negative-control source fixtures |
| [Web/API evidence](docs/web-api-quickstart.md) | Compare captures across identities and assess explicit access expectations |
| [Bounty packet](docs/bounty-workflow.md) | Prepare requests, bind an object ID, assemble evidence, and track retests |
| [Reproducible fuzzing](docs/fuzzing.md) | Use concrete mutation batches, stateful checks, reduction, and regression corpora |

## What you can do

| Task | Implemented support |
| --- | --- |
| Fuzz selected API inputs | Boundary/Hypothesis cases from prepared captures or scalar OpenAPI fields; exact reviewed batches |
| Check state and property boundaries | Relational readback assertions and finite-state sequences with explicit verified reset |
| Reproduce and regress failures | Finite reduction sweeps, smallest verified candidate, deduplicated HTTP case corpora |
| Investigate GraphQL | Offline SDL/introspection inventory, operation-aware captures, scalar/enum variable plans |
| Fuzz reviewed source parsers | Optional Atheris 3.1.0 fixed profiles on Linux x64/Python 3.12–3.14 |
| Prepare research requests | Selected HAR entry to concrete request and unapproved session draft; staged ID binding |
| Assemble evidence packets | Hash-pinned selected exchanges, comparisons, controls and Markdown reproduction steps |
| Track candidate retests | Per-candidate decisions, explicit duplicate relationships, comparison suitability and history |
| Inspect research coverage | Separate route observation, identity/object access outcomes and scenario completion |
| Compare API access | HAR/request-response imports, selected JSON evidence, identity/object access matrix |
| Replay approved requests | Exact prepared requests, session credential references, persistent budgets, HTTPS |
| Review API changes | OpenAPI inventory/coverage and oasdiff 1.32.0 with effective authentication comparison |
| Test lifecycle expectations | Explicit approved scenarios; Schemathesis 4.27.1 on an owned disposable API |
| Review risky source patterns | Opengrep 1.30.0 with five authored Python/JavaScript rules |
| Triage dependency advisories | Import OSV-Scanner JSON with package/version, aliases, and reported fixes |
| Bring your existing tools | Import SARIF 2.1.0, ZAP JSON, Nuclei HTTP JSONL, Opengrep JSON, Betterleaks/Gitleaks JSON |
| Detect potential secrets | Betterleaks 1.8.1, redacted results, live credential validation disabled |
| Track what changed | Compare source trees, dependency manifests, or normalized observation baselines |
| Build a review packet | Portable workspace, structured case notes, linked review decisions, Markdown export |

The native analyzers support Windows and Linux x64. Report imports and the core
Python CLI do not require native analyzers. See the [compatibility table](docs/toolkit.md).
Version `0.1.0` is the first public source release. Pattern matches and advisory
matches remain leads for human investigation.

## Install

Requires Git and Python 3.11 or newer. If your system names Python `python3`,
substitute it in these commands. Start from the published source tag:

```sh
git clone --branch v0.1.0 https://github.com/agentcarlosian/Whitehat.git
cd Whitehat
python -m venv .venv
```

Activate the virtual environment in your shell:

```powershell
# PowerShell
.\.venv\Scripts\Activate.ps1
```

```sh
# Bash or another POSIX shell
. .venv/bin/activate
```

Then install and inspect the CLI:

```sh
python -m pip install .
python -m whitehat doctor
python -m whitehat tools
```

For development on `main`, use the [contributor setup](CONTRIBUTING.md).
Whitehat is distributed from this GitHub repository only. The `whitehat` name on
PyPI belongs to an unrelated project: **do not use `pip install whitehat` to
install this toolkit**. See the [release record](docs/release-readiness.md) for
the exact commit and completed release checks.

## Try a complete review in one minute

These commands work in PowerShell and POSIX shells from the repository root.
They use an owned synthetic report; no scanner installation is needed. Choose a
new workspace name if `.whitehat-demo` already exists; outputs are never overwritten.

```sh
python -m whitehat init .whitehat-demo --title "Owned dependency review"
python -m whitehat import examples/reports/osv.json --format osv --output .whitehat-demo/results/advisories.json
python -m whitehat review .whitehat-demo/results/advisories.json --decision needs-work --note "Check affected code and negative controls." --output .whitehat-demo/notes/review.json
python -m whitehat report .whitehat-demo/results/advisories.json --case .whitehat-demo/case.json --review .whitehat-demo/notes/review.json --output .whitehat-demo/exports/review.md
```

The result contains one synthetic advisory for `whitehat-owned-demo` at `1.0.0`,
a reported fix at `1.0.1`, and unverified reachability. Edit
`.whitehat-demo/case.json` to record what you investigated. Open
`.whitehat-demo/exports/review.md` to see the research packet.

For native source analysis on Windows or Linux x64, explicitly install the
reviewed tools. On macOS or ARM, use the report-import workflow above; see the
[platform limits](docs/toolkit.md#platforms).

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

Importing a report never runs its scanner or contacts its target. Replay is an
explicit action under a current session and exact prepared-request hashes;
credentials are referenced separately. Schemathesis's first execution profile
uses only the owned API fixture. Automatic target discovery, login, broad scanning,
and submission are not provided. Tool setup downloads are separate from research
execution. [Replay contract](docs/http-replay.md) · [Capabilities and limits](docs/constraints.md)

## Contribute

Start with [CONTRIBUTING.md](CONTRIBUTING.md), the [adapter guide](docs/adapter-guide.md),
the [code of conduct](CODE_OF_CONDUCT.md), and [starter tasks](docs/starter-tasks.md).
Add useful fixtures and rejecting controls alongside a tool or rule. Report bugs
in Whitehat itself according to [SECURITY.md](SECURITY.md).

[Roadmap](docs/plan.md) · [Command reference](docs/runbook.md) ·
[Changelog](CHANGELOG.md) · [Third-party tools](THIRD_PARTY.md)

Whitehat source, authored rules, and owned examples are [Apache-2.0](LICENSE).
External tools retain their own licenses and are not bundled in the package.
