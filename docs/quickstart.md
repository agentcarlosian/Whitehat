# Source-review walkthrough

Start from a checkout with Python 3.11+. All commands below work in PowerShell
and POSIX shells. If `python` is named `python3` on your system, substitute it.
Use a fresh output directory each time; Whitehat does not overwrite results.

## Install the CLI and the explicit research tools

```sh
python -m pip install .
python scripts/setup_tools.py --destination .whitehat/tools
python -m whitehat tools
python -m whitehat init .whitehat-source-review --title "Owned source comparison"
```

Native setup supports Windows/Linux x64. Other platforms can follow the report
import path in the README. Tool downloads require Internet access; analysis of
these fixtures does not. No target source is imported or executed.

## Find and compare observations

```sh
python -m whitehat scan opengrep examples/research/vulnerable --output .whitehat-source-review/results/before.json
python -m whitehat scan opengrep examples/research/fixed --output .whitehat-source-review/results/after.json
python -m whitehat scan opengrep examples/research/negative --output .whitehat-source-review/results/control.json
python -m whitehat compare .whitehat-source-review/results/before.json .whitehat-source-review/results/after.json --output .whitehat-source-review/results/comparison.json
```

Expected: five observations in the vulnerable twin, zero in the fixed twin, zero
in the strings-only control. Comparison reports five absent observations.
Absence alone does not prove a fix: inspect the actual change and scan coverage.
The baseline fingerprints include line numbers; moved lines may appear as changed.

## Investigate and record a decision

Edit `.whitehat-source-review/case.json`: identify the controlled input, intended
permission, exact version, hypothesis, reproduction status, negative control,
duplicate assessment, and next action. For this static demonstration leave
reproduction `not-attempted` unless you actually ran a separate controlled test.
The five authored rules cover eval, Python pickle deserialization, and shell
command construction. They do not establish dataflow or attacker reachability.

```sh
python -m whitehat review .whitehat-source-review/results/before.json --decision needs-work --note "Static sink patterns found; attacker-controlled reachability remains unverified." --output .whitehat-source-review/notes/review.json
python -m whitehat report .whitehat-source-review/results/before.json --case .whitehat-source-review/case.json --review .whitehat-source-review/notes/review.json --output .whitehat-source-review/exports/review.md
```

Open the Markdown packet. It contains rule explanations, relative locations,
provenance, the analyst's case, and the matching review note. Evidence references
are displayed as text and never opened or embedded.

## Bring other research artifacts

```sh
python -m whitehat import examples/reports/osv.json --format osv
python -m whitehat import examples/reports/source.sarif --format sarif
python -m whitehat import examples/reports/zap.json --format zap
python -m whitehat import examples/reports/nuclei.jsonl --format nuclei
python -m whitehat scan secrets examples/research/secrets
```

The OSV example is a made-up package/advisory. ZAP and Nuclei use reserved
`.invalid` hosts. The secret example is an owned marker, never a credential.
For absolute source paths in a report, use `--source-root` to strip the exact
lexical prefix. The importer does not open that source directory.

## Developer verification

Install development dependencies before running validation:

```sh
python -m pip install ".[scanner-ruff,release]"
python -B scripts/validate.py
python -B scripts/evaluate_research.py
```

`evaluate_research.py` requires the explicitly installed native tools and fails
if they are missing; it does not silently replace native scans with mocks.
