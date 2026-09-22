# Framework-aware source review

The optional `express-typescript` Opengrep profile identifies request-input flows
to three sensitive operations: shell commands through `child_process.exec`,
dynamic evaluation through `eval`, and file-read paths through `fs.readFile`.
It uses the existing pinned Opengrep 1.30.0 core and newly authored rules; no
Express installation, dependency installation or application execution occurs.

## Run an owned review

After the explicit native-tool setup described in [toolkit.md](toolkit.md):

```sh
python -B scripts/evaluate_source_review.py --native --output-dir .whitehat-source-review
python -m whitehat scan opengrep examples/research/express/vulnerable --profile express-typescript
```

The evaluation exercises actual CLI commands, expects six observations across
TypeScript and CommonJS vulnerable fixtures, and zero in fixed and unrelated-
framework controls. It checks normalized flows, comparison, review and packet
exports. Open `.whitehat-source-review/exports/review.md` or `packet.md`.
Without `--native`, the evaluation needs no native tool and checks the owned SARIF
import/export path. `--installed` uses isolated imports of the installed package.

For an explicitly selected source tree:

```text
whitehat scan opengrep SOURCE --profile express-typescript --output NEW_RESULT.json --json
whitehat report NEW_RESULT.json --output NEW_REVIEW.md
```

`scan opengrep SOURCE` retains the existing `basic` profile: the same five
Python/JavaScript rules, source suffixes and rule/configuration identity.
The new profile copies `.js` and `.ts` files, selects the matching engine parser,
records `analysisProfile: express-typescript-v1` and the rules/config/input hashes,
and validates all reported flow paths against the copied source inventory.

## Supported patterns and limits

The first profile recognizes two-parameter arrow callbacks registered through
`get`, `post`, `put`, `patch`, `delete`, `all` or `use` on an app constructed from
an Express default import or `const express = require("express")`. Request
`query`, `body` and `params` expressions are sources. Sensitive operations use
direct `eval`, supported named/aliased/namespace imports, or namespace `require`
from `child_process`/`fs`, including the `node:` prefix.

Named handlers, Router construction, other callback shapes, decorators, JSX/TSX,
cross-file analysis and complete Express coverage are outside this profile.
The cross-function engine mode is not enabled. No general sanitizer is assumed
safe. The fixed controls use a shell-free API, JSON parsing and a fixed selected
file path. A clean scan does not establish that another application is secure.

The engine-reported source, assignment and sink locations appear in CLI output,
ordinary Markdown reviews and selected packet evidence. Read these as places to
inspect: confirm the route actually runs, the caller controls the input, guards
apply to that same value, and a protected action has unauthorized impact. The
engine may approximate calls or omit relevant guards. Whitehat does not establish
runtime reachability, sanitizer effectiveness, exploitability or finding validity.

## Import SARIF context

```sh
python -m whitehat import examples/reports/source-flow.sarif --format sarif --output .whitehat-source-review/results/flow.json
python -m whitehat report .whitehat-source-review/results/flow.json --output .whitehat-source-review/exports/flow.md
```

The independently authored parser retains secondary `locations`,
`relatedLocations`, and `codeFlows[].threadFlows[].locations` from supplied
SARIF 2.1.0 data. It supports in-report artifact indexes and shared thread-location
indexes. Cached thread locations must agree with any inline properties. Primary
locations retain the existing explicit-URI requirement. No source file, URI base,
external properties file or report-supplied URL is opened.

Only relative paths, bounded line/column coordinates, supplied step order,
execution-order numbers and recognized step kinds survive normalization. Kinds
are `source`, `sink`, `sanitizer`, `assignment`, `call`, `return`, `branch` and
`condition`. A reported sanitizer label is an assertion by the supplying tool.
Messages, snippets, variable contents, state, stacks, URLs and arbitrary properties
are omitted. Relative filenames can still be sensitive and require review.

Limits are 32 secondary locations, eight reported thread flows and 64 steps per
flow, plus 10,000 context locations across a report. Oversized/malformed records
and escaping paths reject. Missing physical locations, unresolved indexes/URI
bases and unrecognized kinds produce explicit representation diagnostics.
Unsupported native `CliCall` traces remain partial rather than being guessed.

Context uses the optional `sourceContext` field with schema
`whitehat-source-context-v1` and `validation: unverified`. Its completeness flag
describes this bounded representation, not analytical coverage or proof.
Observation fingerprints exclude this metadata, so adding a flow produces a
`metadataChanged` comparison instead of inventing a new observation identity.
Old results remain readable. Exports continue to distinguish tool reports from
analyst decisions; accepting a review never validates a reported flow.

Contract references: [SARIF 2.1.0, code and thread flows](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html),
[Opengrep's analysis-scope documentation](https://github.com/opengrep/opengrep/wiki/Intrafile-tainting-tutorial).
Compatibility claims above are checked with the exact pinned native engine and
newly authored fixtures, rather than inferred from those documents alone.
