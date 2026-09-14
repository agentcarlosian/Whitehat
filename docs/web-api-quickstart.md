# Web/API research walkthrough

From a checkout, install the CLI with `python -m pip install .`.
The capture workflow below needs no optional tools or network. Commands work in
PowerShell and POSIX shells; use a new workspace for each run.

## Compare owned access controls

```sh
python -m whitehat init .whitehat-web-review --title "Owned API access review"
python -m whitehat http import examples/http/vulnerable.har --project owned-api --select /marker --output .whitehat-web-review/results/vulnerable.json
python -m whitehat http import examples/http/fixed.har --project owned-api --select /marker --output .whitehat-web-review/results/fixed.json
python -m whitehat http compare .whitehat-web-review/results/vulnerable.json .whitehat-web-review/results/fixed.json --before-index 1 --after-index 1 --output .whitehat-web-review/results/comparison.json
python -m whitehat http assess examples/http/access-matrix.json --evidence .whitehat-web-review/results/vulnerable.json --output .whitehat-web-review/results/assessment.json
python -m whitehat report .whitehat-web-review/results/assessment.json --case .whitehat-web-review/case.json --output .whitehat-web-review/exports/access-review.md
```

Expected: the vulnerable capture has one access-expectation mismatch; the fixed
capture has none. The shared object and revoked-session controls are explicit.
The selected comparison changes from 200 with the owned marker to 403 without it.
A 200 response without the selected proof is inconclusive, not a finding.

HAR 1.2 is accepted from existing proxy workflows. Use `--identity`, `--object`,
and `--operation` to label a capture, or the `_whitehat` entry labels shown in the
owned fixture. `--format capture` accepts the equivalent
`whitehat-http-capture-v1` document with an `entries` array.

## Inspect API contracts

```sh
python -m pip install ".[api]"
python scripts/setup_tools.py --destination .whitehat/tools --tool oasdiff
python -m whitehat api inventory examples/api/before.json --project owned-api
python -m whitehat api diff examples/api/before.json examples/api/after.json --project owned-api --output .whitehat-web-review/results/api-changes.json
```

The diff returns a reported response-property addition and an effective security
change. OpenAPI 3.0/3.1 JSON is supported; YAML uses the optional `api` extra.
External references are refused. Server URLs are never followed by inventory or
diff. `api coverage SCHEMA --evidence HTTP_JSON --project PROJECT` maps observed
methods/routes to documented operations and preserves unmatched/ambiguous cases.

## Run the disposable API evaluation

```sh
python -m pip install ".[api-test,test-tls]"
python -m whitehat api test-owned --output .whitehat-web-review/results/owned-fixed.json
python -m whitehat api test-owned --vulnerable --output .whitehat-web-review/results/owned-broken.json
python -B scripts/evaluate_web.py
```

Schemathesis 4.27.1 executes its stateful phase against a fresh owned mini-API.
An independent explicit create/read/delete/read scenario then verifies the known
lifecycle invariant. The fixed twin passes; the broken twin leaves the deleted
object accessible and produces one review observation. Generated coverage varies
with the bounded run; a clean generated run is not proof of complete coverage.

This first Schemathesis profile has no target URL or custom-code input. It uses
an exact loopback destination, a fixture nonce, a bounded connection guard, a
fixed schema, one worker, no redirects/retries, and a process deadline. Fixtures
and temporary state are disposed. It is not a general OS sandbox.

## Replay approved research requests

The [capture-to-report walkthrough](bounty-workflow.md) adds request/session
drafting, staged ID binding, selected evidence packets, candidate retests and
identity/scenario coverage to the evidence path above.

See [replay sessions](http-replay.md) for actual HTTP(S) replay, credential
references, the request-hash preflight, and explicit stateful scenarios.
Do not send the checked-in `.invalid` example; it is an unapproved template.
