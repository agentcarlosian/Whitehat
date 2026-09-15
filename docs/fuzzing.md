# Fuzzing and reproducible research

Whitehat prepares concrete request cases from captures, OpenAPI scalar fields,
GraphQL variables and finite-state models. The same exact-request replay ledger
executes setup, test, readback and reset. Results connect to evidence packets,
candidate decisions, reduction batches and corpus regression.

Core boundary generation and assessment use the standard library. Install the
optional generators/parsers for the complete walkthrough:

```sh
python -m pip install ".[fuzz,graphql]"
python -B scripts/evaluate_fuzz.py --output-dir .whitehat-fuzz-demo
```

This starts only newly authored disposable APIs on `127.0.0.1`, uses fake owned
identities, runs vulnerable/fixed controls, and retains reports, request batches,
reduction cases and corpus history. It accepts no target URL. Without an output
directory, its artifacts are disposable. Add `--installed` after installation to
exercise isolated imports of the installed CLI.

The owned evaluation must find mutation/readback and workflow discrepancies in
the broken twins, none in the fixed twins, and verify reset. Its counts describe
these fixtures only. The ordinary commands below never choose a target or turn a
schema, captured credential or model into authority to execute requests.

## 1. Prepare a bounded mutation batch

```sh
python -m whitehat init .whitehat-fuzz-review --title "API mutation review"
python -m whitehat fuzz plan examples/fuzz/request.json --schema examples/fuzz/openapi.json --project owned-fuzz --identity bob --seed 7 --output .whitehat-fuzz-review/plan.json
python -m whitehat fuzz generate .whitehat-fuzz-review/plan.json --output-dir .whitehat-fuzz-review/batch
```

`http prepare` can supply the request from an existing HAR entry. `fuzz plan`
also works without OpenAPI: it proposes scalar slots from captured JSON/query
fields. Inferred types are suggestions; review them against the API's contract.
The checked-in examples use `.invalid` and must be retargeted only as part of an
independently authorized session. The owned evaluation does this for its own API.

A `whitehat-fuzz-plan-v1` contains a prepared request, project/identity labels,
seed, maximum cases, samples per field, explicit mutation slots, expected status
codes, and optional setup/readback/reset and relational assertions. The complete
example is [mutation-plan.json](../examples/fuzz/mutation-plan.json).

The first profile changes one object property or query parameter at a time.
Seeds must satisfy the selected scalar projection before a positive baseline is
generated. Query values are classified after string serialization/coercion;
JSON strings and numbers cannot be treated as different wire types in a query.
It tests omissions of declared required fields, null/wrong-type values, numeric
and length boundaries, enums, and reproducible Hypothesis samples. Mutations
cannot change origin, HTTP method, credentials or arbitrary headers. Credential-
like slots are rejected. Query duplicates, path encodings and raw framing need
separate transport profiles and are not silently normalized into these cases.

Supported schema keywords are `type` (string/integer/number/boolean), `enum`,
`minimum`, `maximum`, `minLength` and `maxLength`. Nested object properties are
supported up to five levels. Plans expose unsupported property keywords and
generation refuses them until the operator reviews the projection. Array/input-
object generation, regex constraints and complete OpenAPI conformance are not
claimed. An accepted scalar case does not prove the whole request is valid.

Bounds: 16 mutation slots, 32 cases, 100 total request steps including cleanup,
and 16 MiB of generated artifacts. Hypothesis sampling is pinned to 6.168.0;
`samplesPerField: 0` uses deterministic boundary cases without that dependency.
Record the same plan/seed and engine version when reproducing a generation run.
The case limit can stop generation before every boundary is emitted; inspect the
concrete cases and increase or split the plan deliberately when needed.

Output contains a hash-pinned `batch.json`, case documents, concrete request
files, and `session.draft.json`. The draft has approval and researcher-control
assertions false, mutation disabled and identity authentication set to `none`.
Set actual credential references, selectors, timing, policy and budgets only
after reviewing the full batch. Prepared files and corpora contain request data;
keep them in an ignored research workspace and review them before sharing.

## 2. Execute and assess authoritative readback

```text
whitehat fuzz run BATCH.json --session REVIEWED_SESSION.json --state LEDGER.sqlite3 --output RUN.json
whitehat fuzz evidence RUN.json --output HTTP_EVIDENCE.json
whitehat fuzz assess RELATIONAL_PLAN.json --output ASSESSMENT.json
```

The entire batch is checked against one current session before any request.
All exact request hashes, identities, origins, methods and selected response
pointers must already be approved. The ledger must have enough remaining budget
for the full batch, including reset. Inputs are copied after verification to
prevent source-file edits from changing a case during execution. A transactional
batch claim prevents another batch or ordinary replay from interleaving.

Case expectations contain `statuses`, selected scalar `values`, and `absent`
pointers. Relational assertions support `unchanged`, `equals`, integer `delta`,
`equals-value`, `present`, and `absent`. Operands bind a step/evidence ID, JSON
pointer, identity and object label. A protected-field example:

```json
{
  "id": "owner-unchanged",
  "relation": "unchanged",
  "left": {"stepId": "before", "pointer": "/owner", "identityId": "alice", "objectId": "owned-item"},
  "right": {"stepId": "after", "pointer": "/owner", "identityId": "alice", "objectId": "owned-item"},
  "value": null
}
```

This checks the owner readback before and after Bob's update. The owned broken
twin returns an ordinary success response while changing the protected owner;
the assertion detects the subsequent state change. The fixed twin preserves it.
Missing bodies, unselected values, unsuitable readback statuses and conflicting
object/identity bindings are inconclusive. Boolean true and numeric one are
different values. Integer deltas never coerce strings, floats or booleans.

Offline `whitehat-relational-plan-v1` documents contain `projectId`, `assertions`
and an `evidence` array. Each reference has `id`, contained relative `path`, exact
`resultSha256` and `evidenceSha256`. Order in an offline plan is operator asserted;
the assessor does not invent a causal sequence from unrelated captures.

Test expectation failures still allow the declared readback/reset to complete
while the session permits it. Failed setup skips the test body. A redirect, rate
limit, transport error, stopped session or exhausted budget cannot be bypassed
to perform cleanup. Incomplete or failed reset stops later cases and remains
visible in output. A crashed process can leave a ledger claim for operator
inspection; there is no automatic recovery that clears budgets or state.

`RUN.json` is a standard research result with per-case outcomes and nested
normalized HTTP evidence. `fuzz evidence` extracts the latter for existing
comparison/access/packet commands. Packet renderers include case outcomes,
failure signals, completion and cleanup; supply the extracted HTTP document as
an explicit packet reference. No raw request body or credential is embedded by
these renderers. A mismatch remains a lead requiring impact and control checks.

## 3. Reduce, retain and regress failures

```text
whitehat fuzz reduce CASE.json --run ORIGINAL_RUN.json --failure-key assertion:owner-unchanged --output-dir REDUCTION
whitehat fuzz run REDUCTION/batch.json --session REVIEWED_REDUCTION_SESSION.json --state REDUCTION_LEDGER.sqlite3 --output REDUCTION_RUN.json
whitehat fuzz minimize REDUCTION/batch.json --run REDUCTION_RUN.json --output-dir MINIMIZED
whitehat fuzz corpus init CORPUS --project PROJECT
whitehat fuzz corpus add CORPUS --case MINIMIZED/case.json --run REDUCTION_RUN.json --failure-key assertion:owner-unchanged
whitehat fuzz corpus batch CORPUS --output-dir REGRESSION
whitehat fuzz run REGRESSION/batch.json --session REVIEWED_REGRESSION_SESSION.json --state REGRESSION_LEDGER.sqlite3 --output REGRESSION_RUN.json
whitehat fuzz corpus regress CORPUS --batch REGRESSION/batch.json --run REGRESSION_RUN.json
```

Reduction removes test steps that are not assertion operands, drops top-level
JSON properties, and tries shorter strings/simpler integers. Setup/reset and
assertion definitions remain intact. Every candidate is a new concrete request
and must be in the reviewed reduction session before execution. No hidden replay
or adaptive live shrinking occurs inside `minimize`.

The minimizer selects the shortest step sequence and smallest request bytes
among candidates that actually reproduced the selected signal with completed
cleanup. It retains the parent case/run, seed/engine lineage and selected run
hash. `globalMinimumProven` stays false. Another reduction round can continue
from the selected case. Matching an assertion/status signal is not proof of the
same vulnerability root cause.

Corpus entries deduplicate exact request/expectation sequences plus the selected
failure signal. Up to 100 entries are supported. A regression batch takes a
bounded prefix fitting 32 cases/100 requests; use repeated `--entry SHA256` to
select other entries explicitly. Regression checks distinguish `reproduced`,
`not-observed`, `inconclusive`, `not-tested` and `not-comparable`. Changed input
sequences cannot retain comparability merely by copying a lineage label. Missing
cases never become fixed. These are portable operator-controlled files, not an
immutable store or a platform's private duplicate database.

## 4. Generate stateful sequences

```sh
python -m whitehat fuzz stateful examples/fuzz/stateful-model.json --output-dir .whitehat-fuzz-review/sequences
```

The model declares states, initial state, and actions with allowed predecessor
states, next state, literal prepared request/expectations, and rejection statuses
for invalid transitions. Hypothesis generates bounded action sequences alongside
single-action controls. Readback follows each case, and reset must end with a GET
that checks selected authoritative state. The example detects publication before
approval in the broken twin and confirms the fixed twin rejects it.

Limits are 16 cases, 10 generated actions per case, 20 states and 16 actions;
the common 100-request batch limit includes setup/readback/reset. Cases declare
expected transitions and preserve their seed/model hash. This version uses
preallocated or previously bound object IDs. Response-driven identifier binding
during execution, arbitrary Python models, login/refresh and concurrency are not
part of the profile. Existing staged `http bind` can prepare IDs before generation.

## 5. GraphQL and optional source fuzzing

```sh
python -m whitehat graphql inventory examples/fuzz/schema.graphql --project owned-fuzz
python -m whitehat graphql inspect examples/fuzz/query.graphql --schema examples/fuzz/schema.graphql --project owned-fuzz
python -m whitehat graphql plan examples/fuzz/graphql-request.json --schema examples/fuzz/schema.graphql --project owned-fuzz --identity alice --output .whitehat-fuzz-review/graphql-plan.json
python -m whitehat fuzz generate .whitehat-fuzz-review/graphql-plan.json --output-dir .whitehat-fuzz-review/graphql-batch
```

SDL and supplied introspection JSON are supported through graphql-core 3.2.12.
No introspection request, resolver or schema-supplied code executes. Documents
are parsed/validated with token, node and depth limits. Multiple operations need
an explicit operation name when inspecting; captured `operationName` selects the
operation during import. Fields, aliases, fragments and variable types contribute
to operation metadata. Literal and variable values stay in request hashes rather
than operation metadata. Different operations at `/graphql` remain distinct.

`graphql import CAPTURE.har --schema SCHEMA --project PROJECT --identity ID
--object ID --select /errors/0/message --output EVIDENCE.json` accepts bounded
POST JSON exchanges. Partial `data` and `errors` remain in the selected evidence.
Batches, subscriptions, persisted-query-only inputs and streaming/multipart
responses are outside the first profile. Variable mutation supports built-in
scalar and enum variables. Input objects, lists and custom scalars need explicit
strategies. GraphQL plans add selected error-presence/absence checks because an
HTTP 200 can carry validation errors; nullable variables, ID integer coercion and
required-variable defaults are handled separately from HTTP status codes.

For source fuzzing, use Linux x64 with Python 3.12–3.14:

```sh
python -m pip install ".[source-fuzz]"
python -m whitehat fuzz source capture-parser --runs 1000 --seed 7 --output-dir .whitehat-source-fuzz
```

The optional Atheris 3.1.0 adapter runs reviewed fixed profiles:
`capture-parser` (HAR container parsing), `request-parser` (prepared-request
validation), and the `owned-fixed`/`owned-broken` parser controls. It does not
accept module names, target executables or arbitrary Python. New libraries need
a reviewed harness following [the adapter guide](adapter-guide.md).

The Atheris integration uses the documented engine interface; its coverage
feedback is internal to the engine. It does not publish a branch-coverage score
or claim that generated HTTP cases provide code coverage of a remote service.

Use `--corpus DIRECTORY` for 1–20 explicit seed files, each at most 8 KiB. Native
execution is bounded by runs, 8 KiB inputs, a 15-second engine time setting and
25-second parent deadline, bounded output and a disposable working directory.
The worker refuses Python socket/process APIs. This is not an OS sandbox for
hostile code. The distribution version/RECORD identity, target-source hashes,
seed, callback count and process receipt are retained.
The fixed worker stops after the requested callback count with `SystemExit`;
Atheris/libFuzzer reports exit 77 for that stop. The parent accepts only exits 0
or 77 and still requires a complete bounded worker result with the exact profile
and tool version. An engine exit without that result remains an adapter failure.
Whitehat parses exactly one uniquely prefixed JSON result line; other bounded
Atheris/libFuzzer stdout cannot be interpreted as normalized evidence.

Failures produce `source-case.json` containing the exact input as `dataBase64`
and its digest, plus normalized `result.json`. To reproduce, decode that input
into a new seed file and rerun the same profile/version with that seed corpus.
The raw reproducer is an explicitly requested input artifact; it is not printed
in the terminal receipt. These source seed corpora are distinct from HTTP case
corpora. Expected parser rejections are not counted as failures. Neither callback
count nor a clean run proves complete coverage or absence of vulnerabilities.

Windows/macOS retain the core, GraphQL and Hypothesis workflows. The initial
Atheris execution support is Linux only, matching the reviewed 3.1.0 wheels.
CI executes the actual engine on Linux/Python 3.13 and checks its owned twins.
