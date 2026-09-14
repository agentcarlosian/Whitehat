# From a capture to a reviewable bounty packet

The commands below prepare research artifacts, compare evidence, and record human
decisions. They do not send requests. Install from a checkout with
`python -m pip install .`; no optional dependencies are needed for this walkthrough.

For a complete owned example with all artifacts retained:

```sh
python -B scripts/evaluate_bounty.py --output-dir .whitehat-bounty-demo
```

Open `.whitehat-bounty-demo/exports/bounty-review.md`. The script exercises the
actual CLI: capture preparation, import, comparison, access assessment, ID binding,
packet assembly/export, candidate creation/retest, and access coverage. The
captures are authored fixtures at `.invalid` URLs, not live observations.
Choose a new output directory for every run. Without `--output-dir`, the script
uses disposable storage and is suitable for CI.
After installing the package, add `--installed` to exercise isolated Python
imports of the installed CLI rather than the checkout.

## Prepare one captured request

```sh
python -m whitehat http prepare examples/bounty/capture.har --index 0 --project owned-api --identity alice --object owned-item --operation create --output-dir .whitehat-prepared
python -m whitehat http preview .whitehat-prepared/request.json --json
```

Preparation creates `request.json`, `session.draft.json`, and `receipt.json` in a
new directory. The source capture is unchanged. The request preserves eligible
headers, URL and captured JSON/form text; raw request data is written only to the
requested input artifact. The terminal receipt shows hashes and diagnostics.

Bearer Authorization and Cookie values are removed in favor of a credential
reference. Combined mechanisms, duplicate headers, other credential-like headers,
credential-like query/body fields, echoed captured credentials, and unsupported
body formats require manual preparation. Transport-managed headers are omitted
with diagnostics. This is a bounded preparation profile, not a general HAR-to-wire
round trip or a guarantee that arbitrary request data is nonsensitive. Review the
request file before using or sharing it. Credential detection is conservative
and cannot discover every application's secret naming convention.

Session drafts have both approval and researcher-control assertions false,
mutation permission false, a credential-reference placeholder where needed, and
an empty response selector list. Complete and review the session according to
[HTTP replay](http-replay.md) before execution. Preparation never approves it,
reads credentials from the environment, or edits a consumption ledger.

HAR imports retain ordinary successful/denied HTTP exchanges in the v1 evidence
schema. Status zero or absent responses become `provenance.incompleteEntries`
with original entry indexes and sanitized context. Null/missing captured bodies
remain uncaptured. Malformed entries reject the archive; they are not silently
skipped. `entryIndexes` maps normalized exchanges back to source entries.
WebSocket extensions produce an unsupported-message diagnostic. Compressed HAR
archives and native proxy database files are not supported.

The failed-flow/null-body shapes were checked against the
[mitmproxy HAR exporter](https://github.com/mitmproxy/mitmproxy/blob/main/mitmproxy/addons/savehar.py).
The compatibility tests use newly authored shape fixtures; they do not claim
that every version of mitmproxy or every HAR producer has been exercised.

## Assemble an evidence-linked packet

```sh
python -m whitehat packet init --project owned-api --title "Owned access review" --evidence .whitehat-bounty-demo/results/vulnerable.json --evidence .whitehat-bounty-demo/results/fixed.json --evidence .whitehat-bounty-demo/results/comparison.json --evidence .whitehat-bounty-demo/results/assessment.json --output .whitehat-bounty-demo/another-packet.json
python -m whitehat packet check .whitehat-bounty-demo/another-packet.json --json
python -m whitehat packet export .whitehat-bounty-demo/another-packet.json --preset hackerone --output .whitehat-bounty-demo/exports/another-draft.md
```

`packet init` selects all normalized observations/exchanges in the explicitly
supplied files. Edit each reference's `select` list to narrow that selection.
Fill in prerequisites, demonstrated impact, limitations, negative control, and
numbered steps with action, expected result, observed result, and evidence IDs.
The manifest pins each result hash; every selected ID must exist in that result.
Keep evidence below the manifest's directory. Traversal, links/junctions, and
outside references are rejected. Maximums: 20 files, 8 MiB/file, 32 MiB total,
50 steps, and a 16 MiB Markdown export.

Renderers support normalized research results, HTTP evidence (including explicit
scenario outcomes), and HTTP comparisons. Access assessments include matrix
hashes, row outcomes and exchange references. Raw captures, prepared requests,
arbitrary attachments and credentials are not accepted as packet evidence.
Research v1 results without a project ID retain an operator-asserted association
with the manifest project; existing files are not silently migrated.

`packet check` is informational: `contentComplete` describes content and links,
not finding validity or submission readiness. Missing/altered evidence is named
as an issue and never embedded as verified content. Draft export still succeeds;
malformed manifests and escaping paths fail. Missing comparison/assessment links
and incomplete scenarios remain visible. The `generic`, `hackerone`, and
`bugcrowd` presets are Markdown layouts; there is no account connection or
automatic submission. Existing `report RESULT` remains available unchanged.

## Bind a created ID into a follow-up request

The complete demo produces a working `binding.json`. A binding plan has this shape:

```json
{
  "schemaVersion": "whitehat-request-binding-v1",
  "projectId": "owned-api",
  "source": {
    "path": "results/vulnerable.json",
    "resultSha256": "REPLACE_WITH_RESULT_HASH",
    "evidenceSha256": "REPLACE_WITH_EXCHANGE_HASH",
    "pointer": "/id",
    "identityId": "alice",
    "objectId": "owned-item"
  },
  "request": {"path": "inputs/read-template.json", "requestSha256": "REPLACE_WITH_PREVIEW_HASH"},
  "pathSegment": 2,
  "expectedSegment": "PLACEHOLDER"
}
```

```sh
python -m whitehat http bind .whitehat-bounty-demo/binding.json --output-dir .whitehat-bounty-demo/another-bound-request
```

Path segments are one-based after the leading slash: `/items/PLACEHOLDER` uses
segment 2. The source must be an exact hash-pinned exchange in the declared
project, with explicit matching identity/object labels and a captured, selected
string ID. IDs allow ASCII letters, digits, underscores and hyphens, up to 100
characters. Containers, missing/null values, slashes and traversal syntax fail.
Source and request origins must match. The binding changes only the declared
segment after checking its expected original content; method, headers, body,
query and logical labels remain the same. This first profile intentionally
does not bind query/body values, headers, credentials, or entire URLs.

Output is a new `request.json` and hash-linked `receipt.json`. Review the concrete
request under a new session before replaying it. The binding command never
rewrites a session or ledger and performs no response-driven live chaining.

## Candidate decisions and retests

```sh
python -m whitehat candidate init .whitehat-bounty-demo/another-candidate --id access-2 --project owned-api --title "Owned access discrepancy"
python -m whitehat candidate record .whitehat-bounty-demo/another-candidate --evidence .whitehat-bounty-demo/results/vulnerable.json --select EXCHANGE_SHA256 --decision needs-work --note "Verify object ownership and negative controls."
python -m whitehat candidate record .whitehat-bounty-demo/another-candidate --evidence .whitehat-bounty-demo/results/fixed.json --select FIXED_EXCHANGE_SHA256 --decision not-reproduced --retest-of 1 --note "Same labeled request and selectors; fixed synthetic twin denies access."
python -m whitehat candidate history .whitehat-bounty-demo/another-candidate --json
```

Use exchange evidence hashes for HTTP and observation fingerprints for scanner
results. The demo's existing `candidate/` contains a filled two-decision example.
Decisions are `open`, `needs-work`, `dismissed`, `reproduced`, `not-reproduced`,
`inconclusive`, or `not-comparable`. Each requires rationale. Optional `--related
ID --relation possible-duplicate|same-candidate` records a human relationship;
it never merges candidates or queries a platform's private duplicate history.

Records are exclusively created in sequence and link predecessor and candidate
hashes. History validation rejects missing/reordered/altered records. The files
are ordinary operator-controlled storage, not signatures or tamper-proof logs.
Concurrent appends collide safely on the next filename; rerun after reviewing
the winning decision. Keep the original normalized evidence separately; history
stores references, not raw copies, and does not continually re-open that evidence.

Retests compare selected request/observation context, tool settings and selectors.
Different request URL/body hashes, identity/object labels, source locations or
analysis settings produce `not-comparable`, retaining the requested outcome.
Uncaptured/unparsed HTTP responses cannot establish a comparable negative retest.
The original and all later decisions remain visible. A compatible profile still
does not prove equal server state or independent identity. Conclusions remain
analyst assertions. Empty scans never automatically close a candidate.

`compare` also exposes `metadataChanged` records, including reported severity and
explanation changes, separately from unchanged fingerprints. Changed profiles
carry `comparisonSuitability: not-comparable`; absence still does not prove a fix.

## Coverage of access cases and scenario steps

```sh
python -m whitehat api coverage examples/api/before.json --project owned-api --evidence .whitehat-bounty-demo/results/vulnerable.json --matrix examples/bounty/access-matrix.json --json
```

Repeat `--evidence` for up to 20 HTTP evidence documents. Add `--scenario PLAN.json`
for explicit scenario plans (also repeatable). Coverage separately lists route
observation, access cases with identity/object labels and evidence hashes, and
scenario steps/transitions. A route seen only as 401 does not cover another
identity's access expectation. Stopped scenarios leave later steps and transitions
untested; conflicting receipts remain conflicting. Scenario plan hashes must
match supplied receipts. These are supplied-evidence checks, not a completeness
guarantee about the application or a new assertion/execution engine.
Coverage also checks the current prepared request URL/body hashes and context;
receipts from changed request files appear in `notComparableResults` and do not
cover the changed plan's steps.
