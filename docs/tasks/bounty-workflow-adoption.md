# Bounty workflow adoption

Requested 2026-09-14: implement research priorities 1, 2, 3, and 5.
Owner: Whitehat. Branch: `codex/bounty-workflow-adoption`. Merge target: `main`.
Base: `c04fb29653581a78febad810990fb0d19aeccf97` (PR #2 merged).

## Acceptance and sequence

1. Capture compatibility and preparation: preserve failed/missing HAR exchanges
   as explicit incomplete diagnostics; reject malformed inputs. Generate a
   prepared request, credential-reference requirements, and unapproved session
   draft from an explicitly selected source capture. No credential values in
   diagnostics. No network, ambient credential reads, or session-ledger writes.
2. Evidence-linked packets: versioned manifest, selected existing normalized
   evidence with pinned hashes, steps/prerequisites/expected/actual/impact/limits,
   typed HTTP/comparison/assessment renderers, and informational readiness checks.
   Drafts remain exportable; missing or altered evidence is never embedded as
   verified. Contain all linked paths beneath the manifest directory.
3. Staged ID binding: take one explicitly selected scalar from verified HTTP
   evidence and fill one declared ordinary path segment in a prepared request.
   Produce concrete new requests and binding receipts for subsequent review;
   never widen an existing execution session or introduce live substitution.
5. Candidate triage/retest/coverage: per-candidate hash-linked decision history,
   explicit observation links, retest outcomes and comparison suitability;
   expose severity/description changes; report identity/object access cases and
   completed/missing scenario steps separately from route observation.

Primary surface remains `python -m whitehat`; no new runtime dependencies.
Priority 4 relational assertions and priority 6 Burp/GraphQL are not selected.
Validation uses newly authored owned fixtures only. No third-party testing,
credentials, contact, publication, submission, or automatic merge is authorized.

## Progress

- [x] Inspect current contracts and clean merged base; create branch.
- [x] Capture compatibility/preparation and targeted rejecting controls.
- [x] Packets and typed evidence renderers.
- [x] Staged binding and provenance.
- [x] Candidate histories, comparison changes, and coverage.
- [x] End-to-end CLI examples, docs, full validation, release audit and draft PR.

Review: [PR #3](https://github.com/agentcarlosian/Whitehat/pull/3). Its required
platform checks and release-audit results are the current remote verification
record; this document records implementation and local evidence.

Closure: selected workflows work through CLI and installed package, meaningful
positive/negative fixtures pass, and a reviewable PR has completed checks.

## Verification checkpoint

- Final Windows/Python 3.13.12 validation: 133 tests, two existing symlink
  privilege skips; syntax and golden paths pass. Ruff correctness checks pass.

- 22 focused workflow tests pass, including a real owned scenario that stops
  after its second request; packet output retains planned/executed counts and
  coverage leaves the final step untested. Changed prepared request files are
  explicitly not comparable with old scenario receipts.
- Concurrent candidate appends preserve one complete winning record and reject
  the collision without overwrite. Changed request hashes, response selectors,
  missing bodies, and different identities cannot establish comparable retests.
- Owned CLI and isolated installed-package walkthroughs pass, producing a
  prepared request, bound request, complete draft, two decisions and access cases.
- Native source/secret evaluation and existing web/lifecycle evaluation pass.
  The native evaluation's expected comparison shape was updated for the new
  metadataChanged count; the original detection outcomes remain identical.
- No new runtime dependency, external target, real credential or publication.
- Clean audit at `23b7da4` passed: 132 tracked files, 35 release inputs, zero
  configured secret-pattern matches, canonical Apache-2.0, a 43-file sdist,
  a 34-file wheel and installed `0.11.0a1` diagnostics.
- Initial macOS CI exposed the `/var` versus `/private/var` temporary-directory
  alias: resolving only the manifest root rejected contained evidence. Packet
  creation now compares lexical paths before resolving the common root and
  checking descendants for links/escapes. Existing packet tests reproduce the
  failure on macOS and verify the correction in the PR matrix.
