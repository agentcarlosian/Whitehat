# Web/API workflow implementation

Owner: Whitehat. Branch: `codex/web-api-workflows`. Merge target: `main`.
Requested 2026-09-14: implement the researched sequence, emphasizing web/API bounty work.

## Ordered acceptance

1. Preserve HTTP method/input location in scanner imports. Introduce project-bound
   HTTP observation identities separate from evidence hashes; keep v1 files readable.
2. Import HAR and explicit request/response records. Compare JSON structure and
   selected scalar evidence; assess an explicit identity/object/access matrix.
3. Replay exact prepared requests under an unexpired session, researcher-controlled
   identity profiles, atomic request/concurrency ledger, and bounded HTTP(S).
4. Inventory prepared OpenAPI operations/security and compare schemas using pinned
   oasdiff. No implicit external references or schema-driven target acquisition.
5. Integrate pinned Schemathesis with an owned API evaluation profile, plus reusable
   stateful expectations and report import. Verify actual engine behavior.
6. Maintain an owned API corpus with vulnerable/fixed/shared/revoked controls,
   readable evidence output, documentation, installation, and release/CI validation.

## Scope

Implementation is authorized by the user's request. Execution verification uses
only owned fixtures and generated canary credentials. No third-party target,
credential, live program interaction, contact, or submission is authorized.
The approved replay design is recorded in decision 0005 before implementation.
External HTTPS transport must remain distinct from its mocked/TLS fixture proof.

## Progress

- [x] Confirm clean base `47befa7`; create the implementation branch.
- [x] HTTP evidence and identity repair.
- [x] Imports, semantic comparison, authorization matrix.
- [x] Session-bound replay and owned API controls.
- [x] OpenAPI inventory and pinned oasdiff.
- [x] Schemathesis and stateful evaluation.
- [x] Full tests, installed package, release audit, CI, and reviewable PR.

PR #2 merged at `c04fb29653581a78febad810990fb0d19aeccf97`.
Post-merge run `34836887970` passed Windows 3.11/3.13, Ubuntu 3.11/3.13,
macOS 3.13 and release audit. This task is complete.

## Verification checkpoint

- Windows/Python 3.13.12: full validation passes, 111 tests with two existing
  symlink-privilege skips; syntax, golden paths, and Ruff correctness checks pass.
- HTTP corpus: one mismatch in the vulnerable capture, none in the fixed capture;
  shared-object and revoked-session controls pass. Method identity and request
  value/evidence hash separation have regression coverage.
- Actual owned HTTP/TLS: credentials, denied/revoked cases, certificate trust,
  original TLS hostname versus a pinned connection address, request hash rejection,
  ledger binding/budget exhaustion, redirect/rate-limit stops, and lifecycle twins pass.
- oasdiff 1.32.0 finds the response property change; Whitehat independently catches
  the inherited-authentication override. External refs are rejected.
- Schemathesis 4.27.1 runs its stateful phase in an isolated child against the
  nonce-bound owned fixture. The explicit lifecycle scenario detects the broken
  deletion regardless of generated coverage. Fixed and broken evaluations pass.
- Isolated installed CLI preview and API inventory pass for 0.10.0a1.
- Technical release audit passed at `24c7b88`: 121 tracked files, 31 literal
  release inputs, zero high-confidence secret-pattern matches, a 39-file sdist,
  a 30-file wheel, and clean installed session-bound replay diagnostics.
- No third-party targets or real credentials were used. DNS is mocked in the
  owned TLS hostname/pinning test. External generated testing and dynamic ID
  substitution remain outside the implemented profiles.
