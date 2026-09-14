# Decision 0006: prepared inputs and evidence-linked research

Date: 2026-09-14. Status: accepted for the owner's selected priorities 1/2/3/5.

New preparation, binding, packet, candidate and coverage commands are offline.
Prepared requests contain operator-selected request data and are sensitive input
artifacts. Terminal receipts contain hashes and diagnostics, not raw requests.
Draft sessions always require explicit operator completion and approval. Binding
creates a new concrete request; it cannot modify sessions or consumption ledgers.

HAR status zero/missing responses are incomplete capture records, never HTTP
responses or proof of denial. Preserve their entry index and sanitized context
in import provenance while keeping the v1 successful-exchange schema readable.
Missing captured bodies are not empty captured bodies. Unsupported protocol
extensions are diagnosed rather than silently claimed as supported.

Packets explicitly select normalized evidence beneath their manifest directory,
pin result hashes and render supported typed fields. Hashes establish integrity
relative to the manifest, not independent truth or authenticated identity. Missing
content is a readiness issue; draft export remains available. Raw captures,
credentials and arbitrary attachments are not packet input types.

Candidate IDs are researcher assigned and separate from scanner fingerprints.
History consists of linked immutable-by-convention files written with exclusive
creation; forks and missing predecessors are errors on history validation. This
does not claim tamper-proof storage. Retest outcomes are analyst assertions with
linked evidence, and never turn a missing observation into an automatic fix.

Coverage distinguishes route observation, access-expectation outcomes and
scenario-step completion. Missing, conflicting or noncomparable evidence remains
visible. No runtime expressions, new network capabilities or automatic finding
adjudication are introduced.
