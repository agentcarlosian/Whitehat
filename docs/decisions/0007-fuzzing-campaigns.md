# Decision 0007: concrete fuzz batches and evidence oracles

Date: 2026-09-15. Status: accepted for the owner's requested stages 1-5.

Generation prepares concrete requests and sequences before execution. A batch
has a fixed project, seed, input hashes, selected mutable fields and bounded
cases. Session drafts remain unapproved. Execution preflights the whole batch
against the existing exact-request session, then uses the same persistent replay
ledger for setup, mutations, readback and reset. Credential references stay in
the session; generation never discovers or reads their values.

The first profile generates independent single-field mutations or finite-state
sequences of literal prepared requests. No arbitrary expressions, dynamic URLs,
automatic login, adaptive live input generation, concurrency or broad discovery.
Tests that create state must explicitly declare setup/reset requests and reset
expectations. Cleanup runs after a test expectation fails when the session still
permits requests; transport/stop/budget failures cannot be overridden to clean up.
Incomplete cleanup is reported and stops the batch, never silently retried.

Relational assertions compare selected scalar evidence with explicit object and
identity bindings. Missing/unparsed/cross-object evidence is inconclusive. A
status/schema discrepancy is a lead, not a validated vulnerability. Results reuse
the existing HTTP evidence, research-result and packet contracts.

Reduction generates a finite reviewed candidate batch. The minimizer selects the
smallest actually reproduced same-failure candidate, preserving original input,
seed, engine/configuration, evidence hashes and limitations. It never claims a
global minimum, and corpus regression never equates absence with a fix.

GraphQL parsing and inventory are offline. Only bounded query/mutation documents
are interpreted; no resolvers or introspection requests run implicitly. Atheris
is optional and executes reviewed fixed in-package targets in a bounded child.
The adapter does not import caller Python or claim to sandbox hostile code; new
source targets need an explicitly reviewed adapter. Linux is the initial native
execution platform. Output artifacts and normalized receipts are bounded.
