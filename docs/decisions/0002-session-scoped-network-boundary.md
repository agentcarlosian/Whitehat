# Decision 0002: session-scoped network boundary

Date: 2026-09-11

Status: accepted design; network execution not implemented

## Decision

Future network access will be authorized and budgeted by one short-lived,
human-reviewed session contract rather than a separate approval artifact for
every read-only request. A session binds exact origins, path prefixes, methods,
capabilities, policy timing, transport rules, aggregate budgets, and stop
conditions. It cannot add authority or widen itself.

The first contract is observation-only: exact HTTPS targets, `GET` and `HEAD`, no
redirects or ambient proxies, normal TLS verification, resolve-public-once address
pinning, and false credential, mutation, third-party-data, contact, and submission
effects. Session duration is capped at eight hours.

Session validation remains separate from execution. The current CLI only checks
the local design document and always returns false for legal authority,
implemented network engine, network execution authorization, and execution
performed.

Offline analysis, local records, the synthetic runner, and local scanners never
load or require a network session.

## Consequences

- One human approval may cover a bounded research session without per-request
  approval churn.
- A future engine must atomically reserve each request from a local consumption
  ledger bound to the immutable session hash.
- The engine must use its real UTC clock; the validator's `--evaluation-time`
  option is only for offline design tests and historical inspection.
- Network capability implementation requires a separate reviewed change. This
  decision and a valid contract do not enable a socket.
- Credentials, mutating methods, authenticated sessions, uploads, target state
  changes, payments, contact, disclosure, and submission remain outside this
  initial boundary.
