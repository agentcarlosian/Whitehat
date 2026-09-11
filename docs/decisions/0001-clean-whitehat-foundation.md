# Decision 0001: clean Whitehat foundation

Date: 2026-09-11

Status: accepted

## Decision

Whitehat begins as one independent repository, Python package, CLI, test suite,
and release line. Its first commit contains only newly authored product material
and owned synthetic fixtures.

The codebase separates local analysis from side effects. Offline, read-only work
is directly available. Capabilities that use a network, credentials, external
accounts, target mutation, destructive operations, payments, contact, disclosure,
or submission require a later explicit design and are absent from the initial
runtime.

## Consequences

- There is no compatibility requirement with an earlier command, schema, name,
  or repository layout.
- Product structure is allowed to evolve through small working slices rather than
  a milestone gate for every change.
- Publication is blocked until the owner selects a license and approves the exact
  repository state.
