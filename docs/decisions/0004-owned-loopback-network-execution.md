# Decision 0004: owned-loopback network execution

Date: 2026-09-14

Status: accepted and implemented

## Decision

The first network implementation is restricted to an `owned-loopback` session
whose exact host is IPv4 `127.0.0.1`, scheme is HTTP, capability is
`http.observe`, and method is `GET`. It cannot resolve a hostname or connect to an
external address.

Each request is reserved atomically in a session-hash-bound SQLite ledger before
socket creation. The engine enforces real-clock session validity, policy coverage,
exact port and path scope, request count, concurrency, inter-request delay,
request/response bytes, per-request timeout, and aggregate wall time. Requests
are never automatically retried.

The engine does not follow redirects, use proxy configuration, send credentials
or a body, mutate target state, or retain response content. It records bounded
metadata and a body hash only when the complete response fits the session limit.
HTTP 429 and redirect responses apply monotonic session stops.

## Consequences

- `network` is true in diagnostics because a real loopback socket can be opened.
- `loopbackNetworkExecution` is true and `externalNetwork` remains false.
- The static loopback example is an expired template; tests create short-lived
  owned sessions around a temporary loopback server.
- External HTTPS, DNS resolution, public-address filtering, TLS pinning, and
  authenticated or mutating requests remain unimplemented.
- Extending the engine beyond loopback requires a separate owner decision and
  the remaining gates in `docs/network-session-boundary.md`.
