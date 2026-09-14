# Session-scoped network boundary

## Purpose

This document defines the boundary an external network engine must satisfy. The
owned-loopback proof in Decision 0004 implements only exact IPv4 loopback and is
not evidence that any external target is authorized. Session inspection remains
local-only:

```powershell
python -B -m whitehat session validate .\examples\network-session.synthetic.json --evaluation-time 2026-09-11T01:30:00Z --json
```

The checked-in example uses reserved `.invalid` hosts and an historical
evaluation clock. It cannot produce network execution readiness.

## Implemented owned-loopback proof

`whitehat network observe-loopback` accepts only an active `owned-loopback`
contract with exact host `127.0.0.1`, HTTP, `GET`, and a matching path prefix. It
reserves each attempt in a local SQLite ledger before opening the socket, uses a
direct standard-library connection, never follows a redirect, sends no body or
credentials, reads at most the approved response limit plus one discriminator
byte, and never retains response content.

Request count, concurrency, delay, per-request timeout, response bytes, session
wall time, expiry, policy coverage, stop state, and restart state are enforced.
HTTP 429 and 3xx responses stop the session. Timeouts, connection failures, and
partial reads consume their reservation and are not retried automatically.

`whitehat network stop` applies the monotonic `user-stop` state. The loopback
result can use optional local storage and review like other supported results.

## Boundary components

```text
current human-reviewed policy
  + exact session grant
  + exact typed capability
  + current UTC clock
  + mutable local consumption ledger
  -> request reservation
  -> resolve exact host once and pin an allowed public address
  -> verified TLS request within exact method/path/byte/time limits
  -> bounded observation and ledger completion
```

Any failed intersection stops before a request. Agents and scanner output may
propose a capability plan but cannot create, approve, renew, or widen the session.

## Immutable session grant

`whitehat-network-session-v1` binds:

- one session ID and mode;
- validity start and expiry, with an eight-hour maximum;
- a clean HTTPS policy URL, review time, policy expiry, approver assertion, and
  approval time;
- the exact capability allowlist, initially only `http.observe`;
- one to sixteen exact lowercase HTTPS origins, explicit ports, normalized path
  prefixes, and unique `GET`/`HEAD` methods;
- maximum requests, concurrency, request/response bytes, request timeout, wall
  time, and minimum inter-request delay;
- redirects disabled, proxy environment disabled, TLS verification required,
  and resolve-public-once address pinning;
- false credentials, target mutation, third-party data, contact, and submission;
- mandatory user-stop, expiry, policy, scope, budget, rate-limit, redirect, and
  address stop conditions.

The complete canonical document SHA-256 is the session identity. Changing any
field creates a different session and requires a new review.

## Mutable consumption ledger

A future engine should use a local SQLite ledger outside tracked source. The
ledger is state, not authority. It must bind the session hash and atomically
record:

- request sequence and capability;
- exact target origin, path, and method;
- reservation, start, completion, failure, and cancellation state;
- total reserved/completed requests and bytes;
- active concurrency and last-request time;
- remaining wall time and expiry observation;
- global user stop and terminal stop reason.

Reservation occurs before DNS or socket creation. A crash leaves an attributable
reservation that is reconciled conservatively; it is never silently retried.
Restart must revalidate session hash, policy coverage, current time, target scope,
remaining budgets, delay, and stop state before continuing.

## Transport intersection

The future engine must:

1. Ignore ambient proxy variables and application proxy configuration.
2. Resolve the exact host immediately before the request.
3. Reject loopback, private, link-local, multicast, unspecified, and otherwise
   disallowed addresses for external-program mode.
4. Pin one accepted address for DNS connection and verified TLS while preserving
   the exact hostname for certificate validation and HTTP authority.
5. Reject redirects rather than following them.
6. Send only the exact capability-owned method, path, headers, and empty body.
7. Bound request bytes, response bytes, connection/read time, aggregate wall time,
   request count, concurrency, and delay.
8. Return content only when a later capability explicitly defines a reviewed
   retention boundary; the initial observation design should prefer metadata and
   hashes.

## Stop and recovery

The engine stops before further network activity on user stop, expiry, policy
expiry, scope mismatch, budget exhaustion, rate limiting, an unexpected redirect,
an unexpected resolved address, TLS failure, ledger inconsistency, or cleanup
failure. Stop is monotonic unless a human issues a new session contract.

No automatic retry follows a timeout, ambiguous response, partial read, or
process crash. A human may create a new explicit capability plan within remaining
session budget after reviewing the prior ledger event.

## Separation from offline work

These surfaces remain available without a session:

- `whitehat analyze inventory`
- `whitehat analyze diff`
- `whitehat analyze dependencies`
- `whitehat review`
- `whitehat run synthetic`
- `whitehat scan ruff`

They must not discover or implicitly load a session file. Adding a network engine
must not change their defaults or failure modes.

## Future implementation gate

An external network engine is not ready until tests prove real-clock enforcement, atomic
reservation, restart behavior, user stop, exact origin/path/method matching,
public-address filtering and pinning, TLS hostname verification, proxy removal,
redirect refusal, request/response/time budgets, 429 stopping, no retry, bounded
output, and negative controls showing that offline commands remain independent.
