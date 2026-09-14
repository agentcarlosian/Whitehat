# Approved HTTP replay and explicit scenarios

`http replay` is a distinct capability from the older `network observe-loopback`
profile. It supports exact prepared requests over HTTPS, plus HTTP to owned
`127.0.0.1`. It never creates legal authority or chooses a target.

## Prepare once, replay within the session

A prepared request records method, full URL, non-credential headers, optional
body, object label, and operation label. Use the structure in
`examples/http/request.example.json`. Authentication and cookies belong in
session credential references, not request headers.

```sh
python -m whitehat http preview PATH_TO_REQUEST.json --json
```

The preview validates the request and prints its canonical SHA-256 without
sending it. List the reviewed request hashes in a session based on
`examples/http/session.example.json`. Specify the exact origin, current policy
review, start/expiry, controlled identities/objects, response selectors, and
budgets. The checked-in template has approval false and historical times.

The session can contain up to 100 prepared requests and 10 identity profiles.
An approved request can be replayed under a named approved identity without
another prompt. New request content requires a new reviewed session; the ledger
refuses edits to the session that would reset or widen its budget.

Credential references must use environment names beginning
`WHITEHAT_CREDENTIAL_`. A bearer profile reads a token, a cookie profile reads
an explicit Cookie header value, and a `none` profile sends no credential.
Set these variables in your own shell/credential workflow. Whitehat never prints
their values, follows ambient cookies, or performs login or token refresh.

```sh
python -m whitehat http replay REQUEST.json --session SESSION.json --identity alice --state WORKSPACE/replay.sqlite3 --output WORKSPACE/results/alice.json
python -m whitehat http replay REQUEST.json --session SESSION.json --identity bob --state WORKSPACE/replay.sqlite3 --output WORKSPACE/results/bob.json
python -m whitehat http compare WORKSPACE/results/alice.json WORKSPACE/results/bob.json
python -m whitehat http stop SESSION.json --state WORKSPACE/replay.sqlite3
```

## Transport and budget behavior

- An exact origin and canonical request hash must match before reservation.
- Only approved identities are used. POST/PUT/PATCH/DELETE additionally require
  `allowMutation: true`; method choice alone does not establish absence of effects.
- Only HTTP/1.1 with ordinary ASCII paths is implemented. Encoded path segments,
  ambiguous paths, raw framing headers, CONNECT, and TRACE are refused.
- HTTPS resolves once in a time-bounded child, rejects non-public/transition
  addresses, connects to the selected numeric address, and verifies TLS using
  the original hostname and default trusted CAs. Exact owned loopback is separate.
- There are no proxy, redirect, retry, automatic-cookie, certificate-bypass,
  browser, or arbitrary-command options.
- Requests are reserved atomically before transport. Failed attempts are consumed.
  One request may be in flight. A crash can leave a reservation requiring review.
- Maximums are 100 requests/session, eight hours/session, ten seconds/request,
  64 KiB request body and 1 MiB response body. Compression is rejected.
- A deadline closes the socket, including during headers/body receipt. Rate
  limits, redirects, transport failures and rejected evidence stop the session.
- `stop` blocks subsequent requests; an already in-flight request remains bounded
  by its deadline. Do not clear a ledger to work around an exhausted session.

## Explicit stateful expectations

`http scenario SCENARIO.json --session SESSION.json --state LEDGER --output RESULT`
executes 1-20 pre-reviewed requests in order. A scenario has schemaVersion
`whitehat-http-scenario-v1`, a matching projectId, and steps with:

```json
{
  "id": "read-created-object",
  "request": "requests/read.json",
  "identityId": "alice",
  "expect": {"status": 200, "values": {"/marker": "owned-item"}, "absent": []}
}
```

Request paths are relative to the scenario and contained there. All request
hashes, origins, identities, mutation permissions and evidence selectors are
checked before starting. An expectation mismatch records evidence and stops the
session. This profile uses literal prepared requests; dynamic extraction and
substitution of newly generated IDs during execution is not implemented.
The separate [staged binding workflow](bounty-workflow.md) prepares new concrete
requests offline from selected evidence for a subsequent reviewed session.

## Verification limits

The corpus verifies real owned HTTP and HTTPS exchanges, untrusted certificates,
original TLS hostname versus a pinned connection address, revoked identities,
access controls, redirect/rate-limit stops, budget reuse, and lifecycle twins.
DNS routing in the hostname-pinning test is mocked to the owned TLS server.
No third-party endpoint or real credential was tested during implementation.
