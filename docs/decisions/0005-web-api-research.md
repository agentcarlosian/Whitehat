# Decision 0005: web/API evidence and session replay

Date: 2026-09-14. Status: implementation design under the owner's approved sequence.

Whitehat will preserve HTTP observations independently from optional execution.
Imported captures are untrusted data. Project, method, exact origin/path, query
parameter names, identity label, object label and operation identify a comparison.
Evidence hashes change when the observation changes; identity does not include
volatile response values or scanner severity.

Replay requires a versioned session with explicit start/expiry, reviewed policy
assertion, exact origin, prepared-request hashes, identity credential references,
response-selection rules, and numeric budgets. No per-request human prompt is
needed inside that exact session. The session is an operator record, not legal
proof. Credentials are read only from explicitly named environment variables and
never copied to receipts, reports, or prepared requests.

HTTP is permitted only to exact owned IPv4 loopback. External transport is HTTPS
with certificate verification, one bounded DNS resolution, public-address checks,
and connection to a selected numeric address while retaining the original TLS
hostname. Redirects, proxies, retries, ambient cookies, and automatic login are
not supported. Request bytes and selected identity are checked before a request
reservation; reservations survive failures/restarts. A socket deadline and byte
limits bound transfers. Rate limits and redirects stop the session.

The first automated Schemathesis profile runs only against the owned mini-API;
it does not dispatch an arbitrary scanner at an external target. Its request
history is normalized and assessed through the same evidence interface. External
replay and generated multi-step testing are different execution profiles.

An access-matrix mismatch is a review candidate. A 200 status or schema failure
alone does not prove unauthorized access. Denial, shared-object, and revoked
identity controls accompany the positive fixture. Response values are retained
only at explicitly selected nonsensitive scalar JSON pointers; all other values,
credentials, headers and raw bodies are omitted from exported evidence.
