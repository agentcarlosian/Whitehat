# HTTP evidence and authorization expectations

`whitehat-http-evidence-v1` separates stable observation identity from current
content identity. The context binds project, method, exact endpoint, parameter
names, identity label, object label, and operation label. Response changes alter
the evidence hash without changing that context identity. Different projects,
methods, identities and objects remain distinct.

Query values, raw headers and raw bodies are omitted. URL/body hashes retain
input correlation; hashes and path/parameter names may still be sensitive.
Request JSON structure and parameter names are retained without values.
Response JSON structure is retained; scalar values are retained only at explicit
`--select` pointers. Credential-named pointers and whole objects/arrays are
refused. Known replay-session credentials reflected in selected values cause
rejection and a session stop. Review selected fields before sharing evidence.

Missing capture bodies are distinct from empty bodies. A selected JSON proof
requires a captured, parsed body; omitted data never becomes proof of absence.
Comparison reports status, structural changes, selected-value changes, both
contexts, and explicitly ignored volatile pointers. It does not decide whether
access is authorized.

An access matrix has schemaVersion `whitehat-access-matrix-v1`, projectId, and
rows with id, identityId, objectId, operationId, method, endpoint, expect
(`allow`/`deny`), and proof (`pointer` plus exact owned marker `equals`). See
`examples/http/access-matrix.json`.

Rows are consistent, mismatched, inconclusive, or not-tested. A denied response
that still contains the forbidden marker is a mismatch. A 200 with no selected
proof is inconclusive. All mismatches remain review observations. Identity and
ownership labels are operator assertions, not authenticated proof supplied by
Whitehat.

Existing `whitehat-research-result-v1` files remain readable. The ZAP adapter now
preserves HTTP method and parameter context so GET/POST instances do not collapse.
Older source/advisory fingerprints remain version-1 behavior; the new stable
HTTP identity model does not silently rewrite old research histories.
