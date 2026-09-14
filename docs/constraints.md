# Current constraints

- Python 3.11 or newer is required.
- The runtime uses only the Python standard library.
- Implemented research surfaces include source/dependency comparison, report
  imports, Opengrep and Betterleaks adapters, baseline comparison, portable
  workspaces, structured case notes, linked reviews, and Markdown export.
- Directory comparison is intended for stable, operator-controlled inputs. It is
  not an atomic filesystem snapshot and is not a sandbox for hostile filesystems.
- Symbolic links and non-regular entries are rejected rather than followed.
- Output contains relative paths, sizes, and hashes. Those values can still be
  sensitive and should not be published without review.
- Dependency comparison returns declared Python requirement strings or selected
  npm lock metadata. It omits npm registry URLs but cannot determine whether a
  dependency declaration itself contains sensitive data.
- Optional result and review files are ordinary local JSON, not immutable
  storage, signatures, authenticated identities, or independent execution proof.
- Analysis output storage is capped at 64 MiB, requires an existing parent
  directory, and refuses overwrite. Review notes are capped at 4,000 characters.
- The synthetic runner starts only the checked-in fixed Python child. It limits
  retained input/output and wall time, but it is not an OS CPU/memory sandbox and
  does not claim containment for arbitrary or hostile executables.
- Timeout and overflow kill the fixed child. Descendant-process containment is
  not claimed; the fixed child installs an audit hook denying process and socket
  APIs, and no arbitrary-child profile exists.
- Opengrep core `1.30.0` and Betterleaks `1.8.1` are optional research tools;
  Ruff `0.14.14` remains a correctness adapter. Tool setup downloads literal pinned
  assets only when explicitly invoked. Native engines and their companions are
  hash checked; this is not independent provenance or OS network isolation.
- Opengrep supports `.py` and `.js` with five authored syntactic sink rules;
  it does not prove taint flow or authorization. Betterleaks scans the documented
  text suffixes, with live validation and archive/encoding recursion disabled.
- Native scans default to 1,000 files, 1 MiB per file, 16 MiB total input, 1,000
  observations, and 30 seconds of process wall time. Opengrep additionally uses
  one job, a three-second per-rule/file timeout, and a 512 MiB engine memory limit.
- OSV, SARIF, ZAP, Nuclei, and secret-report imports are non-executing format
  adapters, not proof that the upstream scanner completed or a target was tested.
- Scanner output is static-analysis metadata. A rule match, clean result, exit
  code, or fix suggestion does not establish reachability, exploitability,
  finding validity, impact, severity, eligibility, or authorization.
- Replay supports exact prepared HTTP(S) requests under a current session. Plain
  HTTP is limited to owned 127.0.0.1; external HTTPS requires public-address
  checks and normal TLS certificate/hostname verification. The initial profile
  uses ordinary ASCII paths and HTTP/1.1; redirects, proxies, retries, raw framing,
  automatic login, and dynamic identifier substitution are unsupported.
- Credential references are explicit environment names. No credential discovery
  or provider validation exists. Method-based mutation permission does not prove
  that a request is free of side effects; reviewed request hashes remain required.
- Session budgets and a single in-flight request are enforced with a bound SQLite
  ledger. Failed attempts are consumed. Stop blocks subsequent requests. A crash
  can leave an active reservation for operator review; the ledger is not authority.
- Generated Schemathesis testing runs only on the owned mini-API. Its audit hook,
  nonce, connection cap and process deadline are not an OS sandbox. Reusable
  stateful scenarios outside that fixture contain only exact approved requests.
- HTTP evidence omits raw headers/bodies and query values. Explicit scalar
  selectors may retain sensitive values; review selectors and exports. Missing
  captured bodies never prove that a sensitive field was absent.
- The release audit is a bounded technical check, not legal advice or an
  originality, trademark, maintenance, publication, or distribution decision.
- Secret scanning uses explicit high-confidence patterns and cannot prove that a
  tree contains no sensitive data. Human review remains required before public
  visibility.
- Browser control, arbitrary commands, automatic account actions, destructive
  operations, payments, contact, disclosure, and submission are not provided.
- The project is licensed under Apache-2.0. Publication remains blocked until the
  exact tree completes its release review.
