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
- Network-session validation and owned IPv4 loopback execution are implemented.
  External network execution is not. A contract, approver assertion, policy URL,
  and validation result do not establish legal authority.
- The initial design is HTTPS observation-only with GET/HEAD and all credential,
  mutation, third-party-data, contact, and submission effects false. Broader
  network behavior requires a separate design and implementation review.
- The implemented transport is HTTP GET to exact `127.0.0.1` only. It does not
  prove external HTTPS, DNS/public-address filtering, TLS, IPv6 loopback,
  authenticated requests, mutating methods, or operating-system network isolation.
- The SQLite ledger is local coordination state, not authority or tamper-proof
  evidence. An abrupt process crash can leave a conservative active reservation
  that requires operator review rather than automatic retry.
- The release audit is a bounded technical check, not legal advice or an
  originality, trademark, maintenance, publication, or distribution decision.
- Secret scanning uses explicit high-confidence patterns and cannot prove that a
  tree contains no sensitive data. Human review remains required before public
  visibility.
- No external-target network, credential, browser, arbitrary-command, account, target-mutation,
  destructive, payment, contact, disclosure, or submission capability exists.
- The project is licensed under Apache-2.0. Publication remains blocked until the
  exact tree completes its release review.
