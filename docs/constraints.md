# Current constraints

- Python 3.11 or newer is required.
- The runtime uses only the Python standard library.
- Only local `doctor`, file inventory, directory comparison, and dependency
  manifest comparison are implemented.
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
- Ruff `0.14.14` is the only scanner adapter. It is an optional external tool,
  not a runtime dependency or vendored component. The adapter verifies version
  text and executable hash but does not independently prove tool provenance or
  operating-system network isolation.
- Scanner output is static-analysis metadata. A rule match, clean result, exit
  code, or fix suggestion does not establish reachability, exploitability,
  finding validity, impact, severity, eligibility, or authorization.
- No network, credential, browser, arbitrary-command, account, target-mutation,
  destructive, payment, contact, disclosure, or submission capability exists.
- The project is licensed under Apache-2.0. Publication remains blocked until the
  exact tree completes its release review.
