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
- No network, credential, browser, arbitrary-command, account, target-mutation,
  destructive, payment, contact, disclosure, or submission capability exists.
- The project is licensed under Apache-2.0. Publication remains blocked until the
  exact tree completes its release review.
