# Current constraints

- Python 3.11 or newer is required.
- The runtime uses only the Python standard library.
- Only local `doctor` and directory comparison are implemented.
- Directory comparison is intended for stable, operator-controlled inputs. It is
  not an atomic filesystem snapshot and is not a sandbox for hostile filesystems.
- Symbolic links and non-regular entries are rejected rather than followed.
- Output contains relative paths, sizes, and hashes. Those values can still be
  sensitive and should not be published without review.
- No network, credential, browser, arbitrary-command, account, target-mutation,
  destructive, payment, contact, disclosure, or submission capability exists.
- The project is licensed under Apache-2.0. Publication remains blocked until the
  exact tree completes its release review.
