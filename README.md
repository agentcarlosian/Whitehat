# Whitehat

Whitehat is a local-first toolkit for independent, authorized security research.
It aims to make routine local analysis easy while keeping side-effecting work at
an explicit boundary.

This repository currently provides one small, dependency-free Python CLI:

- `whitehat doctor` reports the implemented capability boundary.
- `whitehat analyze diff` compares two operator-controlled directories without
  executing their contents or returning file contents.

Local read-only and offline analysis does not require an approval file. Network
actions, credentials, target changes, external contact, and report submission are
not implemented in this alpha.

## Quick start

Requires Python 3.11 or newer.

```powershell
python -B -m whitehat doctor --json
python -B -m whitehat analyze diff .\examples\before .\examples\after --json
python -B scripts\validate.py
```

See [docs/quickstart.md](docs/quickstart.md) for the shortest operator path and
[docs/plan.md](docs/plan.md) for the current build order.

## License

Whitehat is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

## Project status

This is a disconnected local staging repository. It has no configured remote.
Publication review and final release checks remain open.
