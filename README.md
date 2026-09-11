# Whitehat

Whitehat is a local-first toolkit for independent, authorized security research.
It aims to make routine local analysis easy while keeping side-effecting work at
an explicit boundary.

This repository currently provides one small, dependency-free Python CLI:

- `whitehat doctor` reports the implemented capability boundary.
- `whitehat analyze inventory` creates a bounded, content-free local file manifest.
- `whitehat analyze diff` compares two operator-controlled directories without
  executing their contents or returning file contents.
- `whitehat analyze dependencies` compares Python project declarations or npm
  lockfiles without resolving or downloading packages.
- Any analysis can persist its exact JSON with `--output FILE`; output is
  optional and never overwritten.
- `whitehat review` writes a bounded, hash-linked local note for a saved result.
- `whitehat run synthetic` executes one fixed local child with bounded input,
  output, time, environment, and disposable workspace cleanup.

Local read-only and offline analysis does not require an approval file. Network
actions, credentials, target changes, external contact, and report submission are
not implemented in this alpha.

## Quick start

Requires Python 3.11 or newer.

```powershell
python -B -m whitehat doctor --json
python -B -m whitehat analyze inventory .\examples\before --json
python -B -m whitehat analyze diff .\examples\before .\examples\after --json
python -B -m whitehat analyze dependencies .\examples\dependencies\before\pyproject.toml .\examples\dependencies\after\pyproject.toml --json
python -B -m whitehat run synthetic --message "owned fixture" --json
python -B scripts\validate.py
```

See [docs/quickstart.md](docs/quickstart.md) for the shortest operator path and
[docs/plan.md](docs/plan.md) for the current build order.

## License

Whitehat is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

## Project status

The canonical repository is currently private. Making it public remains a
separate owner decision after publication review and final release checks.
