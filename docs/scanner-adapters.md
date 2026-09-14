# Reviewed scanner adapters

Updated: 2026-09-11

## Adapter policy

Scanner adapters are added one at a time. Each adapter fixes the tool identity,
arguments, input boundary, resource limits, output parser, claim limits, and
owned positive/negative fixtures before it is described as implemented. A
scanner observation is not a vulnerability finding.

## Ruff adapter version 1

- Tool: Ruff `0.14.14`
- Upstream: `https://github.com/astral-sh/ruff`
- Linter documentation: `https://docs.astral.sh/ruff/linter/`
- Configuration documentation: `https://docs.astral.sh/ruff/configuration/`
- Tool license: upstream MIT license; Ruff is installed separately and is not
  vendored or redistributed in this repository.
- Whitehat installation extra: `python -m pip install ".[scanner-ruff]"`

The adapter loads the Ruff distribution installed beside Whitehat's current
Python interpreter, requires version `0.14.14`, and hashes its installed
`RECORD`. It then runs a separate bounded `python -I -m ruff --version` check and
requires the exact text `ruff 0.14.14`. The Python executable SHA-256 from that
check must match the scan process.

The scan command is fixed by Whitehat:

```text
python -I -m ruff check --isolated --no-cache --output-format json --no-fix --no-preview
  --select E4,E7,E9,F --target-version py311 <disposable-source-copy>
```

The caller cannot supply a Python environment, executable, command, rule
selector, configuration, fix switch, preview switch, target version, or
additional argument. Ambient `PATH` cannot substitute a different Ruff binary.

### Input boundary

- One explicit local directory.
- Only `.py` and `.pyi` regular files are copied.
- `.git`, `.venv`, `venv`, and `__pycache__` directories are excluded.
- Links and unsupported entries are rejected.
- Entries, source files, per-file bytes, aggregate bytes, wall time, retained
  stdout/stderr, and normalized observations are bounded before execution.
- The copied source is deleted with the runner workspace after every outcome.

### Output boundary

Ruff exit `0` is a clean result and exit `1` means lint observations. Exit `2`
or any other status is an adapter failure. Raw JSON and stderr are not returned.
Normalized observations retain only rule code, relative path, row/column range,
and whether Ruff offered a fix. Messages, documentation URLs, edit content,
source snippets, absolute paths, and registry data are omitted.

The result keeps finding validity, impact, severity, and submission authorization
false. It states that source was copied but not executed, a fixed process was
created, network and arbitrary commands were false, and the workspace was
cleaned.

### Verification fixtures

- `examples/scanner/problem/problem.py` deterministically produces `F401` and
  `F841` observations.
- `examples/scanner/clean/clean.py` produces no observations.
- Adversarial tests reject path escape, duplicate observations, wrong tool
  identity, source limits, and source links.
