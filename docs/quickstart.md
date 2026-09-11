# Quickstart

This is the shortest verified path through the Whitehat CLI on Windows, Linux, or
macOS with Python 3.11 or newer. No credentials, environment variables, services,
or external accounts are required.

From the repository root:

```powershell
python -B -m whitehat doctor --json
python -B -m whitehat analyze inventory .\examples\before --json
python -B -m whitehat analyze diff .\examples\before .\examples\after --json
python -B -m whitehat analyze dependencies .\examples\dependencies\before\pyproject.toml .\examples\dependencies\after\pyproject.toml --json
python -B scripts\validate.py
```

Inventory should report two files and 31 bytes. The directory comparison should
report one added path, one modified path, no deleted paths, and one unchanged
file. Dependency comparison should report one added, one removed, one changed,
and one unchanged declaration. Validation should finish with an `ok: true` JSON
result.

If Python cannot import `whitehat`, confirm that the command is running from the
repository root. Use `python --version` to confirm Python 3.11 or newer.
