# Primary CLI smoke example

From the repository root, compare the owned synthetic directories:

```powershell
python -B -m whitehat analyze diff .\examples\before .\examples\after --json
```

Expected summary:

```json
{"added": 1, "deleted": 0, "modified": 1, "unchanged": 1}
```

The command is local and read-only. It creates no artifact and requires no
cleanup.

The complete local-analysis smoke path also includes:

```powershell
python -B -m whitehat analyze inventory .\examples\before --json
python -B -m whitehat analyze dependencies .\examples\dependencies\before\pyproject.toml .\examples\dependencies\after\pyproject.toml --json
```
