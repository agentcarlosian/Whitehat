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

To exercise optional persistence, create an ignored `tmp` directory and choose
new filenames:

```powershell
New-Item -ItemType Directory .\tmp -Force
python -B -m whitehat analyze inventory .\examples\before --output .\tmp\inventory.json --json
python -B -m whitehat review .\tmp\inventory.json --decision accepted --note "Local record reviewed." --output .\tmp\inventory.review.json --json
```

The fixed synthetic-process proof is:

```powershell
python -B -m whitehat run synthetic --message "owned fixture" --repeat 2 --json
```

The optional scanner proof uses an owned dirty/clean pair:

```powershell
python -m pip install ".[scanner-ruff]"
python -B -m whitehat scan ruff .\examples\scanner\problem --json
python -B -m whitehat scan ruff .\examples\scanner\clean --json
```

The future-network boundary is validated separately and locally:

```powershell
python -B -m whitehat session validate .\examples\network-session.synthetic.json --evaluation-time 2026-09-11T01:30:00Z --json
```

The release audit is intentionally separate and requires a clean commit:

```powershell
python -m pip install ".[release]"
python -B -m whitehat release audit --json
```

Owned-loopback execution is covered by the automated temporary-server tests. The
checked-in loopback session is an expired template and should not be treated as a
standing runnable grant.
