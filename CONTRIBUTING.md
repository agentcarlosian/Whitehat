# Contributing to Whitehat

Whitehat serves independent security researchers. Contributions should make a
specific investigation easier to perform, understand, or reproduce.
Participation in the project is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Development setup

Work from a checkout of `main` and create a branch for your change. Create a
virtual environment with `python -m venv .venv`. Activate it with
`.\.venv\Scripts\Activate.ps1` in PowerShell or `. .venv/bin/activate` in a POSIX
shell. Use `python3` if that is your system's Python command.

Install the pinned development extras and run the portable checks:

```sh
python -m pip install ".[scanner-ruff,release,api,api-test,test-tls,fuzz,graphql]"
python -B scripts/validate.py
python -B scripts/evaluate_bounty.py
python -B scripts/evaluate_fuzz.py
```

Core runtime dependencies remain empty. On Windows or Linux x64, also install the
reviewed native engines and run their integration checks:

```sh
python scripts/setup_tools.py --destination .whitehat/tools
python -B scripts/evaluate_research.py
python -B scripts/evaluate_web.py
```

Native setup downloads pinned upstream assets. It is not supported on macOS or
ARM; do not use those platforms to claim native-engine validation. Consult the
[compatibility table](docs/toolkit.md) and report any skipped checks.

Basic lint: `python -I -m ruff check whitehat tests scripts --select E4,E7,E9,F`.
Linux x64/Python 3.12–3.14 contributors can separately install `[source-fuzz]`;
CI performs the required actual Atheris run on Linux/Python 3.13.

## A useful pull request

Explain the research task, changed behavior, supported inputs, limitations, and
completed checks. Include a positive example, a rejecting control, and malformed
or out-of-budget inputs where appropriate. Never include real credentials,
private program material, third-party data, or unreviewed target evidence.

Keep JSON schemas and exit codes compatible, or document a versioned change.
Add new package modules to `release-files.txt`. Update documentation and the
changelog. Authored rules and fixtures use the repository's Apache-2.0 license;
record external tool and ruleset licenses separately.

See [adapter guide](docs/adapter-guide.md) for an implementation recipe and
[starter tasks](docs/starter-tasks.md) for small contribution candidates.

## Release checks

From a clean commit with the release extra installed:

```sh
python -B -m whitehat release audit --json
```

CI validates supported platforms and an installed package. See the
[release record and checklist](docs/release-readiness.md) before preparing a new
release. Publishing a tag or release is a separate maintainer decision; the
current distribution channel is GitHub source only.
