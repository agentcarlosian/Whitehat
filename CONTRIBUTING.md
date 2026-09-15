# Contributing to Whitehat

Whitehat serves independent security researchers. Contributions should make a
specific investigation easier to perform, understand, or reproduce.

## Development setup

Create a virtual environment with `python -m venv .venv`. Activate it with
`.venv/Scripts/Activate.ps1` in PowerShell or `source .venv/bin/activate` in Bash.
Then run:

```sh
python -m pip install ".[scanner-ruff,release,api,api-test,test-tls,fuzz,graphql]"
python scripts/setup_tools.py --destination .whitehat/tools
python -B scripts/validate.py
python -B scripts/evaluate_research.py
python -B scripts/evaluate_web.py
python -B scripts/evaluate_fuzz.py
```

Core runtime dependencies remain empty. Native engines are installed separately.
Formatting and basic lint: `python -m ruff check whitehat tests scripts --select E4,E7,E9,F`.
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

CI validates supported platforms and an installed package. Publishing a tag,
package, or public repository is a separate maintainer decision.
