# Whitehat 0.1.0

Whitehat `0.1.0` is the first public source release of the independent
clean-room security research toolkit.

## Highlights

- Review source and dependency changes with bounded, content-conscious results.
- Import and normalize OSV, SARIF, ZAP, Nuclei, Opengrep, Betterleaks, and
  Gitleaks output without treating scanner matches as findings.
- Compare HTTP evidence across explicit identities and objects, assess access
  expectations, and replay only hash-bound requests under a current approved
  session with persistent budgets.
- Build hash-linked research packets, negative controls, duplicate assessments,
  candidate histories, and generic/HackerOne/Bugcrowd Markdown drafts.
- Prepare concrete API and GraphQL fuzz batches, relational and stateful checks,
  reductions, regression corpora, owned Schemathesis fixtures, and reviewed
  fixed-target Atheris profiles.
- Run reviewed Opengrep, Betterleaks, Ruff, and oasdiff adapters with pinned
  versions, provenance, bounded inputs, normalized outputs, and owned controls.

## Install from the release source

Whitehat is not published on PyPI. The `whitehat` PyPI project is unrelated.

```sh
git clone https://github.com/agentcarlosian/Whitehat.git
cd Whitehat
git checkout v0.1.0
python -m venv .venv
python -m pip install .
python -m whitehat doctor --json
```

Install optional reviewed tools only for the workflows you intend to use. Native
tool setup remains a separate explicit action.

## Boundaries

Whitehat does not supply authorization. Exact program policy, asset identity,
controlled accounts and objects, current sessions, and human review remain
external prerequisites. Scanner matches, status codes, crashes, callbacks, and
model agreement are observations rather than validated vulnerabilities.

Automatic target discovery, broad scanning, credential attacks, autonomous
exploit chaining, disclosure, contact, and report submission are not provided.
The only legacy generic network profile is owned IPv4 loopback; external HTTP(S)
replay requires exact prepared-request hashes and a reviewed session contract.

## Verification

The release commit must pass the Ubuntu, Windows and macOS validation matrix,
source-fuzz, installed-package checks, and the tracked-source release audit. The
audit verifies Apache-2.0, scans tracked and packaged text for reviewed secret
patterns, checks exact archive membership and package source bytes, and installs
the generated wheel without network dependencies. Generated distributions are
audit inputs and are not uploaded with this source-only release.
