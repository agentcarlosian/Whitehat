# GitHub presentation

Description:

Security research toolkit for code review, API evidence, reproducible fuzzing, scanner triage, and bounty workflows.

Topics: security-research, bug-bounty, security-tools, api-security, api-testing,
fuzzing, openapi, graphql, sarif, secret-scanning, static-analysis, python, cli.

The added topics map to implemented surfaces and established GitHub ecosystems:

| Topic | Whitehat surface | GitHub repositories indexed on 2026-09-15 |
| --- | --- | ---: |
| `api-security` | HTTP evidence, access matrices, reviewed replay | 970 |
| `api-testing` | Owned Schemathesis lifecycle and request scenarios | 3,574 |
| `fuzzing` | Mutation, stateful, reduction, corpus and Atheris workflows | 1,898 |
| `openapi` | Offline inventory, coverage and oasdiff comparison | 14,451 |
| `graphql` | Offline schema/document and operation-aware mutation planning | 33,189 |
| `sarif` | Bounded SARIF 2.1.0 import | 1,242 |
| `secret-scanning` | Betterleaks execution and Betterleaks/Gitleaks import | 498 |

[Schemathesis](https://github.com/schemathesis/schemathesis) uses `api-testing`,
`fuzzing`, `openapi`, and `graphql`;
[Semgrep](https://github.com/semgrep/semgrep) uses `static-analysis`; and
[Gitleaks](https://github.com/gitleaks/gitleaks) uses `security-tools`. The
remaining existing topics describe Whitehat's audience, implementation language,
and primary CLI surface.

Initial public settings:

- Keep Issues enabled and Discussions disabled.
- Disable Wiki and Projects unless they have an active owner and workflow.
- Enable automatic deletion of merged branches.
- Protect `main` with a ruleset that blocks force pushes and deletion and requires
  the `release-audit` status check, with a narrow owner recovery path.
- Enable private vulnerability reporting and available dependency, secret, and
  push-protection features immediately after visibility changes.

Do not advertise hosted services, autonomous exploitation, credential validation,
package-index availability, or public availability before those statements are true.
