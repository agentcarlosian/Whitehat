# GitHub presentation

## Public repository description

Security research toolkit for code review, API evidence, reproducible fuzzing, scanner triage, and bounty workflows.

## Topics and implemented surfaces

| Topics | Whitehat surface |
| --- | --- |
| `security-research`, `bug-bounty`, `security-tools` | Authorized research, evidence review, and reproducible packets |
| `api-security`, `api-testing` | HTTP evidence, access matrices, reviewed replay, and owned API fixtures |
| `fuzzing` | Concrete mutation, stateful checks, reduction, corpora, and fixed Atheris profiles |
| `openapi` | Offline inventory, coverage, and oasdiff comparison |
| `graphql` | Offline schemas/documents and operation-aware mutation planning |
| `sarif` | Bounded SARIF 2.1.0 report import |
| `secret-scanning` | Betterleaks execution and Betterleaks/Gitleaks import |
| `static-analysis` | Reviewed source patterns and source/dependency comparison |
| `python`, `cli` | Implementation language and primary command-line surface |

Keep descriptions tied to implemented behavior. Public source availability does
not establish adoption, general detection accuracy, or confirmed vulnerabilities.

## Maintainer settings checklist

Review these settings when maintaining the public repository; this document is
not an attestation that every setting is enabled.

- Keep Issues enabled and Discussions disabled unless an active discussion
  workflow is selected.
- Keep Wiki and Projects disabled unless they have an active owner and workflow.
- Enable automatic deletion of merged branches.
- Protect `main` against force pushes and deletion and require the
  `release-audit` status check, with a narrow owner recovery path.
- Review private vulnerability reporting and available dependency, secret, and
  push-protection features.
- Keep the release link and source-install guidance consistent with the
  [published release record](release-readiness.md).

Hosted services, autonomous exploitation, live credential validation, and
package-index distribution are not current Whitehat capabilities. Do not
advertise them as available.
