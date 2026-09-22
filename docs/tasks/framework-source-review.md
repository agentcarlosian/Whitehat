# Framework-aware source review

Selected scope: improvement 5, source review with framework and data-flow context.
Owner: public Whitehat. Branch: `codex/framework-source-review`. Merge target: `main`.

Acceptance criteria:

- Add an explicit Express/TypeScript Opengrep profile with newly authored rules
  for request input reaching a small reviewed set of sensitive operations.
- Keep the default source profile, existing fingerprints and runtime tool pins
  compatible. Record profile/rules/input identities and actual engine behavior.
- Preserve bounded, redacted SARIF secondary locations and reported code flows,
  and supported native flow locations, as evidence metadata separate from identity.
- Render locations, reported flow order and authored review questions in terminal,
  Markdown review and packet output. Never infer confirmed reachability or impact.
- Prove vulnerable/fixed/unrelated-source controls using the actual pinned engine;
  test malformed paths, counts, traces, metadata tampering and redaction.
- Complete repository validation, native/installed CLI evaluations, documentation,
  release inventory/audit and PR CI verification.

Limits: source is copied and analyzed, never imported or executed. No target
traffic, arbitrary rules/configuration, credential validation, external artifact
resolution, new native tool download or automatic vulnerability conclusion.

Status: implemented and locally verified. Cross-platform verification is recorded
on the feature PR. PR #12 is merged; this slice starts from public main
`e42fc514679c03c205b2a616ce65326e39bb7644`.

Implemented:

- Opt-in `scan opengrep --profile express-typescript`; three authored request-to-
  shell/eval/file-path rules for `.js` and `.ts`. Default rules/config unchanged.
- Optional `whitehat-source-context-v1` evidence metadata with relative locations,
  supplied flow order, recognized kinds and explicit partial-representation
  diagnostics. Context is excluded from observation fingerprints.
- Shared CLI/review/packet display with unverified labels and review guidance.
- SARIF cached thread-location consistency, redaction, path/count/coordinate
  rejection and native copied-source membership checks.

Completed local verification (Windows/Python 3.13.12):

- Full validation: 181 tests, three existing platform skips, 78 syntax files and
  all established golden-path assertions passed.
- Native Express profile: six observations across TypeScript/CommonJS vulnerable
  examples; zero in fixed controls and unrelated-framework examples. Source,
  assignment and sink locations were present; no source was executed.
- Original native research evaluation passed: five basic source observations,
  zero in its fixed/text controls, one redacted secret marker and zero clean matches.
- `evaluate_source_review.py --native` passed in both checkout and isolated
  installed-package modes, including SARIF, comparison and Markdown/packet exports.
- A clean temporary source copy built and installed successfully with the existing
  pinned dependencies; isolated Ruff checks and `git diff --check` passed.
- 66 local Markdown file links resolved.

Limits remain documented in `docs/source-review.md`: narrow Express callback and
import shapes, single-function analysis, no JSX/TSX, no arbitrary rules, bounded
report locations, and no validated-reachability/impact claim. Native execution is
Windows/Linux x64; macOS retains import and rendering support.
