# Research toolkit and adoption

Updated: 2026-09-14. Owner: Whitehat. Branch: `codex/research-toolkit`.
Merge target: `main`.

The owner requested the four toolkit priorities, followed by adoption and research
quality improvements. Positioning is practical security research and authorized
bounty workflows; locality is an implementation property, not the headline.

## Ordered acceptance criteria

1. Security analysis: pinned Opengrep adapter, authored Python/JavaScript rules,
   vulnerable/fixed/false-positive fixtures, normalized results, actual tool proof.
2. Dependency intelligence: OSV-Scanner JSON import with package/version/advisory
   identity and fixed-version context; package matches remain distinct from impact.
3. Interoperability: SARIF, ZAP JSON, and Nuclei JSONL import, redacted observations,
   stable fingerprints, baseline comparison and bounded parsing.
4. Secrets: pinned detector, redacted results, synthetic canary/clean proof,
   and compatible report import.
5. Adoption: installation/quickstart, README/About positioning, contribution and
   project-security guidance, issue templates, changelog, compatibility matrix,
   and a documented adapter update process.
6. Research quality: portable workspace, structured case notes, Markdown export,
   a repeatable source-review walkthrough, and positive/negative evaluations.

## Execution boundaries

- Implement and verify against owned examples and inert reports.
- Tool setup is explicit, version/hash checked, and isolated to an ignored folder.
- Imports cause no target traffic, credential verification, or submission.
- Preserve exact loopback execution. External target execution needs its own
  capability design; removing "local-first" does not enable it.
- No visibility change, tag, package publication, or external messaging.

## Progress

- [x] Verify checkout matches GitHub `7e47505`; create the feature branch.
- [x] Complete priorities 1-4 and adversarial/compatibility tests.
- [x] Complete adoption and research-quality workflow.
- [x] Full validation, installed-package checks, and technical release audit.
- [ ] Record results/limitations and prepare the reviewable change.

Closure requires completed verification for implemented claims. Native tool,
hosted CI, and synthetic parser evidence must be distinguished. The baseline
passed 71 tests on Ubuntu/Python 3.11 and 3.13 plus release CI at `7e47505`.

## Verification checkpoint

- Windows/Python 3.13.12: 91 tests, zero failures, two existing symlink privilege
  skips; syntax and all golden-path checks pass.
- Native Opengrep 1.30.0: five expected observations across Python/JavaScript,
  zero in fixed twins and strings-only controls; complete source coverage checked.
- Betterleaks 1.8.1: one owned marker with value omitted, zero in clean controls;
  native clean JSON `null` behavior verified and supported.
- Native evaluation verifies baseline comparison, OSV import, case, linked review,
  and Markdown export. Tests cover malformed JSON, paths, redaction, input budgets,
  tool identity rejection, review tamper, and overwrite refusal.
- Ruff correctness lint passes. The project-only 0.9.0a1 package install passes.
- Technical release audit passed at `27bb836`: 97 tracked files, 24 release inputs,
  zero high-confidence secret matches, canonical Apache-2.0, 32-file sdist,
  23-file wheel, and clean installed `0.9.0a1` diagnostics. Installed imports and
  toolkit discovery also passed in isolated Python mode.
- Expanded hosted CI remains to be recorded. No public release or visibility
  change is authorized.
