# Workspace visibility and structured-input fuzzing

Selected scope: improvement 1 (unified workspace) and improvement 4
(structured-input fuzzing). Owner: public Whitehat. Merge target: `main`.
Branch: `codex/workspace-and-structured-fuzz`. This is independent public
product work under this repository's development guide.

Acceptance criteria:

- An explicitly registered, portable workspace index supports readable and JSON
  status/check output, validates existing packets/candidates, reports missing or
  changed artifacts, and propagates stale dependencies without modifying evidence.
- Bounded JSON scalar arrays generate reproducible empty, size-boundary,
  duplicate, invalid-element and omission cases with correct expectations.
- GraphQL input objects and scalar lists use the same bounded primitives with
  explicit nullability/default/coercion semantics and unsupported-type rejection.
- Owned controls and adversarial tests cover both workflows; docs, examples,
  release inventory and full repository validation agree with implementation.

Limits: offline preparation/inspection only; no new execution capability,
credential access, target discovery, remote testing, contact or submission.
Existing exact-request sessions remain necessary for any replay. No private or
prior-project implementation, schemas, fixtures or evidence are imported.

Closure: targeted tests, full validation, owned golden paths and installed-package
checks complete; changes and remaining platform limits recorded here.

Status: implementation and local verification complete. GitHub CI is the
remaining cross-platform check before merge.

Implemented:

- `workspace index/status/check`, explicit inputs/results/packets/candidates,
  automatic supported evidence links, operator-declared dependencies and
  transitive staleness. Existing evidence and decision files remain untouched.
- JSON scalar arrays with bounded lengths, typed element/uniqueness checks,
  optional/required omission and deterministic boundary/Hypothesis generation.
- Nested GraphQL input objects and scalar/enum lists, including nullability,
  field/variable defaults, singleton-list coercion and integer ID inputs.
- CLI demonstrations, operator documentation, four owned input examples and CI
  execution of workspace checks and the expanded fuzz evaluation.

Verification (Windows/Python 3.13.12):

- `python -B scripts/validate.py`: 170 tests, three expected platform skips,
  74 syntax files and all existing golden-path assertions passed.
- Isolated Ruff E4/E7/E9/F checks and `git diff --check` passed.
- Workspace CLI evaluation detected an input change and stale comparison/packet.
- Fuzz CLI evaluation: 16 array discrepancies in the broken twin, zero in the
  fixed twin, 16 GraphQL input-object cases, existing mutation/stateful/corpus
  controls passed. The bounty workflow evaluation also passed unchanged.
- Built and installed a wheel from a temporary copy of the release inventory;
  both workspace and fuzz evaluations passed with isolated installed imports.
- 60 local Markdown file links resolved.
- The final review added a regression for numeric array schemas with a negative
  upper bound and no lower bound; both integer and number sampling pass.

The checkout-wide pip wheel build was interrupted after stalling. The clean
source build succeeded with the already installed pinned build dependencies and
`--no-cache-dir` (the host's shared pip cache was not writable in the sandbox).
No dependency versions changed. Linux Atheris and link-creation checks require
their CI platforms. Array query serialization, nested arrays, lists of input
objects, recursive/oneOf GraphQL inputs and custom scalars remain unsupported.
