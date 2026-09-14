# Research quality

Use the templates in `templates/` or the generated `case.json` to separate:
observation, hypothesis, reproduction, rejecting evidence, and analyst decision.

A source rule should lead to inspection of caller control, reachability, identity,
object ownership, and the actual protected action. An advisory should lead to
version/range, fix, reachability, and prior-disclosure checks. A secret detector
should lead to authorized review of the source; this toolkit never validates a
credential against a provider.

The fixture evaluation measures narrow behaviors: five intended source matches,
zero in fixed twins, zero in strings-only controls, one redacted owned marker,
zero in the secret clean control, and successful import/export. These numbers are
not a precision, recall, or bounty-success claim about real projects.

Keep the current target/commit and scope notes in the portable workspace. Record
what would disprove the hypothesis before additional testing. A report export
preserves the analyst's statements and hashes; it cannot independently validate
them. Contact and submission remain deliberate human actions outside the CLI.
