# Adding a research adapter

Start with one user task and one report format. Follow `whitehat/reports.py` for
imports and `whitehat/native_tools.py` for reviewed execution.

## Minimal contract

- Tool identity, exact version when executed, license, and upstream source.
- Input format, parser limits, supported languages/protocols and rejected cases.
- Fixed command/configuration and declared effects for execution.
- Normalized rule ID, relative location, explanation, tool-reported severity,
  contextual identity, fingerprint, and provenance.
- A positive case, fixed/negative control, malformed reports and value-redaction tests.
- Installation, compatibility, update instructions, and an example command.

For an import adapter, implement a pure parser accepting decoded data and an
optional lexical source prefix. Return observations through `observation()` and
`result_document()`. Register the format in `FORMATS` and `normalize()`. Do not
invoke a scanner, follow URLs, or import report-supplied code. Existing CLI,
review, baseline, and export behavior should work without another command family.

For a native adapter, pin the release archive plus executable and companion
identities. Prepare only bounded copied input, use fixed arguments through the
supervisor, normalize output, verify coverage, and retain process/config/input
provenance. Never trust a target's tool configuration or install during a scan.

Use `tests/test_reports.py` and `tests/test_native_tools.py` as examples. Add the
new module to `release-files.txt` and run package validation. No arbitrary-command
plugin interface is provided in this alpha.
