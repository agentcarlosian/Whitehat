# Security of Whitehat

This document concerns defects in Whitehat itself. Whitehat does not operate a
bounty program or accept submissions on behalf of other projects.

For a reproducible issue that can be described without secrets or target data,
open a GitHub issue with the Whitehat version, operating system, a minimal owned
fixture, expected behavior, and actual behavior. Do not attach raw research
captures, credentials, or another person's data.

For a sensitive issue, do not post exploit details publicly. If the repository's
Security tab offers private vulnerability reporting, use that channel. Otherwise
open a content-free issue requesting a private channel from the maintainer. No
unverified email address or response-time commitment is advertised here.

Security fixes are developed on `main`. The first public release is `0.1.0`;
separate maintenance branches, backports, and a long-term support window are not
promised. Check the [changelog](CHANGELOG.md) and
[releases](https://github.com/agentcarlosian/Whitehat/releases) for published fixes.
See [constraints](docs/constraints.md) for the actual runtime boundary. Process
limits and sanitized environments are not a general operating-system sandbox.
