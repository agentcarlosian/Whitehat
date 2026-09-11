# Whitehat alpha specification

## Product surface

The primary interface is `python -m whitehat`; installation also provides the
`whitehat` console command. Commands are deterministic and non-interactive.

## Risk model

| Level | Activity | Initial behavior |
| --- | --- | --- |
| L0 | Local read-only and prepared offline analysis | Available without approval artifacts |
| L1 | Local synthetic processes or containers | Planned; explicit invocation and bounded resources |
| N1 | Network access to an authorized asset | Not implemented; requires a reviewed session design |
| H1 | Credentials, mutation, destructive work, money, contact, disclosure, submission | Not implemented; exact human authorization required |

## `doctor`

`whitehat doctor [--json]` reports the package version, Python runtime, platform,
implemented capabilities, and unavailable side-effect classes. It performs no
network action and reads no project or user configuration.

## `analyze diff`

```text
whitehat analyze diff BEFORE AFTER [--max-entries N] [--max-files N]
  [--max-file-bytes N] [--max-total-bytes N] [--json]
```

The command recursively compares two existing operator-controlled directories.
It hashes regular files and returns sorted metadata for added, deleted, and
modified paths. File contents and unchanged path names are not returned.

The command:

- never executes an input;
- performs no network action;
- rejects symbolic links and unsupported filesystem entries;
- stops when an entry, file, per-file byte, or aggregate byte limit is exceeded;
- detects common file replacement or mutation during hashing;
- returns deterministic summaries and a result hash.

Success exits `0`. Command-line usage errors exit `2`, invalid inputs exit `3`,
and configured limit failures exit `4`.
