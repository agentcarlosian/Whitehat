# Workspace status and integrity

`workspace index` snapshots explicitly selected artifact paths and hashes.
`workspace status` displays current, changed, missing, invalid and stale artifacts.
`workspace check` emits the same result and exits 3 for inconsistent state.
These commands are offline and never execute research requests or read credentials.

## Owned demonstration

```sh
python -B scripts/evaluate_workspace.py --output-dir .whitehat-workspace-demo
python -m whitehat workspace status .whitehat-workspace-demo/workspace.json
```

The demonstration imports an owned report, creates a comparison and packet,
indexes them, then edits the input. Both downstream artifacts become stale.
Use a new output directory. Without `--output-dir`, storage is disposable;
`--installed` checks the installed package.

## Register existing artifacts

```text
whitehat workspace index WORKSPACE --project PROJECT --input inputs/capture.har --result results/before.json --result results/after.json --result results/comparison.json --packet packet.json --candidate candidates/access --depends-on results/before.json=inputs/capture.har --output WORKSPACE/workspace.json
whitehat workspace status WORKSPACE/workspace.json --json
whitehat workspace check WORKSPACE/workspace.json --output WORKSPACE/results/check.json --json
```

Artifact paths and dependency operands are relative to `WORKSPACE`; the output
index must be directly inside it. Repeat registration flags as needed:

| Flag | Inspection |
| --- | --- |
| `--input` | Exact bytes; contents are never displayed or interpreted |
| `--result` | Whitehat result hash and existing evidence validators where applicable |
| `--packet` | Existing packet validator, evidence links and content completeness |
| `--candidate` | Candidate identity, decision hash chain and latest decision |

`--depends-on child-path=parent-path` declares an operator-asserted dependency.
Comparison result/exchange hashes, candidate evidence, assessment evidence,
packet paths and supplied HTTP capture hashes also connect registered artifacts
automatically. Register input-to-result links explicitly when older formats lack
them. Raw captures need not be retained. Missing required comparison/candidate
evidence is reported as a missing link.

Packet evidence must be registered with `--result`. Unregistered packet references
are reported without opening them. A registered candidate includes its identity
and numbered decisions. Other files and directories are not inspected.

## Interpret and maintain an index

`changed` means bytes/history differ from the snapshot; `missing` means the
artifact is absent; `invalid` means validation or required linkage failed.
`stale` propagates through dependencies. Every row names immediate `staleBecause`
dependencies and a next action. Status never changes hashes or repairs evidence.

Packet content completeness is separate: an intact draft may pass the integrity
check while needing prerequisites, impact or reproduction text. Neither property
proves a vulnerability, external-system freshness, or submission readiness.

After reviewing changes and rebuilding affected results, explicitly create a
new index under a new filename. Candidate decisions appended since indexing
are changes too. Reindexing does not itself rerun research or prove that declared
dependencies have been recomputed. Results are deterministic for stable inputs.

Limits: 100 artifacts, 8 MiB/file, 32 MiB total registered input, and 1,000 decisions
per candidate. Paths must remain contained and cannot traverse links/junctions.
Duplicate paths, unknown dependencies and cycles are rejected. Status/check write
nothing unless `--output` is supplied; all outputs refuse overwrite. Exit 0 means
inspection completed (`check` also requires consistency), 3 means invalid input
or inconsistent `check`, and 4 means a byte limit was exceeded.
