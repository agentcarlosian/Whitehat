"""Verify the real CLI against newly authored disposable API and GraphQL fixtures."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from whitehat.fuzz_fixture import owned_fuzz_api  # noqa: E402


def evaluate(root: Path, installed: bool = False) -> dict:
    root.mkdir()
    environment = dict(
        os.environ,
        WHITEHAT_CREDENTIAL_ALICE="owned-alice",
        WHITEHAT_CREDENTIAL_BOB="owned-bob",
    )

    def run(*arguments):
        result = subprocess.run(
            [
                sys.executable,
                *(["-I"] if installed else []),
                "-B",
                "-m",
                "whitehat",
                *map(str, arguments),
                "--json",
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        return json.loads(result.stdout)

    def write(path, value):
        path.write_text(json.dumps(value, indent=2), encoding="utf-8")
        return path

    def retarget(value, origin):
        if isinstance(value, dict):
            return {
                key: (
                    origin + child.removeprefix("https://owned.example.invalid")
                    if key == "url"
                    and isinstance(child, str)
                    and child.startswith("https://owned.example.invalid/")
                    else retarget(child, origin)
                )
                for key, child in value.items()
            }
        if isinstance(value, list):
            return [retarget(child, origin) for child in value]
        return value

    def session(directory, name):
        value = json.loads((directory / "session.draft.json").read_text())
        value["sessionId"] = "owned-" + name
        value["authority"].update(
            approved=True,
            researcherControlled=True,
            policy="Owned disposable API started by this evaluation",
        )
        value["allowMutation"] = True
        value["budgets"]["minDelayMs"] = 0
        for identity in value["identities"]:
            identity.update(
                auth="bearer",
                credentialEnv="WHITEHAT_CREDENTIAL_" + identity["id"].upper(),
            )
        return write(directory / "session.json", value)

    outcomes = {}
    for broken in (False, True):
        name = "broken" if broken else "fixed"
        with owned_fuzz_api(vulnerable=broken) as (origin, state):
            plan = retarget(
                json.loads((ROOT / "examples/fuzz/mutation-plan.json").read_text()),
                origin,
            )
            plan_path = write(root / (name + "-plan.json"), plan)
            directory = root / (name + "-batch")
            run("fuzz", "generate", plan_path, "--output-dir", directory)
            result = run(
                "fuzz",
                "run",
                directory / "batch.json",
                "--session",
                session(directory, name),
                "--state",
                directory / "ledger.sqlite3",
                "--output",
                directory / "run.json",
            )
            outcomes[name] = result["summary"]["observations"]
            if (
                bool(outcomes[name]) != broken
                or not result["provenance"]["complete"]
                or state["owner"] != "alice"
            ):
                raise RuntimeError("owned mutation/readback/reset control failed")
            http_path = directory / "http.json"
            run("fuzz", "evidence", directory / "run.json", "--output", http_path)
            run(
                "packet",
                "init",
                "--project",
                "owned-fuzz",
                "--title",
                "Owned fuzz review",
                "--evidence",
                http_path,
                "--evidence",
                directory / "run.json",
                "--output",
                directory / "packet.json",
            )
            run(
                "packet",
                "export",
                directory / "packet.json",
                "--output",
                directory / "packet.md",
            )
            model = retarget(
                json.loads((ROOT / "examples/fuzz/stateful-model.json").read_text()),
                origin,
            )
            model_path = write(root / (name + "-model.json"), model)
            sequences = root / (name + "-stateful")
            run("fuzz", "stateful", model_path, "--output-dir", sequences)
            stateful = run(
                "fuzz",
                "run",
                sequences / "batch.json",
                "--session",
                session(sequences, name + "-sequences"),
                "--state",
                sequences / "ledger.sqlite3",
                "--output",
                sequences / "run.json",
            )
            if (
                bool(stateful["summary"]["observations"]) != broken
                or state["phase"] != "draft"
            ):
                raise RuntimeError("owned stateful/reset control failed")
            outcomes[name + "Stateful"] = stateful["summary"]["observations"]
            if broken:
                bad = next(
                    case
                    for case in result["provenance"]["cases"]
                    if "assertion:owner-unchanged" in case["failureKeys"]
                )
                reduction = root / "reduction"
                run(
                    "fuzz",
                    "reduce",
                    directory / ("case-" + bad["caseId"] + ".json"),
                    "--run",
                    directory / "run.json",
                    "--failure-key",
                    "assertion:owner-unchanged",
                    "--output-dir",
                    reduction,
                )
                run(
                    "fuzz",
                    "run",
                    reduction / "batch.json",
                    "--session",
                    session(reduction, "reduction"),
                    "--state",
                    reduction / "ledger.sqlite3",
                    "--output",
                    reduction / "run.json",
                )
                minimum = root / "minimized"
                run(
                    "fuzz",
                    "minimize",
                    reduction / "batch.json",
                    "--run",
                    reduction / "run.json",
                    "--output-dir",
                    minimum,
                )
                corpus = root / "corpus"
                run("fuzz", "corpus", "init", corpus, "--project", "owned-fuzz")
                run(
                    "fuzz",
                    "corpus",
                    "add",
                    corpus,
                    "--case",
                    minimum / "case.json",
                    "--run",
                    reduction / "run.json",
                    "--failure-key",
                    "assertion:owner-unchanged",
                )
                duplicate = run(
                    "fuzz",
                    "corpus",
                    "add",
                    corpus,
                    "--case",
                    minimum / "case.json",
                    "--run",
                    reduction / "run.json",
                    "--failure-key",
                    "assertion:owner-unchanged",
                )
                regression = root / "regression"
                run("fuzz", "corpus", "batch", corpus, "--output-dir", regression)
                run(
                    "fuzz",
                    "run",
                    regression / "batch.json",
                    "--session",
                    session(regression, "regression"),
                    "--state",
                    regression / "ledger.sqlite3",
                    "--output",
                    regression / "run.json",
                )
                checked = run(
                    "fuzz",
                    "corpus",
                    "regress",
                    corpus,
                    "--batch",
                    regression / "batch.json",
                    "--run",
                    regression / "run.json",
                )
                if (
                    not duplicate["duplicate"]
                    or checked["entries"][0]["outcome"] != "reproduced"
                ):
                    raise RuntimeError(
                        "corpus reproduction/deduplication control failed"
                    )
                outcomes["corpusReproduced"] = True
    gql_plan = root / "graphql-plan.json"
    inventory = run(
        "graphql",
        "inventory",
        ROOT / "examples/fuzz/schema.graphql",
        "--project",
        "owned-fuzz",
    )
    run(
        "graphql",
        "inspect",
        ROOT / "examples/fuzz/query.graphql",
        "--schema",
        ROOT / "examples/fuzz/schema.graphql",
        "--project",
        "owned-fuzz",
    )
    run(
        "graphql",
        "plan",
        ROOT / "examples/fuzz/graphql-request.json",
        "--schema",
        ROOT / "examples/fuzz/schema.graphql",
        "--project",
        "owned-fuzz",
        "--identity",
        "alice",
        "--output",
        gql_plan,
    )
    generated = run(
        "fuzz", "generate", gql_plan, "--output-dir", root / "graphql-batch"
    )
    if not inventory["operations"] or generated["cases"] < 2:
        raise RuntimeError("GraphQL planning control failed")
    return {
        "ok": True,
        "ownedOutcomes": outcomes,
        "graphqlCases": generated["cases"],
        "installed": installed,
        "externalTargetsTested": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir")
    parser.add_argument("--installed", action="store_true")
    args = parser.parse_args()
    if args.output_dir:
        result = evaluate(Path(args.output_dir).absolute(), args.installed)
    else:
        with tempfile.TemporaryDirectory(
            prefix="whitehat-fuzz-evaluation-"
        ) as temporary:
            result = evaluate(Path(temporary) / "review", args.installed)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
