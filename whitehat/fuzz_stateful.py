"""Finite-state sequence generation with explicit setup/readback/reset."""

from __future__ import annotations

import copy
import importlib.metadata
from pathlib import Path

from .evidence_links import fields
from .fuzz_contracts import CASE_SCHEMA, embedded_step, integer, json_file
from .fuzz_generation import HYPOTHESIS_VERSION, write_batch
from .http_evidence import digest, label
from .reports import ReportError


def generate_stateful(path: str, directory: str) -> dict:
    model = fields(
        json_file(Path(path)),
        {
            "schemaVersion",
            "projectId",
            "seed",
            "maxCases",
            "maxSteps",
            "initialState",
            "states",
            "actions",
            "setup",
            "readback",
            "reset",
            "assertions",
        },
        "stateful model",
    )
    if model["schemaVersion"] != "whitehat-stateful-model-v1":
        raise ReportError("unsupported stateful model")
    project = label(model["projectId"], "project")
    seed = integer(model["seed"], "seed", 0, 2**32 - 1)
    maximum = integer(model["maxCases"], "maxCases", 1, 16)
    length = integer(model["maxSteps"], "maxSteps", 1, 10)
    if not isinstance(model["states"], list) or not 1 <= len(model["states"]) <= 20:
        raise ReportError("model needs bounded states")
    states = {label(s, "state") for s in model["states"]}
    if len(states) != len(model["states"]) or model["initialState"] not in states:
        raise ReportError("invalid initial/duplicate state")
    actions = model["actions"]
    if not isinstance(actions, list) or not 1 <= len(actions) <= 16:
        raise ReportError("model needs 1-16 actions")
    seen = set()
    for action in actions:
        fields(action, {"id", "from", "to", "step", "invalidStatuses"}, "model action")
        if label(action["id"], "action") in seen:
            raise ReportError("duplicate model action")
        seen.add(action["id"])
        if (
            not isinstance(action["from"], list)
            or not action["from"]
            or set(action["from"]) - states
            or action["to"] not in states
        ):
            raise ReportError("model action references unknown states")
        embedded_step(action["step"])
        if (
            not isinstance(action["invalidStatuses"], list)
            or not 1 <= len(action["invalidStatuses"]) <= 10
        ):
            raise ReportError("invalid transitions need explicit rejection statuses")
        for status in action["invalidStatuses"]:
            integer(status, "invalid transition status", 400, 499)
    for phase in ("setup", "readback", "reset"):
        if not isinstance(model[phase], list) or not 1 <= len(model[phase]) <= 5:
            raise ReportError(
                "stateful generation requires bounded explicit setup, readback and reset"
            )
        for step in model[phase]:
            embedded_step(step)
    final_reset = model["reset"][-1]
    if final_reset["request"]["method"] != "GET" or not (
        final_reset["expect"]["values"] or final_reset["expect"]["absent"]
    ):
        raise ReportError("reset must end with a GET that checks authoritative state")
    try:
        if importlib.metadata.version("hypothesis") != HYPOTHESIS_VERSION:
            raise ReportError(
                "stateful generation requires the pinned Hypothesis version"
            )
    except importlib.metadata.PackageNotFoundError as exc:
        raise ReportError("install the fuzz extra for stateful generation") from exc
    from hypothesis import Phase, given, seed as seeded, settings, strategies as st

    sequences = [[i] for i in range(len(actions))]

    @seeded(seed)
    @settings(
        max_examples=maximum * 2, database=None, deadline=None, phases=[Phase.generate]
    )
    @given(st.lists(st.integers(0, len(actions) - 1), min_size=1, max_size=length))
    def collect(sequence):
        sequences.append(sequence)

    collect()
    cases, seen_sequences, total = [], set(), 0
    for sequence in sequences:
        if tuple(sequence) in seen_sequences:
            continue
        seen_sequences.add(tuple(sequence))
        current, steps, transitions = model["initialState"], [], []
        for index, action_index in enumerate(sequence):
            action = actions[action_index]
            allowed = current in action["from"]
            step = copy.deepcopy(action["step"])
            step["id"] = f"action-{index}-{action['id']}"
            if not allowed:
                step["expect"] = {
                    "statuses": action["invalidStatuses"],
                    "values": {},
                    "absent": [],
                }
            steps.append(step)
            next_state = action["to"] if allowed else current
            transitions.append(
                {
                    "actionId": action["id"],
                    "before": current,
                    "after": next_state,
                    "expectedAllowed": allowed,
                }
            )
            current = next_state
        count = sum(len(model[p]) for p in ("setup", "readback", "reset")) + len(steps)
        if total + count > 100:
            break
        total += count
        cases.append(
            {
                "schemaVersion": CASE_SCHEMA,
                "projectId": project,
                "id": f"stateful-{len(cases):03d}",
                "setup": copy.deepcopy(model["setup"]),
                "steps": steps + copy.deepcopy(model["readback"]),
                "reset": copy.deepcopy(model["reset"]),
                "assertions": copy.deepcopy(model["assertions"]),
                "lineage": {
                    "modelSha256": digest(model),
                    "seed": seed,
                    "hypothesisVersion": HYPOTHESIS_VERSION,
                    "transitions": transitions,
                },
            }
        )
        if len(cases) == maximum:
            break
    return write_batch(
        directory,
        project,
        cases,
        {
            "kind": "stateful-generation",
            "modelSha256": digest(model),
            "seed": seed,
            "hypothesisVersion": HYPOTHESIS_VERSION,
            "requestedCases": maximum,
        },
    )
