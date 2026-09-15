"""Finite reduction sweeps, reproducible corpus entries and regression records."""

from __future__ import annotations

import copy
import re
from pathlib import Path

from .evidence_links import contained_path, fields, sha256
from .fuzz_contracts import bundle_case, json_file, load_batch, load_case, write_tree
from .fuzz_generation import write_batch
from .http_evidence import digest, label, validate_evidence
from .reports import (
    CLAIMS,
    ReportError,
    canonical,
    checked_research_result,
    parse_json,
    seal,
)


def load_run(path: str) -> dict:
    result = checked_research_result(path)
    provenance = result["provenance"]
    if provenance.get("kind") != "fuzz-run":
        raise ReportError("expected a concrete fuzz run")
    project = label(provenance.get("projectId"), "project")
    sha256(provenance.get("batchSha256"))
    if not isinstance(provenance.get("httpEvidence"), dict):
        raise ReportError("fuzz run has no valid HTTP evidence document")
    evidence = validate_evidence(provenance["httpEvidence"])
    if (
        evidence["projectId"] != project
        or evidence["provenance"].get("batchSha256") != provenance["batchSha256"]
    ):
        raise ReportError("fuzz run/evidence binding mismatch")
    cases = provenance.get("cases")
    if (
        not isinstance(cases, list)
        or len(cases) > 32
        or type(provenance.get("complete")) is not bool
    ):
        raise ReportError("invalid fuzz run cases/completion")
    seen, seen_hashes = set(), set()
    for case in cases:
        if not isinstance(case, dict):
            raise ReportError("invalid fuzz run case")
        name = label(case.get("caseId"), "case")
        if name in seen:
            raise ReportError("duplicate fuzz run case")
        seen.add(name)
        key = sha256(case.get("caseSha256"))
        if key in seen_hashes:
            raise ReportError("duplicate fuzz case hash")
        seen_hashes.add(key)
        if case.get("outcome") not in (
            "consistent",
            "mismatch",
            "inconclusive",
            "blocked",
        ) or case.get("cleanup") not in ("verified", "incomplete", "not-required"):
            raise ReportError("invalid fuzz run outcome")
        keys = case.get("failureKeys")
        if (
            not isinstance(keys, list)
            or len(keys) > 64
            or any(
                not isinstance(k, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", k)
                for k in keys
            )
        ):
            raise ReportError("invalid fuzz failure keys")
    return result


def extract_http(path: str) -> dict:
    return load_run(path)["provenance"]["httpEvidence"]


def embedded_case(case: dict, requests: dict[str, dict]) -> dict:
    value = copy.deepcopy(case)
    for phase in ("setup", "steps", "reset"):
        for step in value[phase]:
            step["request"] = copy.deepcopy(requests[step["id"]])
            del step["requestSha256"]
    return value


def reproduced(case: dict, run: dict, failure_key: str | None = None) -> dict:
    if run["provenance"]["projectId"] != case["projectId"]:
        raise ReportError("case/run project mismatch")
    matches = [c for c in run["provenance"]["cases"] if c["caseSha256"] == digest(case)]
    if (
        len(matches) != 1
        or matches[0]["outcome"] != "mismatch"
        or matches[0]["cleanup"] == "incomplete"
        or not matches[0]["failureKeys"]
    ):
        raise ReportError("case needs reproduced evidence with completed cleanup")
    if failure_key is not None and failure_key not in matches[0]["failureKeys"]:
        raise ReportError("selected failure key was not reproduced")
    return matches[0]


def reduce_case(
    case_path: str, run_path: str, directory: str, failure_key: str | None = None
) -> dict:
    case, requests = load_case(Path(case_path))
    run = load_run(run_path)
    observed = reproduced(case, run, failure_key)
    failure_key = failure_key or observed["failureKeys"][0]
    original = embedded_case(case, requests)
    variants = [original]
    protected = {
        rule[side]["stepId"]
        for rule in case["assertions"]
        for side in ("left", "right")
        if rule[side]
    }
    # Removing setup/reset would change the test's preconditions and is forbidden.
    for index, step in enumerate(original["steps"]):
        if len(original["steps"]) > 1 and step["id"] not in protected:
            variant = copy.deepcopy(original)
            del variant["steps"][index]
            variants.append(variant)
        request = step["request"]
        if request["body"] is None:
            continue
        try:
            body = parse_json(request["body"].encode("utf-8"))
        except ReportError:
            continue
        if not isinstance(body, dict):
            continue
        for key, value in body.items():
            replacements = [(True, None)]
            if isinstance(value, str):
                replacements.extend((False, v) for v in ("", value[: len(value) // 2]))
            if type(value) is int:
                replacements.extend((False, v) for v in (0, -1 if value < 0 else 1))
            for omit, replacement in replacements:
                smaller = copy.deepcopy(body)
                if omit:
                    smaller.pop(key)
                else:
                    smaller[key] = replacement
                variant = copy.deepcopy(original)
                variant["steps"][index]["request"]["body"] = canonical(smaller).decode(
                    "utf-8"
                )
                variants.append(variant)
    cases, seen, total = [], set(), 0
    for variant in variants:
        signature = digest(
            {k: variant[k] for k in ("setup", "steps", "reset", "assertions")}
        )
        if signature in seen:
            continue
        seen.add(signature)
        count = sum(len(variant[p]) for p in ("setup", "steps", "reset"))
        if total + count > 100 or len(cases) >= 32:
            break
        total += count
        variant["id"] = f"reduction-{len(cases):03d}"
        variant["lineage"] = {
            **variant["lineage"],
            "parentCaseSha256": digest(case),
            "parentRunSha256": run["resultSha256"],
            "failureKey": failure_key,
        }
        cases.append(variant)
    return write_batch(
        directory,
        case["projectId"],
        cases,
        {
            "kind": "reduction",
            "parentCaseSha256": digest(case),
            "parentRunSha256": run["resultSha256"],
            "failureKey": failure_key,
        },
    )


def minimize_batch(batch_path: str, run_path: str, directory: str) -> dict:
    batch, cases = load_batch(batch_path)
    run = load_run(run_path)
    if batch["provenance"].get("kind") != "reduction" or run["provenance"][
        "batchSha256"
    ] != digest(batch):
        raise ReportError(
            "minimization requires the matching reviewed reduction batch/run"
        )
    key = batch["provenance"]["failureKey"]
    observed = {c["caseSha256"]: c for c in run["provenance"]["cases"]}
    matches = []
    for case, requests in cases:
        result = observed.get(digest(case))
        if (
            result
            and result["outcome"] == "mismatch"
            and result["cleanup"] != "incomplete"
            and key in result["failureKeys"]
        ):
            score = (
                len(case["steps"]),
                sum(len(canonical(requests[s["id"]])) for s in case["steps"]),
                digest(case),
            )
            matches.append((score, case, requests))
    if not matches:
        raise ReportError("no reduction candidate reproduced the selected failure")
    _, best, requests = min(matches, key=lambda v: v[0])
    documents = {}
    bundled = bundle_case(embedded_case(best, requests), documents)
    documents["case.json"] = bundled
    receipt = seal(
        {
            "schemaVersion": "whitehat-fuzz-minimization-v1",
            "ok": True,
            "projectId": batch["projectId"],
            "caseSha256": digest(bundled),
            "sourceBatchSha256": digest(batch),
            "sourceRunSha256": run["resultSha256"],
            "parentCaseSha256": batch["provenance"]["parentCaseSha256"],
            "failureKey": key,
            "verifiedCandidates": len(matches),
            "globalMinimumProven": False,
            "effects": {"network": False, "filesystemWrite": True},
        }
    )
    documents["receipt.json"] = receipt
    write_tree(directory, documents)
    return receipt


def initialize_corpus(directory: str, project: str) -> dict:
    value = {
        "schemaVersion": "whitehat-fuzz-corpus-v1",
        "projectId": label(project, "project"),
    }
    write_tree(directory, {"corpus.json": value})
    return seal(
        {
            "schemaVersion": "whitehat-fuzz-corpus-status-v1",
            "ok": True,
            "projectId": project,
            "entries": [],
            "effects": {"network": False, "filesystemWrite": True},
        }
    )


def corpus_entries(directory: str) -> tuple[dict, list[tuple[dict, dict, dict]]]:
    root = Path(directory)
    metadata = fields(
        json_file(contained_path(root, "corpus.json")),
        {"schemaVersion", "projectId"},
        "corpus",
    )
    if metadata["schemaVersion"] != "whitehat-fuzz-corpus-v1":
        raise ReportError("unsupported corpus")
    label(metadata["projectId"], "project")
    children = sorted(root.iterdir())
    if len(children) > 101:
        raise ReportError("corpus exceeds 100 entries")
    entries = []
    for child in children:
        if child.name == "corpus.json":
            continue
        if not child.name.startswith("entry-"):
            raise ReportError("unexpected corpus file")
        key = sha256(child.name[6:])
        entry = fields(
            json_file(contained_path(root, child.name + "/entry.json")),
            {"schemaVersion", "key", "caseSha256", "runSha256", "failureKey"},
            "corpus entry",
        )
        case, requests = load_case(contained_path(root, child.name + "/case.json"))
        if (
            entry["key"] != key
            or entry["caseSha256"] != digest(case)
            or case["projectId"] != metadata["projectId"]
        ):
            raise ReportError("corpus entry hash/project mismatch")
        sha256(entry["runSha256"])
        if (
            entry["schemaVersion"] != "whitehat-fuzz-corpus-entry-v1"
            or not isinstance(entry["failureKey"], str)
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", entry["failureKey"])
        ):
            raise ReportError("invalid corpus failure reference")
        entries.append((entry, case, requests))
    return metadata, entries


def add_corpus(
    directory: str, case_path: str, run_path: str, failure_key: str | None = None
) -> dict:
    metadata, entries = corpus_entries(directory)
    case, requests = load_case(Path(case_path))
    run = load_run(run_path)
    observed = reproduced(case, run, failure_key)
    if case["projectId"] != metadata["projectId"]:
        raise ReportError("case and corpus projects differ")
    key_name = failure_key or observed["failureKeys"][0]
    embedded = embedded_case(case, requests)
    key = digest(
        {
            "projectId": case["projectId"],
            "failureKey": key_name,
            **{p: embedded[p] for p in ("setup", "steps", "reset", "assertions")},
        }
    )
    duplicate = any(e["key"] == key for e, _, _ in entries)
    if not duplicate:
        if len(entries) == 100:
            raise ReportError("corpus entry limit reached")
        documents = {}
        saved = bundle_case(embedded, documents)
        documents.update(
            {
                "case.json": saved,
                "entry.json": {
                    "schemaVersion": "whitehat-fuzz-corpus-entry-v1",
                    "key": key,
                    "caseSha256": digest(saved),
                    "runSha256": run["resultSha256"],
                    "failureKey": key_name,
                },
            }
        )
        write_tree(str(Path(directory) / ("entry-" + key)), documents)
    return seal(
        {
            "schemaVersion": "whitehat-fuzz-corpus-status-v1",
            "ok": True,
            "projectId": metadata["projectId"],
            "entryKey": key,
            "duplicate": duplicate,
            "entryCount": len(entries) + (not duplicate),
            "effects": {"network": False, "filesystemWrite": not duplicate},
        }
    )


def corpus_batch(
    directory: str, output: str, selected: list[str] | None = None
) -> dict:
    metadata, entries = corpus_entries(directory)
    cases, total = [], 0
    if selected and set(selected) - {e["key"] for e, _, _ in entries}:
        raise ReportError("corpus selection references an unknown entry")
    for entry, case, requests in entries:
        if selected and entry["key"] not in selected:
            continue
        count = sum(len(case[p]) for p in ("setup", "steps", "reset"))
        if len(cases) == 32 or total + count > 100:
            break
        total += count
        embedded = embedded_case(case, requests)
        embedded["id"] = "corpus-" + entry["key"]
        embedded["lineage"] = {
            **embedded["lineage"],
            "corpusEntry": entry["key"],
            "corpusCaseSha256": digest(case),
        }
        cases.append(embedded)
    return write_batch(
        output,
        metadata["projectId"],
        cases,
        {
            "kind": "corpus-regression",
            "entryKeys": [c["lineage"]["corpusEntry"] for c in cases],
            "totalCorpusEntries": len(entries),
        },
    )


def regress_corpus(directory: str, batch_path: str, run_path: str) -> dict:
    metadata, entries = corpus_entries(directory)
    batch, cases = load_batch(batch_path)
    run = load_run(run_path)
    if batch["projectId"] != metadata["projectId"] or run["provenance"][
        "batchSha256"
    ] != digest(batch):
        raise ReportError("corpus regression batch/run mismatch")
    by_entry = {
        case["lineage"].get("corpusEntry"): (case, requests) for case, requests in cases
    }
    observed = {c["caseSha256"]: c for c in run["provenance"]["cases"]}
    outcomes = []
    for entry, original, original_requests in entries:
        case, requests = by_entry.get(entry["key"], (None, None))
        result = observed.get(digest(case)) if case else None
        if case is None or result is None:
            outcome = "not-tested"
        elif case["lineage"].get("corpusCaseSha256") != digest(original) or digest(
            {
                p: embedded_case(case, requests)[p]
                for p in ("setup", "steps", "reset", "assertions")
            }
        ) != digest(
            {
                p: embedded_case(original, original_requests)[p]
                for p in ("setup", "steps", "reset", "assertions")
            }
        ):
            outcome = "not-comparable"
        elif result["cleanup"] == "incomplete" or result["outcome"] in (
            "blocked",
            "inconclusive",
        ):
            outcome = "inconclusive"
        elif entry["failureKey"] in result["failureKeys"]:
            outcome = "reproduced"
        else:
            outcome = "not-observed"
        outcomes.append(
            {
                "entryKey": entry["key"],
                "outcome": outcome,
                "caseSha256": digest(case) if case else None,
            }
        )
    return seal(
        {
            "schemaVersion": "whitehat-fuzz-regression-v1",
            "ok": True,
            "projectId": metadata["projectId"],
            "runSha256": run["resultSha256"],
            "entries": outcomes,
            "claims": dict(CLAIMS),
            "interpretation": "Not observed under this run's conditions is not proof of a fix.",
            "effects": {"network": False},
        }
    )
