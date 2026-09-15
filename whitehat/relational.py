"""Typed relational checks over explicitly bound selected response evidence."""

from __future__ import annotations

from pathlib import Path

from .evidence_links import contained_path, fields, sha256
from .fuzz_contracts import assertions, json_file
from .http_evidence import digest, label, load_evidence
from .reports import ReportError, observation, result_document


def evaluate_assertions(rules: list[dict], entries: dict[str, dict]) -> list[dict]:
    results = []
    for rule in rules:
        values, hashes, contexts = [], [], []
        inconclusive = False
        for side in ("left", "right"):
            operand = rule[side]
            if operand is None:
                continue
            entry = entries.get(operand["stepId"])
            if entry is None:
                inconclusive = True
                continue
            context, response = entry["context"], entry["response"]
            contexts.append(context)
            hashes.append(entry["evidenceSha256"])
            data = response["json"]
            if (
                any(context[k] != operand[k] for k in ("identityId", "objectId"))
                or not response["bodyCaptured"]
                or not data["parsed"]
                or operand["pointer"] not in data["selectedPointers"]
                or (
                    rule["relation"] not in ("absent", "present")
                    and not 200 <= response["status"] < 300
                )
            ):
                inconclusive = True
            values.append(
                (
                    operand["pointer"] in data["values"],
                    data["values"].get(operand["pointer"]),
                )
            )
        if len(contexts) == 2 and any(
            contexts[0][key] != contexts[1][key] for key in ("projectId", "objectId")
        ):
            inconclusive = True
        if inconclusive or not values:
            outcome = "inconclusive"
        elif rule["relation"] in ("absent", "present"):
            outcome = (
                "consistent"
                if values[0][0] == (rule["relation"] == "present")
                else "mismatch"
            )
        elif not all(present for present, _ in values):
            outcome = "inconclusive"
        else:
            left = values[0][1]
            right = values[1][1] if len(values) > 1 else rule["value"]
            if rule["relation"] == "delta":
                if type(left) is not int or type(right) is not int:
                    outcome = "inconclusive"
                else:
                    outcome = (
                        "consistent" if right - left == rule["value"] else "mismatch"
                    )
            else:
                outcome = "consistent" if digest(left) == digest(right) else "mismatch"
        results.append(
            {
                "assertionId": rule["id"],
                "relation": rule["relation"],
                "outcome": outcome,
                "evidenceSha256": hashes,
            }
        )
    return results


def assess_relations(path: str) -> dict:
    source = Path(path)
    plan = fields(
        json_file(source),
        {"schemaVersion", "projectId", "evidence", "assertions"},
        "relational plan",
    )
    if plan["schemaVersion"] != "whitehat-relational-plan-v1":
        raise ReportError("unsupported relational plan")
    project = label(plan["projectId"], "project")
    if not isinstance(plan["evidence"], list) or not 1 <= len(plan["evidence"]) <= 32:
        raise ReportError("relational plan needs 1-32 evidence references")
    entries, results = {}, []
    for reference in plan["evidence"]:
        fields(
            reference,
            {"id", "path", "resultSha256", "evidenceSha256"},
            "relational evidence",
        )
        name = label(reference["id"], "evidence ID")
        if name in entries:
            raise ReportError("duplicate relational evidence ID")
        document = load_evidence(str(contained_path(source.parent, reference["path"])))
        if document["projectId"] != project or document["resultSha256"] != sha256(
            reference["resultSha256"]
        ):
            raise ReportError("relational evidence project/hash mismatch")
        matches = [
            e
            for e in document["exchanges"]
            if e["evidenceSha256"] == sha256(reference["evidenceSha256"])
        ]
        if len(matches) != 1:
            raise ReportError("relational reference must identify one exchange")
        entries[name] = matches[0]
        results.append(document["resultSha256"])
    evaluations = evaluate_assertions(
        assertions(plan["assertions"], set(entries)), entries
    )
    observations = [
        observation(
            "whitehat-relational",
            evaluation["relation"] + "-mismatch",
            category="web-observation",
            context={"projectId": project, "assertionId": evaluation["assertionId"]},
            explanation="Selected readback evidence conflicts with the operator's relational expectation. Verify ordering, object ownership and impact.",
        )
        for evaluation in evaluations
        if evaluation["outcome"] == "mismatch"
    ]
    return result_document(
        observations,
        {
            "kind": "relational-assessment",
            "projectId": project,
            "planSha256": digest(plan),
            "evidenceResults": sorted(set(results)),
            "evaluations": evaluations,
            "ordering": "operator-asserted",
            "executionVerified": False,
        },
    )
