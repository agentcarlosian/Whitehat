"""Newly authored, fixed source-analysis profiles and review guidance."""

from .security_rules import EXPLANATIONS, RULES, RULES_VERSION


def _source():
    return {
        "patterns": [
            {
                "pattern-either": [
                    {"pattern": "$REQ.query"},
                    {"pattern": "$REQ.body"},
                    {"pattern": "$REQ.params"},
                ]
            },
            {"pattern-inside": "$APP.$METHOD(..., ($REQ, $RES) => { ... })"},
            {
                "metavariable-regex": {
                    "metavariable": "$METHOD",
                    "regex": "^(get|post|put|patch|delete|all|use)$",
                }
            },
            {
                "pattern-either": [
                    {
                        "pattern-inside": 'import $EXPRESS from "express"; ... const $APP = $EXPRESS(...); ...'
                    },
                    {
                        "pattern-inside": 'const $EXPRESS = require("express"); ... const $APP = $EXPRESS(...); ...'
                    },
                ]
            },
        ],
        "exact": True,
    }


def _imported_sinks(module, member):
    result = []
    for prefix in ("", "node:"):
        for call, binding in (
            ("$CALL", f'import {{ {member} as $CALL }} from "{prefix}{module}"; ...'),
            (member, f'import {{ {member} }} from "{prefix}{module}"; ...'),
            (f"$MODULE.{member}", f'import * as $MODULE from "{prefix}{module}"; ...'),
            (f"$MODULE.{member}", f'const $MODULE = require("{prefix}{module}"); ...'),
        ):
            result.append(
                {
                    "patterns": [
                        {"pattern": f"{call}($INPUT, ...)"},
                        {"pattern-inside": binding},
                        {"focus-metavariable": "$INPUT"},
                    ]
                }
            )
    return result


EXPRESS_RULES = [
    {
        "id": "whitehat.express.request-to-shell",
        "languages": ["javascript", "typescript"],
        "mode": "taint",
        "message": "Review Express request input reaching a shell command.",
        "severity": "WARNING",
        "pattern-sources": [_source()],
        "pattern-sinks": _imported_sinks("child_process", "exec"),
        "metadata": {"cwe": "CWE-78"},
    },
    {
        "id": "whitehat.express.request-to-eval",
        "languages": ["javascript", "typescript"],
        "mode": "taint",
        "message": "Review Express request input reaching dynamic evaluation.",
        "severity": "WARNING",
        "pattern-sources": [_source()],
        "pattern-sinks": [
            {
                "patterns": [
                    {"pattern": "eval($INPUT)"},
                    {"focus-metavariable": "$INPUT"},
                ]
            }
        ],
        "metadata": {"cwe": "CWE-95"},
    },
    {
        "id": "whitehat.express.request-to-file",
        "languages": ["javascript", "typescript"],
        "mode": "taint",
        "message": "Review Express request input reaching a file-read path.",
        "severity": "WARNING",
        "pattern-sources": [_source()],
        "pattern-sinks": _imported_sinks("fs", "readFile"),
        "metadata": {"cwe": "CWE-22"},
    },
]

EXPRESS_EXPLANATIONS = {
    rule["id"]: rule["message"]
    + " Engine-reported flow; confirm route reachability, input control, guards and impact independently."
    for rule in EXPRESS_RULES
}

PROFILES = {
    "basic": {
        "rules": RULES,
        "rulesVersion": RULES_VERSION,
        "languages": {".py": "python", ".js": "javascript"},
        "explanations": EXPLANATIONS,
    },
    "express-typescript": {
        "rules": EXPRESS_RULES,
        "rulesVersion": "express-typescript-v1",
        "languages": {".js": "javascript", ".ts": "typescript"},
        "explanations": EXPRESS_EXPLANATIONS,
    },
}
