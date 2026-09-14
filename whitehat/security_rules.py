"""Whitehat-authored Apache-2.0 rules and explanations. No downloaded rule packs."""

RULES_VERSION = "1"
RULES = [
    {"id": "whitehat.python.dynamic-eval", "languages": ["python"],
     "message": "Inspect whether untrusted input reaches eval.", "severity": "WARNING",
     "pattern": "eval($INPUT)", "metadata": {"cwe": "CWE-95"}},
    {"id": "whitehat.python.shell-command", "languages": ["python"],
     "message": "Inspect input control when shell=True is used.", "severity": "WARNING",
     "pattern": "subprocess.run(..., shell=True, ...)", "metadata": {"cwe": "CWE-78"}},
    {"id": "whitehat.python.pickle-loads", "languages": ["python"],
     "message": "Inspect the trust boundary before deserializing pickle data.", "severity": "WARNING",
     "pattern": "pickle.loads($INPUT)", "metadata": {"cwe": "CWE-502"}},
    {"id": "whitehat.javascript.dynamic-eval", "languages": ["javascript"],
     "message": "Inspect whether untrusted input reaches eval.", "severity": "WARNING",
     "pattern": "eval($INPUT)", "metadata": {"cwe": "CWE-95"}},
    {"id": "whitehat.javascript.shell-command", "languages": ["javascript"],
     "message": "Inspect input control before constructing a shell command.", "severity": "WARNING",
     "pattern": "require('child_process').exec($COMMAND, ...)", "metadata": {"cwe": "CWE-78"}},
]

EXPLANATIONS = {rule["id"]: rule["message"] + " A match is a review lead, not evidence of attacker control or impact." for rule in RULES}

SECRET_CONFIG = '''title = "Whitehat reviewed secret profile"
[extend]
useDefault = true

[[rules]]
id = "whitehat-synthetic-canary"
description = "Owned non-credential demonstration marker"
regex = 'WHITEHAT_DEMO_[A-Za-z0-9]{24}'
keywords = ["WHITEHAT_DEMO_"]
'''
