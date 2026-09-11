from __future__ import annotations

import platform
import sys
from typing import Any

from . import __version__


def doctor_result() -> dict[str, Any]:
    return {
        "schemaVersion": "whitehat-doctor-v1",
        "ok": True,
        "product": "Whitehat",
        "version": __version__,
        "runtime": {
            "implementation": platform.python_implementation(),
            "python": platform.python_version(),
            "supported": sys.version_info >= (3, 11),
            "system": platform.system(),
        },
        "capabilities": {
            "localDirectoryDiff": True,
            "localReadOnly": True,
            "localSyntheticExecution": False,
            "network": False,
            "credentials": False,
            "targetMutation": False,
            "externalContact": False,
            "submission": False,
        },
    }
