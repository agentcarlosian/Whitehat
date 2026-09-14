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
            "localDependencyComparison": True,
            "localDirectoryDiff": True,
            "localFileInventory": True,
            "localReadOnly": True,
            "localResultStorage": True,
            "localReviewNotes": True,
            "localSyntheticExecution": True,
            "network": True,
            "externalNetwork": True,
            "loopbackNetworkExecution": True,
            "networkSessionValidation": True,
            "releaseAudit": True,
            "credentials": True,
            "ruffScannerAdapter": True,
            "opengrepScannerAdapter": True,
            "secretScannerAdapter": True,
            "researchReportImports": True,
            "researchBaselineComparison": True,
            "researchWorkspace": True,
            "markdownResearchExport": True,
            "httpEvidenceImports": True,
            "httpAuthorizationComparison": True,
            "sessionBoundHttpReplay": True,
            "openApiInventory": True,
            "oasdiffAdapter": True,
            "ownedSchemathesisProfile": True,
            "targetMutation": False,
            "externalContact": False,
            "submission": False,
        },
    }
