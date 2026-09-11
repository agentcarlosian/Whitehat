from __future__ import annotations

import json
import os
import sys
import time


def _deny_side_effects(event: str, _arguments: tuple[object, ...]) -> None:
    if event.startswith("socket.") or event.startswith("subprocess."):
        raise RuntimeError("synthetic child denied a side effect")
    if event in {"os.exec", "os.posix_spawn", "os.spawn", "os.system"}:
        raise RuntimeError("synthetic child denied a side effect")


def main() -> int:
    sys.addaudithook(_deny_side_effects)
    request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    if (
        not isinstance(request, dict)
        or request.get("schemaVersion") != "whitehat-synthetic-request-v1"
    ):
        return 2
    message = request.get("message")
    repeat = request.get("repeat")
    delay_ms = request.get("delayMs")
    if (
        not isinstance(message, str)
        or not isinstance(repeat, int)
        or not isinstance(delay_ms, int)
    ):
        return 2
    if delay_ms:
        time.sleep(delay_ms / 1000)
    response = {
        "schemaVersion": "whitehat-synthetic-response-v1",
        "payload": message * repeat,
        "environmentKeys": sorted(os.environ),
    }
    sys.stdout.write(
        json.dumps(response, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
