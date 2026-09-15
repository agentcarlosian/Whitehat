"""Internal Atheris worker for fixed reviewed parser and owned profiles."""

from __future__ import annotations

import atexit
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main() -> int:
    from whitehat.reports import ReportError, parse_json

    request = parse_json(sys.stdin.buffer.read(256 * 1024))
    if not isinstance(request, dict) or set(request) != {
        "profile",
        "runs",
        "seed",
        "corpus",
    }:
        return 3
    if request["profile"] not in {
        "capture-parser",
        "request-parser",
        "owned-fixed",
        "owned-broken",
    }:
        return 3
    if type(request["runs"]) is not int or not 1 <= request["runs"] <= 10000:
        return 3
    import importlib.metadata

    if importlib.metadata.version("atheris") != "3.1.0":
        return 3
    import atheris

    with atheris.instrument_imports():
        from whitehat.http_evidence import capture_entries
        from whitehat.http_replay import prepared_request

    root = Path.cwd()
    corpus = root / "corpus"
    corpus.mkdir()
    for index, encoded in enumerate(request["corpus"]):
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) > 8192:
            return 3
        (corpus / f"seed-{index}").write_bytes(raw)
    state = {"callbacks": 0, "failure": None}
    emitted = False

    def finish():
        nonlocal emitted
        if not emitted:
            emitted = True
            print(
                "WHITEHAT_RESULT="
                + json.dumps(
                    {
                        "schemaVersion": "whitehat-atheris-worker-v1",
                        "toolVersion": "3.1.0",
                        "profile": request["profile"],
                        **state,
                    },
                    sort_keys=True,
                ),
                flush=True,
            )

    atexit.register(finish)

    def guard(event, _args):
        if event.startswith("socket.") or event in {
            "subprocess.Popen",
            "os.system",
            "os.exec",
            "os.posix_spawn",
            "os.spawn",
        }:
            raise RuntimeError("source profile refused network/process action")

    sys.addaudithook(guard)

    @atheris.instrument_func
    def fuzz_one(data):
        state["callbacks"] += 1
        try:
            if request["profile"] == "capture-parser":
                capture_entries(data)
            elif request["profile"] == "request-parser":
                prepared_request(parse_json(data))
            else:
                # Authored parser twin: documented negative quantities must be rejected.
                value = parse_json(data)
                if isinstance(value, dict) and type(value.get("quantity")) is int:
                    accepted = (
                        value["quantity"] >= 0 or request["profile"] == "owned-broken"
                    )
                    if accepted and value["quantity"] < 0:
                        raise AssertionError("owned-negative-quantity")
        except ReportError:
            pass  # Explicit parser rejection is an expected result, not a crash.
        except Exception as exc:
            state["failure"] = {
                "class": type(exc).__name__,
                "dataBase64": base64.b64encode(data).decode("ascii"),
            }
            finish()
            raise SystemExit(0)
        if state["callbacks"] >= request["runs"]:
            finish()
            raise SystemExit(0)

    atheris.Setup(
        [
            "whitehat-source",
            str(corpus),
            "-seed=" + str(request["seed"]),
            "-max_len=8192",
            "-rss_limit_mb=512",
            "-timeout=2",
            "-max_total_time=15",
            "-verbosity=0",
            "-atheris_runs=" + str(request["runs"]),
        ],
        fuzz_one,
    )
    atheris.Fuzz()
    finish()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
