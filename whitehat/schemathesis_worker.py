"""Internal owned-fixture profile. No caller-supplied schema, code, or credentials."""

from __future__ import annotations

import importlib.metadata
import json
import platform
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from whitehat.api_fixture import fixture_schema  # noqa: E402
from whitehat.http_evidence import import_capture  # noqa: E402
from whitehat.reports import read_bytes, parse_json  # noqa: E402


def main() -> int:
    request = json.loads(sys.stdin.buffer.read(2048))
    if set(request) != {"origin", "nonce"} or not re.fullmatch(
        r"http://127\.0\.0\.1:[0-9]{1,5}", request["origin"]
    ):
        return 3
    if not re.fullmatch(r"[a-f0-9]{32}", request["nonce"]):
        return 3
    port = urlsplit(request["origin"]).port
    if sys.platform == "win32":
        # Avoid platform.win32_ver's shell fallback in the constrained child.
        # Version metadata is available from the in-process Windows API.
        def windows_version(*_args, **_kwargs):
            version = sys.getwindowsversion()
            return (
                str(version.major),
                f"{version.major}.{version.minor}.{version.build}",
                version.service_pack,
                "",
            )

        platform.win32_ver = windows_version

        def windows_command_version(*_args, **_kwargs):
            release, version, _, _ = windows_version()
            return ("Windows", release, version)

        platform._syscmd_ver = windows_command_version
    attempts = 0

    def guard(event, args):
        nonlocal attempts
        if event == "socket.connect":
            address = args[1]
            if not isinstance(address, tuple) or address[:2] != ("127.0.0.1", port):
                raise RuntimeError("owned profile refused network destination")
            attempts += 1
            if attempts > 80:
                raise RuntimeError("owned profile connection budget exhausted")
        elif event == "socket.getaddrinfo" and (args[0], args[1]) != (
            "127.0.0.1",
            port,
        ):
            raise RuntimeError("owned profile refused DNS lookup")
        elif event in {
            "socket.sendto",
            "subprocess.Popen",
            "os.system",
            "os.exec",
            "os.posix_spawn",
            "os.spawn",
        }:
            raise RuntimeError("owned profile refused process/datagram action")

    sys.addaudithook(guard)
    import http.client

    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
    try:
        connection.request("GET", "/.well-known/whitehat-fixture")
        response = connection.getresponse()
        if response.status != 200 or json.loads(response.read(1024)) != {
            "nonce": request["nonce"]
        }:
            return 3
    finally:
        connection.close()
    from click.testing import CliRunner
    from schemathesis.cli import schemathesis

    if importlib.metadata.version("schemathesis") != "4.27.1":
        return 3
    root = Path.cwd()
    (root / "schema.json").write_text(json.dumps(fixture_schema()), encoding="utf-8")
    (root / "config.toml").write_text("", encoding="utf-8")
    arguments = [
        "--config-file",
        str(root / "config.toml"),
        "--no-color",
        "run",
        str(root / "schema.json"),
        "--url",
        request["origin"],
        "--header",
        "Authorization: Bearer owned-alice",
        "--phases",
        "stateful",
        "--max-examples",
        "1",
        "--max-time",
        "2",
        "--seed",
        "1",
        "--no-shrink",
        "--workers",
        "1",
        "--checks",
        "not_a_server_error,response_schema_conformance,use_after_free,ensure_resource_availability",
        "--rate-limit",
        "10/s",
        "--max-redirects",
        "0",
        "--request-retries",
        "0",
        "--request-timeout",
        "1",
        "--report",
        "har,json",
        "--report-har-path",
        str(root / "run.har"),
        "--report-json-path",
        str(root / "run.json"),
    ]
    completed = CliRunner().invoke(schemathesis, arguments)
    report = parse_json(read_bytes(root / "run.json", 1024 * 1024))
    if (
        completed.exit_code not in (0, 1)
        or not report.get("complete")
        or report.get("errors")
    ):
        print(
            json.dumps(
                {
                    "error": "owned Schemathesis run was incomplete",
                    "exitCode": completed.exit_code,
                }
            )
        )
        return 3
    evidence = import_capture(
        str(root / "run.har"),
        "owned-api",
        identity="alice",
        object_id="owned-item",
        operation="generated-lifecycle",
        selected=["/marker"],
    )
    print(
        json.dumps(
            {
                "schemaVersion": "whitehat-schemathesis-run-v1",
                "toolVersion": "4.27.1",
                "exitCode": completed.exit_code,
                "complete": True,
                "connectionAttempts": attempts,
                "failureCount": len(report.get("failures", [])),
                "phases": report.get("phases"),
                "testCases": report.get("test_cases"),
                "evidence": evidence,
            },
            ensure_ascii=True,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
