"""Fixed, time-bounded DNS helper invoked only by the approved replay transport."""

import json
import re
import socket
import sys


def main() -> int:
    value = json.loads(sys.stdin.buffer.read(2048))
    if set(value) != {"host", "port"} or not re.fullmatch(
        r"[a-z0-9.-]{1,253}", value["host"]
    ):
        return 3
    if type(value["port"]) is not int or not 1 <= value["port"] <= 65535:
        return 3
    records = socket.getaddrinfo(value["host"], value["port"], type=socket.SOCK_STREAM)
    addresses = sorted({record[4][0] for record in records})
    if not 1 <= len(addresses) <= 16:
        return 3
    print(json.dumps({"addresses": addresses}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
