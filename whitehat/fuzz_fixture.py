"""Owned stateful and property-authorization twins for fuzz workflow evaluation."""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@contextmanager
def owned_fuzz_api(*, vulnerable: bool = False):
    state = {
        "owner": "alice",
        "quantity": 1,
        "phase": "draft",
        "requests": 0,
        "resets": 0,
        "vulnerable": vulnerable,
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def answer(self, status, value):
            raw = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)

        def principal(self):
            return {"Bearer owned-alice": "alice", "Bearer owned-bob": "bob"}.get(
                self.headers.get("Authorization")
            )

        def do_GET(self):
            state["requests"] += 1
            if self.principal() is None:
                return self.answer(401, {"error": "missing-identity"})
            if self.path == "/state":
                return self.answer(
                    200, {k: state[k] for k in ("owner", "quantity", "phase")}
                )
            return self.answer(404, {"error": "missing"})

        def do_POST(self):
            state["requests"] += 1
            if self.principal() != "alice":
                return self.answer(403, {"error": "denied"})
            if self.path == "/reset":
                state.update(
                    owner="alice", quantity=1, phase="draft", resets=state["resets"] + 1
                )
                return self.answer(200, {"reset": True})
            if self.path == "/approve":
                if state["phase"] != "draft":
                    return self.answer(409, {"error": "wrong-state"})
                state["phase"] = "approved"
                return self.answer(200, {"phase": "approved"})
            if self.path == "/publish":
                if state["phase"] != "approved" and not state["vulnerable"]:
                    return self.answer(409, {"error": "approval-required"})
                state["phase"] = "published"
                return self.answer(200, {"phase": "published"})
            return self.answer(404, {"error": "missing"})

        def do_PATCH(self):
            state["requests"] += 1
            if self.principal() is None:
                return self.answer(401, {"error": "missing-identity"})
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 <= length <= 65536:
                return self.answer(413, {"error": "too-large"})
            try:
                value = json.loads(self.rfile.read(length))
            except (ValueError, UnicodeError):
                return self.answer(400, {"error": "invalid-json"})
            if self.path != "/item" or not isinstance(value, dict):
                return self.answer(400, {"error": "invalid-request"})
            if "quantity" in value:
                quantity = value["quantity"]
                if type(quantity) is not int or not (
                    state["vulnerable"] or 0 <= quantity <= 10
                ):
                    return self.answer(422, {"error": "invalid-quantity"})
                state["quantity"] = quantity
            if (
                "owner" in value
                and state["vulnerable"]
                and value["owner"] in ("alice", "bob")
            ):
                state["owner"] = value["owner"]
            return self.answer(200, {"accepted": True})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
