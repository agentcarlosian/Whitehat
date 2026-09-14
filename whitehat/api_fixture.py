"""Owned mini-API. No external dependencies, real accounts, or production data."""

from __future__ import annotations

import json
import ssl
import threading
import uuid
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator


def fixture_schema() -> dict:
    item = {
        "type": "object",
        "required": ["id", "marker"],
        "properties": {
            "id": {"type": "string", "enum": ["demo"]},
            "marker": {"type": "string"},
        },
    }

    def response(description, schema):
        return {
            "description": description,
            "content": {"application/json": {"schema": schema}},
        }

    create = response("Created owned item", item)
    create["links"] = {
        "ReadCreated": {
            "operationId": "getItem",
            "parameters": {"id": "$response.body#/id"},
        },
        "DeleteCreated": {
            "operationId": "deleteItem",
            "parameters": {"id": "$response.body#/id"},
        },
    }
    deleted = response(
        "Deleted owned item",
        {"type": "object", "properties": {"deleted": {"type": "boolean"}}},
    )
    deleted["links"] = {
        "ReadDeleted": {
            "operationId": "getItem",
            "parameters": {"id": "$request.path.id"},
        }
    }
    return {
        "openapi": "3.0.3",
        "info": {"title": "Owned lifecycle fixture", "version": "1.0.0"},
        "paths": {
            "/items": {
                "post": {"operationId": "createItem", "responses": {"201": create}}
            },
            "/items/{id}": {
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "enum": ["demo"]},
                    }
                ],
                "get": {
                    "operationId": "getItem",
                    "responses": {
                        "200": response("Owned item", item),
                        "404": {"description": "Gone"},
                    },
                },
                "delete": {
                    "operationId": "deleteItem",
                    "responses": {"200": deleted, "404": {"description": "Gone"}},
                },
            },
        },
    }


@contextmanager
def owned_api(
    *, vulnerable: bool = False, tls: ssl.SSLContext | None = None
) -> Iterator[tuple[str, dict]]:
    state = {"items": {}, "requests": 0, "vulnerable": vulnerable, "nonce": uuid.uuid4().hex}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def answer(self, status, value):
            raw = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.close_connection = True

        def principal(self):
            auth = self.headers.get("Authorization", "")
            return {"Bearer owned-alice": "alice", "Bearer owned-bob": "bob"}.get(auth)

        def do_GET(self):
            state["requests"] += 1
            if self.path == "/.well-known/whitehat-fixture":
                return self.answer(200, {"nonce": state["nonce"]})
            if self.path == "/rate-limit":
                return self.answer(429, {"error": "slow down"})
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "https://unapproved.example.invalid/")
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                return
            user = self.principal()
            if user is None:
                return self.answer(401, {"error": "expired-or-missing"})
            if self.path == "/objects/shared":
                return self.answer(200, {"marker": "owned-shared", "owner": "shared"})
            if self.path == "/objects/private-a":
                if user != "alice" and not vulnerable:
                    return self.answer(403, {"error": "denied"})
                return self.answer(200, {"marker": "owned-private-a", "owner": "alice"})
            if self.path == "/items/demo" and "demo" in state["items"]:
                return self.answer(200, {"id": "demo", "marker": "owned-item"})
            return self.answer(404, {"error": "not-found"})

        def do_POST(self):
            state["requests"] += 1
            count = int(self.headers.get("Content-Length", "0"))
            if not 0 <= count <= 4096:
                return self.answer(413, {"error": "too-large"})
            self.rfile.read(count)
            if self.principal() != "alice":
                return self.answer(403, {"error": "denied"})
            if self.path == "/items":
                state["items"]["demo"] = True
                return self.answer(201, {"id": "demo", "marker": "owned-item"})
            return self.answer(404, {"error": "not-found"})

        def do_DELETE(self):
            state["requests"] += 1
            if self.principal() != "alice":
                return self.answer(403, {"error": "denied"})
            if self.path == "/items/demo" and "demo" in state["items"]:
                if not vulnerable:
                    state["items"].pop("demo", None)
                return self.answer(200, {"deleted": True})
            return self.answer(404, {"error": "not-found"})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    if tls is not None:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    server.daemon_threads = True
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    try:
        yield (
            f"{'https' if tls is not None else 'http'}://127.0.0.1:{server.server_port}",
            state,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
