"""Shared scaffolding for the two fixture servers.

`docs/HANDOFF.md` §9.5. The fixtures are the harness's own oracle: RECALL is the
fraction of seeded violations detected against the non-conformant one, and the
FALSE-POSITIVE RATE is the count of failures reported against the conformant
one, which must be zero.

They are deliberately built on `http.server` from the standard library and
nothing else. A fixture that shared code with the harness would let a bug in the
shared part hide itself from both sides.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

PROTOCOL = "2026-07-28"
LEGACY = "2025-11-25"

KEY_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
KEY_SERVER_INFO = "io.modelcontextprotocol/serverInfo"


class Handler(BaseHTTPRequestHandler):
    """Routes POST /mcp to `dispatch`, which each fixture defines."""

    #: Set by serve().
    dispatch: Any = None
    server_version = "sentinel-fixture/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        """Silence the default stderr access log; a scan makes hundreds of
        requests and the noise buries the fixture's own output."""

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""

        status, payload = type(self).dispatch(self, body)

        encoded = json.dumps(payload).encode() if payload is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        if encoded:
            self.wfile.write(encoded)

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok\n")


def parse(body: bytes) -> dict[str, Any] | None:
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def result(request_id: Any, payload: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": payload}


def error(request_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": err}


def serve(dispatch: Any, port: int, *, banner: str) -> ThreadingHTTPServer:
    """Start a fixture on `port` and return the server."""
    handler = type("BoundHandler", (Handler,), {"dispatch": dispatch})
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    print(f"{banner} on http://127.0.0.1:{port}/mcp", flush=True)
    return httpd


def serve_forever(dispatch: Any, port: int, *, banner: str) -> None:
    httpd = serve(dispatch, port, banner=banner)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def serve_background(
    dispatch: Any, port: int, *, banner: str
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    """Start a fixture on a background thread, for tests."""
    httpd = serve(dispatch, port, banner=banner)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread
