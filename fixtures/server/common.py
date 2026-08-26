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

#: The Content-Type a JSON-RPC reply is labelled with. `text/event-stream` is
#: the only other value the specification permits, so a fixture answering
#: anything else is seeding a violation rather than making a style choice.
JSON_CONTENT_TYPE = "application/json"

#: What a bare GET or DELETE on the endpoint gets. Both belonged to the
#: transport this revision replaced and now have nothing to do.
METHOD_NOT_ALLOWED = 405


class Handler(BaseHTTPRequestHandler):
    """Routes POST /mcp to `dispatch`, which each fixture defines.

    The two class attributes below are the HTTP-layer knobs a fixture cannot
    reach from inside `dispatch`, because they are decided before or outside a
    JSON-RPC body. `serve()` overrides them per fixture; the defaults here are
    the conformant answers.
    """

    #: Set by serve().
    dispatch: Any = None
    response_content_type: str = JSON_CONTENT_TYPE
    bare_method_status: int = METHOD_NOT_ALLOWED
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
        self.send_header("Content-Type", type(self).response_content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        if encoded:
            self.wfile.write(encoded)

    def _legacy_method(self) -> None:
        """GET and DELETE: the previous transport's stream-open and
        session-close, which this revision leaves with nothing to do."""
        status = type(self).bare_method_status
        body = b"" if status == METHOD_NOT_ALLOWED else b"ok\n"
        self.send_response(status)
        if status == METHOD_NOT_ALLOWED:
            self.send_header("Allow", "POST")
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self) -> None:
        self._legacy_method()

    def do_DELETE(self) -> None:
        self._legacy_method()


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


def serve(dispatch: Any, port: int, *, banner: str, **behaviour: Any) -> ThreadingHTTPServer:
    """Start a fixture on `port` and return the server.

    `behaviour` overrides `Handler`'s HTTP-layer class attributes —
    `response_content_type` and `bare_method_status`. Each fixture publishes its
    own as a `BEHAVIOUR` dict, so a violation that lives outside the JSON-RPC
    body is still declared in the fixture that seeds it rather than here.
    """
    handler = type("BoundHandler", (Handler,), {"dispatch": dispatch, **behaviour})
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    print(f"{banner} on http://127.0.0.1:{port}/mcp", flush=True)
    return httpd


def serve_forever(dispatch: Any, port: int, *, banner: str, **behaviour: Any) -> None:
    httpd = serve(dispatch, port, banner=banner, **behaviour)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def serve_background(
    dispatch: Any, port: int, *, banner: str, **behaviour: Any
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    """Start a fixture on a background thread, for tests."""
    httpd = serve(dispatch, port, banner=banner, **behaviour)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread
