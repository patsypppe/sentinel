"""A server that has not migrated is still linted: manifest rules run over a legacy session."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from sentinel.catalog.base import REGISTRY, Outcome
from sentinel.grade import run_scan

pytestmark = pytest.mark.unit

TOOLS = [
    {
        "name": "good_tool",
        "description": "Look up an order by its id.",
        "inputSchema": {"type": "object"},
    },
    {
        "name": "bad name!",
        "description": "Has an illegal character in its name.",
        "inputSchema": {"type": "object"},
    },
]


class _LegacyHandler(BaseHTTPRequestHandler):
    """Speaks only the previous revision: initialize first, then requests under a session."""

    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        method, rid = body.get("method"), body.get("id")
        headers = {"Content-Type": "application/json"}
        if method == "initialize":
            headers["Mcp-Session-Id"] = "abc123"
            reply = {"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2025-11-25"}}
        elif method == "tools/list" and self.headers.get("Mcp-Session-Id") == "abc123":
            reply = {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
        elif rid is None:
            self.send_response(202)
            self.end_headers()
            return
        else:
            reply = {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "no"}}
        data = json.dumps(reply).encode()
        self.send_response(200)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def legacy_endpoint() -> Iterator[str]:
    server = HTTPServer(("127.0.0.1", 0), _LegacyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/mcp"
    server.shutdown()


def test_manifest_rules_run_against_a_server_that_has_not_migrated(legacy_endpoint: str) -> None:
    report = run_scan(legacy_endpoint)
    assert report.generation == "legacy"
    outcome = {f.rule.id: f.outcome for f in report.findings}
    assert outcome["MCP/2026-07-28/SHOULD/tool-names-well-formed"] is Outcome.FAIL
    # The current-protocol rules still say the server is not on the current protocol.
    assert outcome["MCP/2026-07-28/MUST/discover-implemented"] is Outcome.FAIL
    assert "MCP/2026-07-28/SHOULD/tool-names-well-formed" in {r.id for r in REGISTRY.all()}
