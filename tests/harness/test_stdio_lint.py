"""`sentinel lint --command` lints a server that only speaks stdio."""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap

import pytest

pytestmark = pytest.mark.unit

SERVER = textwrap.dedent(
    """
    import json, sys
    TOOLS = [
        {"name": "lookup_order", "description": "Look up an order by its id.",
         "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}}},
    ]
    print("starting up", flush=True)  # a banner on stdout is not a reply
    for line in sys.stdin:
        msg = json.loads(line)
        if "id" not in msg:
            continue
        if msg["method"] == "initialize":
            result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}}
        elif msg["method"] == "tools/list":
            result = {"tools": TOOLS}
        else:
            print(json.dumps({"jsonrpc": "2.0", "id": msg["id"],
                              "error": {"code": -32601, "message": "no"}}), flush=True)
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
    """
)


def test_lint_reads_a_stdio_servers_manifest_and_reports_the_undescribed_parameter(
    tmp_path: pytest.TempPathFactory,
) -> None:
    script = tmp_path / "server.py"  # type: ignore[operator]
    script.write_text(SERVER)
    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel.cli",
            "lint",
            "--command",
            f"{sys.executable} {script}",
            "--format",
            "json",
            "--timeout",
            "10",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    report = json.loads(done.stdout)
    outcome = {f["ruleId"]: f["outcome"] for f in report["findings"]}
    assert outcome["SENTINEL/STYLE/parameters-are-described"] == "fail"
    assert outcome["MCP/2026-07-28/SHOULD/tool-names-well-formed"] == "pass"
    assert done.returncode == 1
