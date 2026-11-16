"""`toolgauge lint --client-config` lints every server in a client config."""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

SERVER = textwrap.dedent(
    """
    import json, os, sys
    open(os.environ["TOOLGAUGE_TEST_MARKER"], "w").write("started")
    TOOLS = [
        {"name": "lookup_order", "description": "Look up an order by its id.",
         "inputSchema": {"type": "object", "properties": {"filters": {"type": "object"}}}},
    ]
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


def run_lint(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "toolgauge.cli", "lint", *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


@pytest.fixture
def client_config(tmp_path: Path) -> Path:
    script = tmp_path / "server.py"
    script.write_text(SERVER)
    marker = tmp_path / "started.txt"
    config = {
        "mcpServers": {
            "alpha": {
                "command": sys.executable,
                "args": [str(script)],
                "env": {"TOOLGAUGE_TEST_MARKER": str(marker), "SECRET": "hunter2"},
            },
            "beta": {
                "command": sys.executable,
                "args": [str(script)],
                "env": {"TOOLGAUGE_TEST_MARKER": str(marker)},
            },
        }
    }
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(config))
    return path


def test_lints_every_server_and_never_prints_env(client_config: Path) -> None:
    done = run_lint("--client-config", str(client_config), "--format", "json", "--timeout", "10")
    assert "hunter2" not in done.stdout
    assert "hunter2" not in done.stderr
    payload = json.loads(done.stdout)
    assert payload["clientConfig"] == str(client_config)
    assert [server["name"] for server in payload["servers"]] == ["alpha", "beta"]
    for server in payload["servers"]:
        assert server["kind"] == "stdio"
        outcomes = {f["ruleId"]: f["outcome"] for f in server["report"]["findings"]}
        assert outcomes["TOOLGAUGE/STYLE/parameters-are-described"] == "fail"
    assert done.returncode == 1
    # Both child processes really started with the configured env.
    assert (client_config.parent / "started.txt").read_text() == "started"


def test_text_output_labels_each_server(client_config: Path) -> None:
    done = run_lint("--client-config", str(client_config), "--format", "text", "--timeout", "10")
    assert "== alpha (stdio) ==" in done.stdout
    assert "== beta (stdio) ==" in done.stdout
    assert "hunter2" not in done.stdout


def test_a_broken_config_exits_2_without_a_traceback(tmp_path: Path) -> None:
    path = tmp_path / "mcp.json"
    path.write_text('{"mcpServers": {}}')
    done = run_lint("--client-config", str(path))
    assert done.returncode == 2
    assert "no enabled servers" in done.stderr
    assert "Traceback" not in done.stderr


def test_client_config_rejects_formats_it_cannot_merge(client_config: Path) -> None:
    done = run_lint("--client-config", str(client_config), "--format", "sarif")
    assert done.returncode == 2
    assert "supports --format text, markdown or json" in done.stderr
