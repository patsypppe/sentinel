"""Parsing MCP client configs for `toolgauge lint --client-config`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from toolgauge.client_config import (
    ClientConfigError,
    HttpServer,
    StdioServer,
    load_client_config,
    redact_env,
)

pytestmark = pytest.mark.unit


def write_config(tmp_path: Path, payload: dict[str, Any]) -> Path:
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(payload))
    return path


def test_reads_claude_and_cursor_mcp_servers(tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        {
            "mcpServers": {
                "memory": {
                    "command": "npx",
                    "args": ["-y", "server-memory"],
                    "env": {"TOKEN": "x"},
                },
                "remote": {"url": "https://example.test/mcp"},
            }
        },
    )
    assert load_client_config(path) == [
        StdioServer("memory", ["npx", "-y", "server-memory"], {"TOKEN": "x"}),
        HttpServer("remote", "https://example.test/mcp"),
    ]


def test_reads_vscode_servers_and_skips_disabled_entries(tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        {
            "servers": {
                "off": {"command": "npx", "args": ["x"], "disabled": True},
                "on": {"type": "stdio", "command": "uvx", "args": ["pkg"]},
            }
        },
    )
    assert load_client_config(path) == [StdioServer("on", ["uvx", "pkg"], {})]


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({}, 'no "mcpServers" or "servers"'),
        ({"mcpServers": []}, "must be an object"),
        ({"mcpServers": {"x": "npx"}}, "must be an object"),
        ({"mcpServers": {"x": {"args": []}}}, "neither command nor url"),
        ({"mcpServers": {"x": {"command": "npx", "args": "x"}}}, "args must be a list"),
        ({"mcpServers": {"x": {"command": "npx", "env": {"K": 1}}}}, "env must be a string map"),
        ({"mcpServers": {"x": {"command": "npx", "disabled": True}}}, "no enabled servers"),
    ],
)
def test_rejects_entries_it_cannot_run(
    tmp_path: Path, payload: dict[str, Any], message: str
) -> None:
    with pytest.raises(ClientConfigError, match=message):
        load_client_config(write_config(tmp_path, payload))


def test_rejects_files_that_are_not_json_or_missing(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{")
    with pytest.raises(ClientConfigError, match="not JSON"):
        load_client_config(broken)
    with pytest.raises(ClientConfigError, match="cannot read"):
        load_client_config(tmp_path / "missing.json")
    array = tmp_path / "array.json"
    array.write_text("[]")
    with pytest.raises(ClientConfigError, match="expected a JSON object"):
        load_client_config(array)


def test_redacts_every_configured_value() -> None:
    env = {"SHORT": "abc", "LONG": "abcdef", "EMPTY": ""}
    assert redact_env("token abcdef and abc", env) == "token *** and ***"
    assert redact_env("nothing to hide", env) == "nothing to hide"
