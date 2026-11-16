"""Read the MCP client config formats and turn their servers into lint targets.

Claude Desktop, Claude Code and Cursor use ``{"mcpServers": {...}}``; VS Code
uses ``{"servers": {...}}``. Entries are either a stdio server (``command``,
``args``, ``env``) or a remote one (``url``). Environment *values* are passed
to the child process and never printed; log helpers here redact them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "ClientConfigError",
    "HttpServer",
    "StdioServer",
    "load_client_config",
    "redact_env",
]


class ClientConfigError(ValueError):
    """The file is not a usable MCP client config."""


@dataclass(frozen=True)
class StdioServer:
    """A server the client starts as a child process."""

    name: str
    command: list[str]
    env: dict[str, str]


@dataclass(frozen=True)
class HttpServer:
    """A server the client reaches over HTTP."""

    name: str
    url: str


Server = StdioServer | HttpServer


def _table(data: dict[str, Any], path: Path) -> dict[str, Any]:
    for key in ("mcpServers", "servers"):
        table = data.get(key)
        if table is None:
            continue
        if not isinstance(table, dict):
            raise ClientConfigError(f"{path}: {key!r} must be an object")
        return table
    raise ClientConfigError(f'{path}: no "mcpServers" or "servers" object')


def _stdio(name: str, entry: dict[str, Any], path: Path) -> StdioServer | None:
    command = entry.get("command")
    if not isinstance(command, str) or not command.strip():
        return None
    args = entry.get("args", [])
    if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        raise ClientConfigError(f'{path}: server "{name}" args must be a list of strings')
    raw_env = entry.get("env", {})
    if not isinstance(raw_env, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in raw_env.items()
    ):
        raise ClientConfigError(f'{path}: server "{name}" env must be a string map')
    return StdioServer(name=name, command=[command, *args], env=dict(raw_env))


def load_client_config(path: Path) -> list[Server]:
    """Every server the config enables, in file order.

    Entries with ``"disabled": true`` are skipped. A server with neither
    ``command`` nor ``url`` is an error: silently linting nothing is worse than
    saying the entry is not understood.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ClientConfigError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ClientConfigError(f"{path} is not JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ClientConfigError(f"{path}: expected a JSON object")
    servers: list[Server] = []
    for name, entry in _table(data, path).items():
        if not isinstance(entry, dict):
            raise ClientConfigError(f'{path}: server "{name}" must be an object')
        if entry.get("disabled") is True:
            continue
        server = _stdio(name, entry, path)
        if server is not None:
            servers.append(server)
            continue
        url = entry.get("url")
        if isinstance(url, str) and url.strip():
            servers.append(HttpServer(name=name, url=url))
            continue
        raise ClientConfigError(f'{path}: server "{name}" has neither command nor url')
    if not servers:
        raise ClientConfigError(f"{path}: no enabled servers")
    return servers


def redact_env(text: str, env: dict[str, str]) -> str:
    """Replace every configured environment value in ``text`` with ``***``."""
    for value in sorted(env.values(), key=len, reverse=True):
        if value:
            text = text.replace(value, "***")
    return text
