"""Fixture servers, started in-process for the harness's own test suite."""

from __future__ import annotations

import socket
import time
from collections.abc import Iterator

import httpx
import pytest

from server.common import serve_background
from server.conformant import BEHAVIOUR as CONFORMANT_BEHAVIOUR
from server.conformant import dispatch as conformant_dispatch
from server.nonconformant import BEHAVIOUR as NONCONFORMANT_BEHAVIOUR
from server.nonconformant import dispatch as nonconformant_dispatch


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait(endpoint: str, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            # No Mcp-Name: the header table defines it for tools/call,
            # resources/read and prompts/get only, and a conformant server may
            # refuse one sent anywhere else.
            httpx.post(endpoint, json={"jsonrpc": "2.0", "id": 1, "method": "server/discover"},
                       headers={"Mcp-Method": "server/discover"},
                       timeout=1.0)
            return
        except httpx.RequestError:
            time.sleep(0.05)
    raise RuntimeError(f"{endpoint} never became ready")


@pytest.fixture(scope="session")
def nonconformant_endpoint() -> Iterator[str]:
    port = free_port()
    # **BEHAVIOUR carries the faults that live outside `dispatch` -- the response
    # Content-Type and what a bare GET gets. Without it the in-process fixture
    # would be a strictly more conformant server than the one `sentinel fixture
    # serve` starts, and two seeded violations would go undetectable here.
    httpd, _ = serve_background(
        nonconformant_dispatch, port, banner="test nonconformant", **NONCONFORMANT_BEHAVIOUR
    )
    endpoint = f"http://127.0.0.1:{port}/mcp"
    _wait(endpoint)
    yield endpoint
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture(scope="session")
def conformant_endpoint() -> Iterator[str]:
    port = free_port()
    httpd, _ = serve_background(
        conformant_dispatch, port, banner="test conformant", **CONFORMANT_BEHAVIOUR
    )
    endpoint = f"http://127.0.0.1:{port}/mcp"
    _wait(endpoint)
    yield endpoint
    httpd.shutdown()
    httpd.server_close()
