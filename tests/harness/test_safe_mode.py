"""Safe mode: scanning a server you do not own must not change it.

Three rules prove a MUST by calling a tool the server advertises (an
`Mcp-Name` rule needs a real name to omit the header from). Against your own
server that is fine; against someone else's, a `tools/call` with empty
arguments can still do something. `--safe` sends such a call only when the
tool's own annotations promise it is read-only, and every rule it declines is
reported INDETERMINATE with a reason that says so -- never a pass.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Iterator
from typing import Any

import pytest
from conftest import _wait, free_port

from sentinel.catalog.base import Outcome
from sentinel.grade import SAFE_MODE_DETAIL, run_scan
from sentinel.probe.client import is_read_only
from server import conformant
from server.common import serve_background

pytestmark = pytest.mark.unit


class _Recorder:
    """Wraps a fixture's dispatch and remembers every tools/call name it served."""

    def __init__(self, tools: list[dict[str, Any]]) -> None:
        self.called: list[str] = []
        self.tools = tools

    def __call__(self, handler: Any, body: bytes) -> tuple[int, dict[str, Any] | None]:
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = None
        if isinstance(payload, dict) and payload.get("method") == "tools/call":
            name = (payload.get("params") or {}).get("name")
            if isinstance(name, str):
                self.called.append(name)
        original = conformant.TOOLS
        conformant.TOOLS[:] = self.tools
        try:
            return conformant.dispatch(handler, body)
        finally:
            conformant.TOOLS[:] = original


def _serve(tools: list[dict[str, Any]]) -> Iterator[tuple[str, _Recorder]]:
    recorder = _Recorder(tools)
    port = free_port()
    httpd, _ = serve_background(recorder, port, banner="safe-mode test")
    endpoint = f"http://127.0.0.1:{port}/mcp"
    _wait(endpoint)
    try:
        yield endpoint, recorder
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture
def unannotated() -> Iterator[tuple[str, _Recorder]]:
    yield from _serve(copy.deepcopy(conformant.TOOLS))


@pytest.fixture
def read_only() -> Iterator[tuple[str, _Recorder]]:
    tools = copy.deepcopy(conformant.TOOLS)
    for tool in tools:
        tool["annotations"] = {"readOnlyHint": True, "destructiveHint": False}
    yield from _serve(tools)


def _advertised(recorder: _Recorder) -> set[str]:
    return {t["name"] for t in recorder.tools}


def test_safe_mode_never_invokes_an_unannotated_advertised_tool(
    unannotated: tuple[str, _Recorder],
) -> None:
    endpoint, recorder = unannotated
    report = run_scan(endpoint, safe=True)

    assert not set(recorder.called) & _advertised(recorder)
    assert report.safe
    assert report.skipped_for_safety, "the rules that need a real tool must say they were skipped"
    for finding in report.skipped_for_safety:
        assert finding.outcome is Outcome.INDETERMINATE
        assert finding.result.detail.startswith(SAFE_MODE_DETAIL)
        assert "unreachable" not in finding.result.detail


def test_safe_mode_skips_rules_but_never_turns_one_into_a_failure(
    unannotated: tuple[str, _Recorder],
) -> None:
    endpoint, _ = unannotated
    full = run_scan(endpoint)
    safe = run_scan(endpoint, safe=True)

    full_failures = {f.rule.id for f in full.by_outcome(Outcome.FAIL)}
    safe_failures = {f.rule.id for f in safe.by_outcome(Outcome.FAIL)}
    assert safe_failures <= full_failures


def test_without_safe_mode_the_same_rules_do_invoke_the_tool(
    unannotated: tuple[str, _Recorder],
) -> None:
    endpoint, recorder = unannotated
    run_scan(endpoint)
    assert set(recorder.called) & _advertised(recorder), (
        "if the unsafe scan never calls a real tool, the safe-mode test above proves nothing"
    )


def test_safe_mode_does_invoke_a_tool_annotated_read_only(
    read_only: tuple[str, _Recorder],
) -> None:
    endpoint, recorder = read_only
    report = run_scan(endpoint, safe=True)

    assert set(recorder.called) & _advertised(recorder)
    assert not report.skipped_for_safety


@pytest.mark.parametrize(
    ("annotations", "expected"),
    [
        (None, False),
        ({}, False),
        ({"readOnlyHint": True}, True),
        ({"readOnlyHint": True, "destructiveHint": False}, True),
        ({"readOnlyHint": True, "destructiveHint": True}, False),
        ({"readOnlyHint": "true"}, False),
        ({"destructiveHint": False}, False),
    ],
)
def test_read_only_requires_an_explicit_promise(
    annotations: dict[str, Any] | None, expected: bool
) -> None:
    tool: dict[str, Any] = {"name": "t"}
    if annotations is not None:
        tool["annotations"] = annotations
    assert is_read_only(tool) is expected
