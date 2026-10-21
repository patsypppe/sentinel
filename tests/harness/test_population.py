"""The registry scan: listing, classification, politeness, and what it publishes.

A population scan touches servers nobody here owns, so the properties tested
hardest are the ones that make it safe to run: it never sends two requests to
one host at once, it never invokes a tool that is not annotated read-only, and
the summary it publishes names no server.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest
from conftest import _wait, free_port

from sentinel import population
from sentinel.population import (
    CLASS_AUTH,
    CLASS_CURRENT,
    CLASS_LEGACY,
    CLASS_UNREACHABLE,
    Result,
    Target,
)
from server.common import error, parse, result, serve_background

pytestmark = pytest.mark.unit

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _entry(
    name: str,
    url: str,
    *,
    kind: str = "streamable-http",
    status: str = "active",
    latest: bool = True,
    headers: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    remote: dict[str, Any] = {"type": kind, "url": url}
    if headers is not None:
        remote["headers"] = headers
    return {
        "server": {"name": name, "version": "1.0.0", "description": "d", "remotes": [remote]},
        "_meta": {population.OFFICIAL_META: {"status": status, "isLatest": latest}},
    }


# -- listing -----------------------------------------------------------------


def test_listing_keeps_only_latest_active_concrete_streamable_http() -> None:
    entries = [
        _entry("a/ok", "https://a.example/mcp"),
        _entry("a/sse", "https://a.example/sse", kind="sse"),
        _entry("a/templated", "https://{tenant}.example/mcp"),
        _entry("a/deprecated", "https://b.example/mcp", status="deprecated"),
        _entry("a/old", "https://c.example/mcp", latest=False),
        _entry("a/dup", "https://a.example/mcp"),
        _entry(
            "a/keyed",
            "https://d.example/mcp",
            headers=[{"name": "X-Api-Key", "isRequired": True}],
        ),
        {"server": "not a dict"},
    ]
    targets = population.targets_from_listing(entries)
    assert [(t.server, t.url, t.needs_headers) for t in targets] == [
        ("a/ok", "https://a.example/mcp", False),
        ("a/keyed", "https://d.example/mcp", True),
    ]


def test_fetch_listing_follows_the_cursor() -> None:
    import httpx

    pages = {
        None: {"servers": [_entry("a/1", "https://x/mcp")], "metadata": {"nextCursor": "c1"}},
        "c1": {"servers": [_entry("a/2", "https://y/mcp")], "metadata": {"nextCursor": ""}},
    }
    seen: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        seen.append(params)
        return httpx.Response(200, json=pages[params.get("cursor")])

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        entries = list(population.fetch_listing("https://registry.test", client=client))
    assert [e["server"]["name"] for e in entries] == ["a/1", "a/2"]
    assert all(p["version"] == "latest" for p in seen)


# -- politeness --------------------------------------------------------------


def test_one_host_is_never_scanned_concurrently() -> None:
    active: dict[str, int] = {}
    peak: dict[str, int] = {}
    lock = threading.Lock()

    def fake_scan(target: Target) -> Result:
        with lock:
            active[target.host] = active.get(target.host, 0) + 1
            peak[target.host] = max(peak.get(target.host, 0), active[target.host])
        time.sleep(0.02)
        with lock:
            active[target.host] -= 1
        return Result(
            server=target.server, version="1", url=target.url, host=target.host,
            classification=CLASS_UNREACHABLE, needs_headers=False,
        )

    targets = [
        Target(server=f"s/{h}{i}", version="1", url=f"https://{h}.example/{i}", needs_headers=False)
        for h in ("one", "two", "three")
        for i in range(5)
    ]
    results = population.scan_population(targets, concurrency=8, scanner=fake_scan)
    assert len(results) == 15
    assert peak == {"one.example": 1, "two.example": 1, "three.example": 1}


# -- classification against live stand-ins ----------------------------------


def _legacy_dispatch(handler: Any, body: bytes) -> tuple[int, dict[str, Any] | None]:
    payload = parse(body) or {}
    if payload.get("method") == "initialize":
        return 200, result(payload.get("id"), {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "serverInfo": {"name": "legacy", "version": "1"},
        })
    return 400, error(payload.get("id"), -32600, "Bad Request: no valid session ID provided")


def _auth_dispatch(handler: Any, body: bytes) -> tuple[int, dict[str, Any] | None]:
    return 401, None


@pytest.fixture
def stand_ins(conformant_endpoint: str) -> Iterator[dict[str, str]]:
    servers = []
    endpoints = {"current": conformant_endpoint}
    for name, dispatch in (("legacy", _legacy_dispatch), ("auth", _auth_dispatch)):
        port = free_port()
        httpd, _ = serve_background(dispatch, port, banner=name)
        servers.append(httpd)
        endpoints[name] = f"http://127.0.0.1:{port}/mcp"
    endpoints["unreachable"] = f"http://127.0.0.1:{free_port()}/mcp"
    _wait(endpoints["legacy"])
    yield endpoints
    for httpd in servers:
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.parametrize(
    ("which", "expected"),
    [
        ("current", CLASS_CURRENT),
        ("legacy", CLASS_LEGACY),
        ("auth", CLASS_AUTH),
        ("unreachable", CLASS_UNREACHABLE),
    ],
)
def test_classification(stand_ins: dict[str, str], which: str, expected: str) -> None:
    target = Target(server=f"t/{which}", version="1", url=stand_ins[which], needs_headers=False)
    res = population.scan_target(target, timeout=2.0)
    assert res.classification == expected, res.detail


def test_only_current_servers_are_graded(stand_ins: dict[str, str]) -> None:
    current = population.scan_target(
        Target(server="t/c", version="1", url=stand_ins["current"], needs_headers=False)
    )
    legacy = population.scan_target(
        Target(server="t/l", version="1", url=stand_ins["legacy"], needs_headers=False)
    )
    assert current.must and current.must["pass"] > 0
    assert current.must_failures == []
    assert current.skipped_for_safety > 0, "the conformant fixture's tools are unannotated"
    assert legacy.must == {}


# -- what gets published -----------------------------------------------------


def test_summary_names_no_server_and_its_percentages_add_up() -> None:
    def r(cls: str, url: str, fails: list[str] | None = None) -> Result:
        res = Result(
            server=f"secret/{url}", version="1", url=f"https://{url}.example/mcp",
            host=f"{url}.example", classification=cls, needs_headers=False,
            response_framing="json" if cls != CLASS_UNREACHABLE else "",
        )
        if cls == CLASS_CURRENT:
            res.must = {"pass": 1, "fail": len(fails or []), "not_applicable": 0,
                        "indeterminate": 0}
            res.must_failures = fails or []
        return res

    results = [
        r(CLASS_CURRENT, "a"),
        r(CLASS_CURRENT, "b", ["MCP/2026-07-28/MUST/result-type-present"]),
        r(CLASS_LEGACY, "c"),
        r(CLASS_LEGACY, "d"),
        r(CLASS_UNREACHABLE, "e"),
    ]
    summary = population.summarize(results, listed=5, scanned_at="2026-10-21")
    text = json.dumps(summary) + population.render_markdown(summary)
    for res in results:
        assert res.server not in text and res.url not in text and res.host not in text
    assert summary["classification"][CLASS_CURRENT] == 2
    assert summary["current"]["passMustGate"] == 1
    assert summary["current"]["passMustGatePct"] == 50.0
    assert summary["speakingCurrentRevisionPctOfAnswering"] == 50.0
    assert summary["current"]["mostFailedMust"][0]["servers"] == 1


def test_registry_scan_command_end_to_end(
    stand_ins: dict[str, str], tmp_path: pathlib.Path
) -> None:
    listing = tmp_path / "listing.json"
    listing.write_text(json.dumps({"servers": [
        _entry(f"t/{name}", url) for name, url in stand_ins.items()
    ]}))
    out = tmp_path / "out"
    proc = subprocess.run(
        [sys.executable, "-m", "sentinel.cli", "registry-scan",
         "--listing", str(listing), "--out-dir", str(out), "--timeout", "2"],
        capture_output=True, text=True, check=False, cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    summary = json.loads((out / "summary.json").read_text())
    assert summary["endpointsScanned"] == 4
    assert summary["classification"] == {
        CLASS_CURRENT: 1, CLASS_LEGACY: 1, CLASS_AUTH: 1, CLASS_UNREACHABLE: 1, "other": 0
    }
    lines = (out / "results.jsonl").read_text().splitlines()
    assert len(lines) == 4
    assert (out / "summary.md").read_text().startswith("# MCP registry conformance scan")
