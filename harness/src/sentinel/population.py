"""Scanning the population: every remote server in the official MCP registry.

One scan of one server says whether *that* server is conformant. This module
answers the question nobody had measured: how far the servers people actually
publish have got with the 2026-07-28 revision, and what they get wrong.

How it stays a good citizen on servers it does not own:

* **Safe mode, always.** Every scan runs with `safe=True`: no tool the server
  has not annotated read-only is ever invoked. The rules that need one report
  INDETERMINATE, and the summary counts them.
* **One request at a time per host.** Servers are grouped by host and each host
  is scanned serially; concurrency is across hosts only, so a platform hosting
  hundreds of servers never sees more than one of these connections at once.
* **No retries, short timeouts.** A request that fails is recorded, not repeated.
* **Identified.** Every request carries a User-Agent naming this repository.
* **Aggregates are published, per-server results are not.** `summarize` produces
  counts only; the per-server JSONL stays with whoever ran the scan, so a
  finding can be disclosed to its maintainer before anyone else reads it.

Classification happens before grading, because grading a server that does not
speak this revision against this revision's MUSTs measures nothing useful:

* ``2026-07-28``  -- answered `server/discover`. Graded against the full catalog.
* ``legacy``      -- refused `server/discover` but completed a 2025-11-25
  `initialize`. Not graded: it has not migrated, and that is the finding.
* ``auth``        -- HTTP 401/403 before any JSON-RPC answer.
* ``unreachable`` -- no HTTP response, or HTTP 404/5xx.
* ``other``       -- answered, but neither handshake succeeded.
"""

from __future__ import annotations

import concurrent.futures
import json
import time
import urllib.parse
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Iterator
from dataclasses import asdict, dataclass, field
from typing import Any

import httpx

from sentinel import SPEC_REVISION, __version__
from sentinel.catalog.base import Outcome, Severity
from sentinel.grade import run_scan
from sentinel.probe.client import Probe
from sentinel.probe.transport import DEFAULT_USER_AGENT, Request

REGISTRY_BASE = "https://registry.modelcontextprotocol.io"
OFFICIAL_META = "io.modelcontextprotocol.registry/official"
LEGACY_REVISION = "2025-11-25"

CLASS_CURRENT = SPEC_REVISION
CLASS_LEGACY = "legacy"
CLASS_AUTH = "auth"
CLASS_UNREACHABLE = "unreachable"
CLASS_OTHER = "other"
CLASSES = (CLASS_CURRENT, CLASS_LEGACY, CLASS_AUTH, CLASS_UNREACHABLE, CLASS_OTHER)


@dataclass(frozen=True, slots=True)
class Target:
    """One remote endpoint listed in the registry."""

    server: str
    version: str
    url: str
    #: The listing declares headers the client must supply (an API key, a
    #: tenant id). Such a server is still classified -- it may answer discovery
    #: without them -- but a refusal is expected rather than a finding.
    needs_headers: bool

    @property
    def host(self) -> str:
        return urllib.parse.urlsplit(self.url).netloc.lower()


@dataclass(slots=True)
class Result:
    server: str
    version: str
    url: str
    host: str
    classification: str
    needs_headers: bool
    http_status: int | None = None
    detail: str = ""
    #: Only for CLASS_CURRENT servers, which are the ones graded.
    must: dict[str, int] = field(default_factory=dict)
    should: dict[str, int] = field(default_factory=dict)
    must_failures: list[str] = field(default_factory=list)
    should_failures: list[str] = field(default_factory=list)
    skipped_for_safety: int = 0
    response_framing: str = ""
    elapsed_s: float = 0.0


# -- listing -----------------------------------------------------------------


def _concrete_url(url: str) -> bool:
    """A remote URL with no unresolved `{template}` variables."""
    return url.startswith(("http://", "https://")) and "{" not in url


def targets_from_listing(entries: Iterable[dict[str, Any]]) -> list[Target]:
    """Every scannable remote in a page of `GET /v0.1/servers` results.

    Kept: the latest, active version of each server; its streamable-http
    remotes with a concrete URL. Dropped: deprecated and deleted listings,
    superseded versions, templated URLs a caller would have to fill in, and the
    SSE transport this revision deprecated (inventoried, not graded).
    Duplicates of one URL are scanned once.
    """
    seen: set[str] = set()
    found: list[Target] = []
    for entry in entries:
        server = entry.get("server")
        if not isinstance(server, dict):
            continue
        meta = (entry.get("_meta") or {}).get(OFFICIAL_META) or {}
        if meta.get("status", "active") != "active" or meta.get("isLatest") is False:
            continue
        for remote in server.get("remotes") or []:
            if not isinstance(remote, dict) or remote.get("type") != "streamable-http":
                continue
            url = remote.get("url")
            if not isinstance(url, str) or not _concrete_url(url) or url in seen:
                continue
            seen.add(url)
            headers = remote.get("headers") or []
            found.append(
                Target(
                    server=str(server.get("name", "")),
                    version=str(server.get("version", "")),
                    url=url,
                    needs_headers=any(isinstance(h, dict) and h.get("isRequired") for h in headers),
                )
            )
    return found


def fetch_listing(
    base: str = REGISTRY_BASE,
    *,
    page_size: int = 100,
    max_pages: int = 200,
    client: httpx.Client | None = None,
) -> Iterator[dict[str, Any]]:
    """Every entry of `GET /v0.1/servers`, following `metadata.nextCursor`."""
    own = client is None
    http = client or httpx.Client(timeout=30.0, headers={"User-Agent": DEFAULT_USER_AGENT})
    try:
        cursor: str | None = None
        for _ in range(max_pages):
            params: dict[str, str | int] = {"limit": page_size, "version": "latest"}
            if cursor:
                params["cursor"] = cursor
            resp = http.get(f"{base}/v0.1/servers", params=params)
            resp.raise_for_status()
            page = resp.json()
            yield from page.get("servers") or []
            cursor = (page.get("metadata") or {}).get("nextCursor")
            if not cursor:
                return
    finally:
        if own:
            http.close()


# -- classification ----------------------------------------------------------


def _legacy_initialize() -> Request:
    params = {
        "protocolVersion": LEGACY_REVISION,
        "capabilities": {},
        "clientInfo": {"name": "sentinel-probe", "version": __version__},
    }
    return Request(
        method="initialize",
        params=params,
        request_id=1,
        headers={"MCP-Protocol-Version": LEGACY_REVISION},
    )


def framing_of(resp: Any) -> str:
    if not resp.reached_server:
        return ""
    return "sse" if resp.is_event_stream else "json"


def classify(probe: Probe) -> tuple[str, int | None, str, str]:
    """Which protocol generation answers at this endpoint, and how it frames replies."""
    discover = probe.discover()
    framing = framing_of(discover)
    if not discover.reached_server:
        return CLASS_UNREACHABLE, None, discover.transport_error or "", framing
    if discover.status in (401, 403):
        return CLASS_AUTH, discover.status, "refused before any JSON-RPC answer", framing
    if discover.result() is not None:
        return CLASS_CURRENT, discover.status, "answered server/discover", framing

    legacy = probe.send(_legacy_initialize())
    if legacy.reached_server and legacy.status in (401, 403):
        return CLASS_AUTH, legacy.status, "refused before any JSON-RPC answer", framing
    result = legacy.result()
    if result is not None and "protocolVersion" in result:
        detail = f"negotiated {result.get('protocolVersion')!r}"
        return CLASS_LEGACY, legacy.status, detail, framing_of(legacy) or framing
    if discover.status == 404 or discover.status >= 500:
        return CLASS_UNREACHABLE, discover.status, f"HTTP {discover.status}", framing
    code = discover.error_code()
    return (
        CLASS_OTHER,
        discover.status,
        (
            f"server/discover answered HTTP {discover.status}"
            + (f" with JSON-RPC error {code}" if code is not None else " with no JSON-RPC response")
        ),
        framing,
    )


def scan_target(target: Target, *, timeout: float = 10.0) -> Result:
    """Classify one endpoint and, if it speaks this revision, grade it safely."""
    started = time.perf_counter()
    result = Result(
        server=target.server,
        version=target.version,
        url=target.url,
        host=target.host,
        classification=CLASS_UNREACHABLE,
        needs_headers=target.needs_headers,
    )
    try:
        with Probe(target.url, timeout=timeout, retries=0, safe=True) as probe:
            classification, status, detail, framing = classify(probe)
        result.classification, result.http_status, result.detail = classification, status, detail
        result.response_framing = framing
        if classification == CLASS_CURRENT:
            report = run_scan(target.url, timeout=timeout, retries=0, safe=True)
            result.must = report.counts(Severity.MUST)
            result.should = report.counts(Severity.SHOULD)
            result.must_failures = sorted(
                f.rule.id for f in report.by_outcome(Outcome.FAIL, Severity.MUST)
            )
            result.should_failures = sorted(
                f.rule.id for f in report.by_outcome(Outcome.FAIL, Severity.SHOULD)
            )
            result.skipped_for_safety = len(report.skipped_for_safety)
    except Exception as exc:  # one broken server must not end a population scan
        result.classification = CLASS_UNREACHABLE
        result.detail = f"scan aborted: {type(exc).__name__}: {exc}"
    result.elapsed_s = round(time.perf_counter() - started, 3)
    return result


def scan_population(
    targets: list[Target],
    *,
    concurrency: int = 8,
    timeout: float = 10.0,
    on_result: Callable[[Result], None] | None = None,
    scanner: Callable[[Target], Result] | None = None,
) -> list[Result]:
    """Scan every target: hosts in parallel, each host's targets one at a time."""
    scan = scanner or (lambda t: scan_target(t, timeout=timeout))
    by_host: dict[str, list[Target]] = defaultdict(list)
    for target in targets:
        by_host[target.host].append(target)

    def run_host(host_targets: list[Target]) -> list[Result]:
        out: list[Result] = []
        for target in host_targets:
            res = scan(target)
            if on_result is not None:
                on_result(res)
            out.append(res)
        return out

    results: list[Result] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        for host_results in pool.map(run_host, by_host.values()):
            results.extend(host_results)
    return results


# -- aggregation -------------------------------------------------------------


def summarize(results: list[Result], *, listed: int, scanned_at: str) -> dict[str, Any]:
    """Population-level counts only. Nothing here names a server."""
    by_class = Counter(r.classification for r in results)
    current = [r for r in results if r.classification == CLASS_CURRENT]
    passing_must = [r for r in current if not r.must_failures]
    must_rule_failures = Counter(rule for r in current for rule in r.must_failures)
    should_rule_failures = Counter(rule for r in current for rule in r.should_failures)
    answering = [r for r in results if r.response_framing]

    def pct(n: int, d: int) -> float | None:
        return None if d == 0 else round(100 * n / d, 1)

    return {
        "schemaVersion": 1,
        "tool": f"sentinel {__version__}",
        "specRevision": SPEC_REVISION,
        "scannedAt": scanned_at,
        "registry": REGISTRY_BASE,
        "method": {
            "safeMode": True,
            "retries": 0,
            "perHostConcurrency": 1,
            "listing": "latest active version; streamable-http remotes with a concrete URL",
        },
        "serversListedWithARemote": listed,
        "endpointsScanned": len(results),
        "classification": {c: by_class.get(c, 0) for c in CLASSES},
        "classificationPct": {c: pct(by_class.get(c, 0), len(results)) for c in CLASSES},
        "speakingCurrentRevisionPctOfAnswering": pct(
            len(current), len(results) - by_class.get(CLASS_UNREACHABLE, 0)
        ),
        "current": {
            "graded": len(current),
            "passMustGate": len(passing_must),
            "passMustGatePct": pct(len(passing_must), len(current)),
            "medianMustFailures": _median([len(r.must_failures) for r in current]),
            "rulesSkippedForSafetyTotal": sum(r.skipped_for_safety for r in current),
            "mostFailedMust": [
                {"ruleId": rule, "servers": n, "pctOfGraded": pct(n, len(current))}
                for rule, n in must_rule_failures.most_common(15)
            ],
            "mostFailedShould": [
                {"ruleId": rule, "servers": n, "pctOfGraded": pct(n, len(current))}
                for rule, n in should_rule_failures.most_common(10)
            ],
        },
        "responseFraming": dict(Counter(r.response_framing for r in answering)),
        "needsHeadersListed": sum(1 for r in results if r.needs_headers),
    }


def _median(values: list[int]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    return float(ordered[mid]) if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2


def render_markdown(summary: dict[str, Any]) -> str:
    c = summary["classification"]
    pct = summary["classificationPct"]
    cur = summary["current"]
    lines = [
        f"# MCP registry conformance scan — {summary['scannedAt']}",
        "",
        f"Sentinel `{summary['tool'].split()[-1]}` graded every remote server in the "
        f"[official MCP registry]({summary['registry']}) against MCP "
        f"`{summary['specRevision']}`, in safe mode (no tool invoked unless annotated "
        "read-only, one connection per host, no retries).",
        "",
        "| | Endpoints | % |",
        "|---|---:|---:|",
        f"| Scanned | {summary['endpointsScanned']} | |",
    ]
    labels = {
        CLASS_CURRENT: f"Speak `{summary['specRevision']}`",
        CLASS_LEGACY: f"Only speak the old `{LEGACY_REVISION}` handshake",
        CLASS_AUTH: "Require credentials before answering",
        CLASS_UNREACHABLE: "Unreachable or erroring",
        CLASS_OTHER: "Answer, but neither handshake",
    }
    for key in CLASSES:
        lines.append(f"| {labels[key]} | {c[key]} | {pct[key]} |")
    lines += [
        "",
        f"Of the {cur['graded']} servers speaking `{summary['specRevision']}`, "
        f"**{cur['passMustGate']}** ({cur['passMustGatePct']}%) pass every MUST rule "
        f"Sentinel can verify from the wire. Median MUST failures per server: "
        f"{cur['medianMustFailures']}.",
        "",
    ]
    if cur["mostFailedMust"]:
        lines += [
            "## Most-failed MUST rules",
            "",
            "| Rule | Servers | % of graded |",
            "|---|---:|---:|",
        ]
        lines += [
            f"| `{row['ruleId']}` | {row['servers']} | {row['pctOfGraded']} |"
            for row in cur["mostFailedMust"]
        ]
        lines.append("")
    lines += [
        "Per-server results are deliberately not published: findings go to each "
        "server's maintainer first.",
        "",
    ]
    return "\n".join(lines)


def to_jsonl(results: Iterable[Result]) -> str:
    return "".join(json.dumps(asdict(r), sort_keys=True) + "\n" for r in results)
