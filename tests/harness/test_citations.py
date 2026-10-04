"""Every spec citation must point at a page and anchor that exist.

Verified against the published 2026-07-28 pages (headings fetched 2026-10-03).
A citation to an anchor that does not exist sends the reader of a report to the
top of a page and implies the spec says something it does not, so the allowlist
below is the contract: add a page/anchor here only after checking the live spec.
"""

from __future__ import annotations

from urllib.parse import urlparse

import pytest

from sentinel.catalog.base import REGISTRY, SPEC_BASE, Namespace

pytestmark = pytest.mark.unit

#: page path (relative to the revision) -> anchors known to exist ("" = page only).
KNOWN: dict[str, set[str]] = {
    "changelog": {"major-changes", "minor-changes", "deprecated"},
    "basic/index": {"error-codes", "_meta", "resulttype", "statelessness"},
    "basic/versioning": {"protocol-version-negotiation", "extension-negotiation"},
    "basic/transports": {"request-metadata", "backward-compatibility"},
    "basic/transports/streamable-http": {
        "security-endpoint",
        "sending-messages",
        "request-metadata",
        "protocol-version-header",
        "standard-request-headers",
        "server-validation",
        "backward-compatibility",
    },
    "basic/patterns/mrtr": {"basic-workflow", "error-handling"},
    "basic/authorization": {"client-registration"},
    "basic/security_best_practices": {
        "token-passthrough",
        "state-handle-hijacking",
    },
    "server/tools": {"capabilities", "listing-tools"},
    "server/discover": {"response", "data-types"},
}


def _spec_rules() -> list[tuple[str, str]]:
    return [(r.id, r.citation) for r in REGISTRY if r.namespace is Namespace.MCP]


@pytest.mark.parametrize(("rule_id", "citation"), _spec_rules())
def test_citation_resolves_to_a_real_page_and_anchor(rule_id: str, citation: str) -> None:
    assert citation.startswith(SPEC_BASE + "/"), f"{rule_id}: {citation}"
    parsed = urlparse(citation)
    page = parsed.path.removeprefix(urlparse(SPEC_BASE).path + "/")
    assert page in KNOWN, f"{rule_id}: unknown page {page!r}"
    if parsed.fragment:
        assert parsed.fragment in KNOWN[page], (
            f"{rule_id}: anchor #{parsed.fragment} not on {page}; known: {sorted(KNOWN[page])}"
        )
