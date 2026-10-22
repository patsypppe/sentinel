"""Every spec citation must point at a page and anchor that exist.

Verified against the 2026-07-28 specification source (headings read 2026-10-22).
A citation to an anchor that does not exist sends the reader of a report to the
top of a page and implies the spec says something it does not, so the allowlist
below is the contract: add a page/anchor here only after checking the live spec.
"""

from __future__ import annotations

from urllib.parse import urlparse

import pytest

from sentinel.catalog.base import DOCS_BASE, REGISTRY, SPEC_BASE, Namespace

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
        "schema-extension",
    },
    "basic/patterns/mrtr": {
        "basic-workflow",
        "error-handling",
        "server-requirements-basic-workflow",
    },
    "basic/authorization": {"client-registration"},
    "server/tools": {
        "capabilities",
        "listing-tools",
        "tool",
        "tool-names",
        "security-considerations",
    },
    "server/discover": {"response", "data-types"},
}


#: Tutorial pages live under /docs/<revision>/, not /specification/<revision>/.
KNOWN_DOCS: dict[str, set[str]] = {
    "tutorials/security/security_best_practices": {"token-passthrough", "state-handle-hijacking"},
}


def _spec_rules() -> list[tuple[str, str]]:
    return [(r.id, r.citation) for r in REGISTRY if r.namespace is Namespace.MCP]


@pytest.mark.parametrize(("rule_id", "citation"), _spec_rules())
def test_citation_resolves_to_a_real_page_and_anchor(rule_id: str, citation: str) -> None:
    parsed = urlparse(citation)
    if citation.startswith(DOCS_BASE + "/"):
        known, base = KNOWN_DOCS, DOCS_BASE
    else:
        assert citation.startswith(SPEC_BASE + "/"), f"{rule_id}: {citation}"
        known, base = KNOWN, SPEC_BASE
    page = parsed.path.removeprefix(urlparse(base).path + "/")
    assert page in known, f"{rule_id}: unknown page {page!r}"
    if parsed.fragment:
        assert parsed.fragment in known[page], (
            f"{rule_id}: anchor #{parsed.fragment} not on {page}; known: {sorted(known[page])}"
        )
