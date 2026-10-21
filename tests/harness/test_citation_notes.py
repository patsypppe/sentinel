"""docs/CITATIONS.md must list exactly the rules whose citation has no anchor."""

from __future__ import annotations

import pathlib
import re

import pytest

from sentinel.catalog.base import REGISTRY, Namespace

pytestmark = pytest.mark.unit

DOC = pathlib.Path(__file__).resolve().parents[2] / "docs" / "CITATIONS.md"


def test_the_unanchored_citation_list_matches_the_catalog() -> None:
    unanchored = {
        r.id.split("/", 2)[2]
        for r in REGISTRY.all(include_deprecated=True)
        if r.namespace is Namespace.MCP and "#" not in r.citation
    }
    listed = set(
        re.findall(r"^\| `((?:MUST|SHOULD)/[a-z0-9-]+)` \|", DOC.read_text(), re.MULTILINE)
    )
    assert listed == unanchored, (
        f"CITATIONS.md lists {sorted(listed - unanchored)} that now have anchors and omits "
        f"{sorted(unanchored - listed)}"
    )
