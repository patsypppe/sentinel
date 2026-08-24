"""The three severity corrections.

Three rules demanded more than the specification does. Rule IDs are permanent
(HANDOFF §8.8), so each is deprecated and superseded rather than edited --
otherwise an archived report naming one of these ids becomes uninterpretable.
"""

from __future__ import annotations

import pytest

import sentinel.catalog  # noqa: F401  -- import registers every rule
from sentinel.catalog import REGISTRY
from sentinel.catalog.base import validate_registry

pytestmark = pytest.mark.unit


CORRECTIONS = [
    ("MCP/2026-07-28/MUST/server-info-echoed", "MCP/2026-07-28/SHOULD/server-info-echoed"),
    (
        "MCP/2026-07-28/MUST/tools-list-is-deterministic",
        "MCP/2026-07-28/SHOULD/tools-list-is-deterministic",
    ),
    ("MCP/2026-07-28/SHOULD/tools-sorted-by-name", "SENTINEL/STYLE/tools-sorted-by-name"),
]


@pytest.mark.parametrize(("old", "new"), CORRECTIONS)
def test_wrongly_graded_rules_are_deprecated_not_edited(old: str, new: str) -> None:
    by_id = {r.id: r for r in REGISTRY.all(include_deprecated=True)}
    assert old in by_id, f"{old} was deleted; ids are permanent"
    assert by_id[old].is_deprecated
    assert by_id[old].superseded_by == new
    assert new in by_id
    assert not by_id[new].is_deprecated


def test_the_deprecated_rules_are_not_scanned_by_default() -> None:
    live = {r.id for r in REGISTRY.all()}
    for old, new in CORRECTIONS:
        assert old not in live
        assert new in live


def test_the_shipped_catalog_validates() -> None:
    assert validate_registry(REGISTRY) == []
