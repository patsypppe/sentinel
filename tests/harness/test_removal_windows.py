"""The deprecation inventory reports what the registry says, not what is convenient.

Two of the six removal conditions are not date arithmetic: includeContext's
window follows Sampling's, and HTTP+SSE's depends on an event that has not
happened. A model that can only express `deprecated_on + 12 months` has to
invent a date for both -- and an invented date in a migration report is the same
failure as scoring an unverifiable MUST as a pass.
"""

from __future__ import annotations

import datetime
import json
import pathlib

import pytest

from sentinel.catalog.deprecations import (
    FEATURES_BY_ID,
    AfterEvent,
    Confidence,
    Detection,
    FixedRevision,
    FollowsFeature,
    Inventory,
    resolve_removal,
)

pytestmark = pytest.mark.unit

REGISTRY = json.loads(
    (pathlib.Path(__file__).parent / "data" / "deprecation_registry.json").read_text()
)


@pytest.mark.parametrize("row", REGISTRY["features"], ids=lambda r: r["id"])
def test_deprecated_on_matches_the_registry(row: dict[str, str]) -> None:
    feature = FEATURES_BY_ID[row["id"]]
    assert feature.deprecated_on == datetime.date.fromisoformat(row["deprecated_in"])


def test_every_registry_row_has_a_feature_and_vice_versa() -> None:
    assert {r["id"] for r in REGISTRY["features"]} == set(FEATURES_BY_ID)


def test_include_context_follows_sampling() -> None:
    assert FEATURES_BY_ID["include-context"].removal == FollowsFeature(
        feature_id="sampling", sep="SEP-2577"
    )
    resolved = resolve_removal(FEATURES_BY_ID["include-context"], FEATURES_BY_ID)
    assert resolved == FixedRevision(datetime.date(2027, 7, 28))


def test_http_sse_removal_is_an_event_and_no_date_is_invented() -> None:
    window = FEATURES_BY_ID["http-sse"].removal
    assert isinstance(window, AfterEvent)
    assert window.sep == "SEP-2596"
    assert "Final" in window.describe()
    # And nothing anywhere turns it into a date.
    assert not hasattr(window, "on_or_after")


def test_months_remaining_is_none_for_an_event_relative_window() -> None:
    detection = Detection(
        feature=FEATURES_BY_ID["http-sse"], in_use=True, confidence=Confidence.OBSERVED
    )
    inventory = Inventory(
        endpoint="http://x/mcp", as_of=datetime.date(2026, 8, 23), detections=[detection]
    )
    assert inventory.months_remaining(detection) is None


def test_months_remaining_is_computed_for_a_fixed_window() -> None:
    detection = Detection(
        feature=FEATURES_BY_ID["roots"], in_use=True, confidence=Confidence.OBSERVED
    )
    inventory = Inventory(
        endpoint="http://x/mcp", as_of=datetime.date(2026, 8, 23), detections=[detection]
    )
    assert inventory.months_remaining(detection) == 11


def test_the_twelve_month_policy_and_the_registry_agree_for_sep_2577() -> None:
    """Not arithmetic we rely on -- a cross-check that the registry is consistent."""
    from sentinel.catalog.deprecations import earliest_removal

    for fid in ("roots", "sampling", "logging"):
        feature = FEATURES_BY_ID[fid]
        assert isinstance(feature.removal, FixedRevision)
        assert feature.removal.on_or_after == earliest_removal(feature.deprecated_on)
