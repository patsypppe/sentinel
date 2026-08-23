"""The deprecation inventory, graded against the same fixtures.

`docs/HANDOFF.md` §10 (WP-11): "All five detected against the fixture, none
against Broker."
"""

from __future__ import annotations

from datetime import date

import pytest

from sentinel.catalog.deprecations import (
    DEPRECATED_ON,
    FEATURES,
    MINIMUM_NOTICE_MONTHS,
    Confidence,
    build_inventory,
    earliest_removal,
    render_json,
    render_text,
)
from sentinel.probe.client import Probe
from server.nonconformant import SEEDED_DEPRECATIONS

pytestmark = pytest.mark.unit

AS_OF = date(2026, 9, 23)


def inventory_for(endpoint: str):
    with Probe(endpoint) as probe:
        return build_inventory(probe, AS_OF)


def test_all_seeded_deprecations_are_detected(nonconformant_endpoint: str) -> None:
    """The recall half, for deprecations.

    The denominator comes from the fixture's own `SEEDED_DEPRECATIONS`, exactly
    as MUST recall comes from `SEEDED_VIOLATIONS`.
    """
    inventory = inventory_for(nonconformant_endpoint)
    detected = {d.feature.id for d in inventory.in_use}
    seeded = set(SEEDED_DEPRECATIONS)

    missed = seeded - detected
    assert not missed, f"{len(missed)} seeded deprecation(s) undetected: {sorted(missed)}"


def test_none_detected_against_a_conformant_server(conformant_endpoint: str) -> None:
    """The false-positive half. A migration plan full of features nobody uses is
    a plan people stop reading."""
    inventory = inventory_for(conformant_endpoint)
    assert not inventory.in_use, (
        "deprecated features reported against a conformant server: "
        f"{[d.feature.id for d in inventory.in_use]}"
    )


def test_the_five_named_features_are_all_tracked() -> None:
    """§10 (WP-11) names them explicitly."""
    tracked = {f.id for f in FEATURES}
    for required in ("roots", "sampling", "logging", "http-sse", "oauth-dcr", "include-context"):
        assert required in tracked, f"{required} is not tracked"


def test_removal_window_is_twelve_months() -> None:
    assert MINIMUM_NOTICE_MONTHS == 12
    assert earliest_removal(date(2026, 7, 28)) == date(2027, 7, 28)


def test_removal_arithmetic_survives_month_ends() -> None:
    """31 January plus twelve months is still 31 January; 29 February is not."""
    assert earliest_removal(date(2026, 1, 31)) == date(2027, 1, 31)
    assert earliest_removal(date(2024, 2, 29)) == date(2025, 2, 28)
    assert earliest_removal(date(2026, 12, 15)) == date(2027, 12, 15)


def test_removal_is_phrased_on_or_after(nonconformant_endpoint: str) -> None:
    """§10 (WP-11): "Say 'on or after'; the window is a minimum, not a schedule."

    A date presented as a deadline gets planned around as the moment the feature
    stops working, which is not what the specification promised.
    """
    rendered = render_text(inventory_for(nonconformant_endpoint), color=False)
    assert "removable on or after" in rendered
    for forbidden in ("removed on ", "deadline", "must migrate by", "expires on"):
        assert forbidden not in rendered.lower(), (
            f"the report says {forbidden!r}, which presents a minimum notice period as a schedule"
        )


def test_json_key_carries_the_semantics_too(nonconformant_endpoint: str) -> None:
    """A consumer reading the JSON never sees the prose, so the key name has to
    carry the meaning by itself."""
    doc = render_json(inventory_for(nonconformant_endpoint))
    for feature in doc["features"]:  # type: ignore[index]
        assert "removableOnOrAfter" in feature
        assert "removedOn" not in feature
        assert "deadline" not in feature


def test_each_finding_names_its_replacement(nonconformant_endpoint: str) -> None:
    """A finding that only says "this is deprecated" leaves the reader to work
    out the migration themselves."""
    for detection in inventory_for(nonconformant_endpoint).in_use:
        assert detection.feature.replacement, f"{detection.feature.id} names no replacement"
        assert len(detection.feature.note) > 40, f"{detection.feature.id} does not explain why"


def test_findings_cite_the_specification(nonconformant_endpoint: str) -> None:
    for detection in inventory_for(nonconformant_endpoint).detections:
        assert detection.feature.citation.startswith("https://modelcontextprotocol.io/")


def test_months_remaining_goes_negative_rather_than_clamping() -> None:
    """Reporting 0 months once the window has passed implies there is still
    time. A negative number says what actually happened."""
    from sentinel.catalog.deprecations import Detection, Inventory

    detection = Detection(FEATURES[0], in_use=True, confidence=Confidence.OBSERVED)
    late = Inventory(endpoint="x", as_of=date(2028, 1, 1), detections=[detection])
    assert late.months_remaining(detection) < 0


def test_an_undeterminable_feature_is_flagged_not_assumed_absent(
    nonconformant_endpoint: str,
) -> None:
    """The inventory has three states, and the third is load-bearing.

    OAuth DCR is advertised in the authorization server's own metadata, which
    the probe deliberately does not fetch — following a URL the scan target
    supplied is the SSRF the security guidance warns about. So a server that
    advertises nothing is reported as UNKNOWN rather than clean.
    """
    inventory = inventory_for(nonconformant_endpoint)
    by_id = {d.feature.id: d for d in inventory.detections}

    # This fixture DOES advertise it, so it is observed here...
    assert by_id["oauth-dcr"].in_use

    # ...and the confidence vocabulary exists for the case where it does not.
    assert Confidence.UNKNOWN in set(Confidence)


def test_conformant_server_reports_dcr_as_unknown_not_clean(
    conformant_endpoint: str,
) -> None:
    inventory = inventory_for(conformant_endpoint)
    by_id = {d.feature.id: d for d in inventory.detections}

    assert not by_id["oauth-dcr"].in_use
    assert by_id["oauth-dcr"].confidence is Confidence.UNKNOWN, (
        "a feature the probe cannot see must not be reported as confidently absent"
    )
    assert "SSRF" in by_id["oauth-dcr"].evidence, (
        "the evidence should say why it was not fetched, or the limitation reads as an "
        "oversight rather than a decision"
    )


def test_deprecated_on_is_the_revision_date() -> None:
    assert date(2026, 7, 28) == DEPRECATED_ON
