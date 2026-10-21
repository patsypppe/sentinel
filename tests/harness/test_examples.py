"""The documented examples must load, or the documentation is lying."""

from __future__ import annotations

import pathlib

import pytest

from sentinel.config import load_policy
from sentinel.fleet import load_fleet
from sentinel.graybox import Evidence

pytestmark = pytest.mark.unit

EXAMPLES = pathlib.Path(__file__).resolve().parents[2] / "docs" / "examples"


def test_the_example_policy_loads_and_means_what_the_docs_say() -> None:
    policy = load_policy(config=EXAMPLES / "sentinel.toml", env={})
    assert policy.endpoint == "https://broker.internal.example/mcp"
    assert policy.gate == "must"
    assert policy.concurrency == 8
    assert policy.token_env == "BROKER_TOKEN"
    assert "MCP/2026-07-28/SHOULD/get-delete-405" in policy.disabled
    assert policy.severity_overrides
    assert policy.waivers[0].approved_by == "security@example.com"


def test_the_example_graybox_table_is_complete_for_every_kind() -> None:
    policy = load_policy(config=EXAMPLES / "sentinel.toml", env={})
    env = {
        "SENTINEL_WRONG_AUD": "a",
        "SENTINEL_PRINCIPAL_B": "b",
        "SENTINEL_PRINCIPAL_A": "c",
    }
    evidence = Evidence(config=policy.graybox, env=env)
    for kind in (
        "wrong_audience_token",
        "second_principal",
        "egress_capture",
        "effect_counter",
        "audit_verify",
    ):
        assert evidence.status(kind) == ("ready", ""), kind


def test_the_example_fleet_loads() -> None:
    fleet = load_fleet(EXAMPLES / "sentinel-fleet.yaml")
    assert [t.name for t in fleet.targets] == ["broker-prod", "vendor-x"]
    assert fleet.targets[1].gate == "should" and fleet.targets[1].safe is True
    assert fleet.targets[1].waivers_from == EXAMPLES / "vendor-x.toml"


def test_the_example_target_waivers_load() -> None:
    from sentinel.config import waivers_from

    [waiver] = waivers_from(EXAMPLES / "vendor-x.toml")
    assert waiver.rule.endswith("invalid-origin-rejected")
