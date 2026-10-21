"""`sentinel.toml`: precedence is tested cell by cell, not asserted in prose."""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from sentinel.catalog.base import Severity
from sentinel.config import ConfigError, discover, load_policy

pytestmark = pytest.mark.unit

MUST = "MCP/2026-07-28/MUST/malformed-json-is-parse-error"
SHOULD = "MCP/2026-07-28/SHOULD/get-delete-405"


def write(directory: Path, name: str, body: str) -> Path:
    path = directory / name
    path.write_text(body)
    return path


def test_defaults_when_nothing_is_set(tmp_path: Path) -> None:
    policy = load_policy(cwd=tmp_path, env={})
    assert (policy.timeout, policy.concurrency, policy.gate, policy.endpoint) == (
        10.0,
        8,
        None,
        None,
    )
    assert policy.sources["timeout"] == "default"


def test_each_layer_beats_the_one_below_it(tmp_path: Path) -> None:
    write(tmp_path, "base.toml", "[scan]\ntimeout = 9.0\nconcurrency = 2\n")
    child = write(
        tmp_path,
        "sentinel.toml",
        'extends = "base.toml"\n[scan]\ntimeout = 7.0\n',
    )

    # extends supplies what the project file does not say...
    policy = load_policy(config=child, env={})
    assert policy.timeout == 7.0
    assert policy.concurrency == 2
    assert policy.sources["concurrency"].startswith("extends:")
    # ...and the project file beats extends where both speak.
    assert policy.sources["timeout"] == str(child)

    # env beats the file...
    policy = load_policy(config=child, env={"SENTINEL_TIMEOUT": "5"})
    assert policy.timeout == 5.0
    assert policy.sources["timeout"] == "env: SENTINEL_TIMEOUT"

    # ...and the CLI beats env.
    policy = load_policy(config=child, env={"SENTINEL_TIMEOUT": "5"}, cli={"timeout": 3.0})
    assert policy.timeout == 3.0
    assert policy.sources["timeout"] == "cli"


def test_an_unset_cli_flag_does_not_override_anything(tmp_path: Path) -> None:
    cfg = write(tmp_path, "sentinel.toml", "[scan]\ngate = 'must'\n")
    policy = load_policy(config=cfg, env={}, cli={"gate": None})
    assert policy.gate == "must"


def test_discovery_order(tmp_path: Path) -> None:
    assert discover(None, tmp_path) is None
    hidden = write(tmp_path, ".sentinel.toml", "")
    assert discover(None, tmp_path) == hidden
    visible = write(tmp_path, "sentinel.toml", "")
    assert discover(None, tmp_path) == visible
    explicit = write(tmp_path, "other.toml", "")
    assert discover(explicit, tmp_path) == explicit
    with pytest.raises(ConfigError, match="does not exist"):
        discover(tmp_path / "missing.toml", tmp_path)


def test_a_cycle_in_extends_is_an_error(tmp_path: Path) -> None:
    write(tmp_path, "a.toml", 'extends = "b.toml"\n')
    write(tmp_path, "b.toml", 'extends = "a.toml"\n')
    with pytest.raises(ConfigError, match="cycle"):
        load_policy(config=tmp_path / "a.toml", env={})


def test_severity_may_be_raised_but_never_lowered(tmp_path: Path) -> None:
    stricter = write(tmp_path, "up.toml", f'[rules.severity]\n"{SHOULD}" = "must"\n')
    policy = load_policy(config=stricter, env={})
    assert policy.severity_overrides[SHOULD] is Severity.MUST

    laundering = write(tmp_path, "down.toml", f'[rules.severity]\n"{MUST}" = "should"\n')
    with pytest.raises(ConfigError, match="demote"):
        load_policy(config=laundering, env={})


def test_a_rule_id_that_does_not_exist_is_an_error_with_a_hint(tmp_path: Path) -> None:
    cfg = write(
        tmp_path, "sentinel.toml", '[rules]\ndisable = ["MCP/2026-07-28/SHOULD/get-delete-404"]\n'
    )
    with pytest.raises(ConfigError, match="not a rule in this catalog"):
        load_policy(config=cfg, env={})
    near = write(
        tmp_path, "near.toml", '[rules]\ndisable = ["MCP/2026-07-28/MUST/get-delete-405"]\n'
    )
    with pytest.raises(ConfigError, match="Did you mean"):
        load_policy(config=near, env={})


def test_disable_is_allowed_and_visible_in_the_report_block(tmp_path: Path) -> None:
    cfg = write(tmp_path, "sentinel.toml", f'[rules]\ndisable = ["{SHOULD}"]\n')
    policy = load_policy(config=cfg, env={})
    assert policy.describe()["disabledRules"] == [SHOULD]


def waiver(expires: str) -> str:
    return (
        "[[waivers]]\n"
        f'rule = "{MUST}"\n'
        'reason = "behind an ingress that strips the header, PLAT-4412"\n'
        f"expires_at = {expires}\n"
    )


def test_a_waiver_needs_a_real_date(tmp_path: Path) -> None:
    ok = write(tmp_path, "ok.toml", waiver("2026-11-30"))
    assert load_policy(config=ok, env={}).waivers[0].expires_at == datetime.date(2026, 11, 30)
    quoted = write(tmp_path, "quoted.toml", waiver('"2026-11-30"'))
    assert load_policy(config=quoted, env={}).waivers[0].expires_at == datetime.date(2026, 11, 30)

    for bad in ('"someday"', '"2026-13-45"', "42", '""'):
        cfg = write(tmp_path, "bad.toml", waiver(bad))
        with pytest.raises(ConfigError, match="not a date"):
            load_policy(config=cfg, env={})


def test_a_waiver_without_an_expiry_or_reason_is_rejected(tmp_path: Path) -> None:
    no_expiry = write(
        tmp_path, "a.toml", f'[[waivers]]\nrule = "{MUST}"\nreason = "long enough reason"\n'
    )
    with pytest.raises(ConfigError, match="missing 'expires_at'"):
        load_policy(config=no_expiry, env={})
    thin = write(
        tmp_path,
        "b.toml",
        f'[[waivers]]\nrule = "{MUST}"\nreason = "no"\nexpires_at = 2026-11-30\n',
    )
    with pytest.raises(ConfigError, match="too short to be a reason"):
        load_policy(config=thin, env={})


def test_extends_misplaced_under_a_waiver_gets_a_useful_error(tmp_path: Path) -> None:
    cfg = write(tmp_path, "sentinel.toml", waiver("2026-11-30") + 'extends = "x.toml"\n')
    with pytest.raises(ConfigError, match="first line"):
        load_policy(config=cfg, env={})


def test_a_bad_value_names_where_it_came_from(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"SENTINEL_TIMEOUT|env: SENTINEL_TIMEOUT"):
        load_policy(cwd=tmp_path, env={"SENTINEL_TIMEOUT": "soon"})
    with pytest.raises(ConfigError, match="at least 1"):
        load_policy(cwd=tmp_path, env={}, cli={"concurrency": 0})


def test_the_token_comes_from_the_named_environment_variable(tmp_path: Path) -> None:
    cfg = write(tmp_path, "sentinel.toml", "[scan]\ntoken_env = 'BROKER_TOKEN'\n")
    policy = load_policy(config=cfg, env={})
    assert policy.token({"BROKER_TOKEN": "s3cret", "SENTINEL_TOKEN": "wrong"}) == "s3cret"
    assert policy.token({}) is None
    assert "s3cret" not in str(policy.describe())
