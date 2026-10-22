"""Gray-box evidence: a verdict only where the evidence settles it.

Every kind is tested four ways -- a correct server, a server broken in exactly the
way the evidence is meant to catch, no evidence at all, and evidence that is
incomplete -- because the property that matters is that none of them is ever a pass
by default.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from tests.harness.conftest import free_port

from sentinel.catalog.base import REGISTRY, Outcome
from sentinel.config import load_policy
from sentinel.grade import ScanReport
from sentinel.graybox import Evidence, run_command, validate_graybox
from sentinel.runner import ScanOptions, scan_target
from sentinel.waivers import ConfigError
from server.common import serve_background
from server.graybox import WRONG_AUDIENCE, GrayboxServer

pytestmark = pytest.mark.unit

FETCH = "import sys,urllib.request;print(urllib.request.urlopen(sys.argv[1]).read().decode())"

ENV = {"TOKEN_A": "principal-a", "TOKEN_B": "principal-b", "WRONG": WRONG_AUDIENCE}


@pytest.fixture
def make_server() -> Iterator[Callable[..., tuple[GrayboxServer, str]]]:
    started: list[Any] = []

    def make(**knobs: Any) -> tuple[GrayboxServer, str]:
        server = GrayboxServer(**knobs)
        port = free_port()
        httpd, _ = serve_background(
            server.dispatch, port, banner="graybox", introspect=server.introspect
        )
        started.append(httpd)
        return server, f"http://127.0.0.1:{port}"

    yield make
    for httpd in started:
        httpd.shutdown()
        httpd.server_close()


def command(base: str, path: str) -> list[str]:
    return [sys.executable, "-c", FETCH, f"{base}{path}"]


def graybox_config(base: str) -> dict[str, Any]:
    return {
        "wrong_audience_token_env": "WRONG",
        "second_principal_token_env": "TOKEN_B",
        "egress_token_env": "TOKEN_A",
        "egress_tool": "data.proxy-call",
        "egress_capture": command(base, "/_egress"),
        "effect_counter": command(base, "/_effects"),
        "audit_verify": command(base, "/_audit"),
        "audit_tool": "audit.touch",
        "handle": {
            "mint_tool": "data.make-handle",
            "handle_field": "structuredContent.handle",
            "use_tool": "data.read-handle",
            "use_argument": "handle",
        },
        "mrtr": {"tool": "ops.apply"},
    }


def verdicts(
    base: str, tmp_path: Any, config: dict[str, Any] | None, *, allow_exec: bool = True
) -> dict[str, tuple[Outcome, str, str]]:
    cfg = tmp_path / "sentinel.toml"
    cfg.write_text("")
    policy = load_policy(config=cfg, env={})
    policy.graybox = config if config is not None else {}
    report: ScanReport = scan_target(
        ScanOptions(
            endpoint=f"{base}/mcp",
            policy=policy,
            token="principal-a",
            env=ENV,
            allow_exec=allow_exec,
        )
    )
    unverifiable = {
        "token-audience-validated",
        "no-token-passthrough",
        "handle-possession-is-not-authentication",
        "mrtr-retries-are-idempotent",
        "invocations-are-audited",
    }
    return {
        f.rule.slug: (f.outcome, f.verified_by, f.result.detail)
        for f in report.findings
        if f.rule.slug in unverifiable and not f.rule.is_deprecated
    }


def test_there_are_exactly_five_evidence_backed_rules() -> None:
    assert {r.evidence_kind for r in REGISTRY.all() if r.evidence_kind} == {
        "wrong_audience_token",
        "second_principal",
        "egress_capture",
        "effect_counter",
        "audit_verify",
    }


def test_a_correct_server_passes_every_rule_and_names_the_evidence(
    make_server: Callable[..., tuple[GrayboxServer, str]], tmp_path: Any
) -> None:
    _, base = make_server()
    got = verdicts(base, tmp_path, graybox_config(base))
    assert {slug: o for slug, (o, _, _) in got.items()} == dict.fromkeys(got, Outcome.PASS), got
    assert {slug: v for slug, (_, v, _) in got.items()} == {
        "token-audience-validated": "wrong_audience_token",
        "no-token-passthrough": "egress_capture",
        "handle-possession-is-not-authentication": "second_principal",
        "mrtr-retries-are-idempotent": "effect_counter",
        "invocations-are-audited": "audit_verify",
    }


@pytest.mark.parametrize(
    ("knob", "slug"),
    [
        ({"validates_audience": False}, "token-audience-validated"),
        ({"binds_handles": False}, "handle-possession-is-not-authentication"),
        ({"forwards_token": True}, "no-token-passthrough"),
        ({"idempotent": False}, "mrtr-retries-are-idempotent"),
        ({"audits": False}, "invocations-are-audited"),
    ],
)
def test_each_defect_is_caught_by_its_own_evidence_and_only_its_own(
    make_server: Callable[..., tuple[GrayboxServer, str]],
    tmp_path: Any,
    knob: dict[str, Any],
    slug: str,
) -> None:
    _, base = make_server(**knob)
    got = verdicts(base, tmp_path, graybox_config(base))
    assert got[slug][0] is Outcome.FAIL, got[slug]
    others = {s: o for s, (o, _, _) in got.items() if s != slug}
    assert set(others.values()) == {Outcome.PASS}, others


def test_without_evidence_every_rule_is_indeterminate_and_none_is_a_pass(
    make_server: Callable[..., tuple[GrayboxServer, str]], tmp_path: Any
) -> None:
    _, base = make_server(validates_audience=False, binds_handles=False, forwards_token=True)
    got = verdicts(base, tmp_path, None)
    assert {o for o, _, _ in got.values()} == {Outcome.INDETERMINATE}
    assert {v for _, v, _ in got.values()} == {"black_box"}


def test_a_wrong_audience_refusal_that_looks_like_a_garbage_refusal_is_indeterminate(
    make_server: Callable[..., tuple[GrayboxServer, str]], tmp_path: Any
) -> None:
    _, base = make_server(distinct_refusals=False)
    outcome, _, detail = verdicts(base, tmp_path, graybox_config(base))["token-audience-validated"]
    assert outcome is Outcome.INDETERMINATE
    assert "Indistinguishable is not the same as correct" in detail


def test_evidence_that_was_started_and_not_finished_says_what_is_missing(
    make_server: Callable[..., tuple[GrayboxServer, str]], tmp_path: Any
) -> None:
    _, base = make_server()
    config = graybox_config(base)
    config["wrong_audience_token_env"] = "NOT_SET_ANYWHERE"
    outcome, _, detail = verdicts(base, tmp_path, config)["token-audience-validated"]
    assert outcome is Outcome.INDETERMINATE
    assert "NOT_SET_ANYWHERE" in detail


def test_no_exec_disables_every_command_and_leaves_the_token_kinds(
    make_server: Callable[..., tuple[GrayboxServer, str]], tmp_path: Any
) -> None:
    _, base = make_server()
    got = verdicts(base, tmp_path, graybox_config(base), allow_exec=False)
    assert got["token-audience-validated"][0] is Outcome.PASS
    assert got["handle-possession-is-not-authentication"][0] is Outcome.PASS
    for slug in ("no-token-passthrough", "mrtr-retries-are-idempotent", "invocations-are-audited"):
        outcome, _, detail = got[slug]
        assert outcome is Outcome.INDETERMINATE
        assert "--no-exec" in detail


def test_an_empty_egress_capture_proves_nothing(
    make_server: Callable[..., tuple[GrayboxServer, str]], tmp_path: Any
) -> None:
    _, base = make_server()
    config = graybox_config(base)
    config["egress_capture"] = [sys.executable, "-c", "print('')"]
    outcome, _, detail = verdicts(base, tmp_path, config)["no-token-passthrough"]
    assert outcome is Outcome.INDETERMINATE
    assert "proves nothing" in detail


def test_a_counter_that_does_not_move_proves_nothing(
    make_server: Callable[..., tuple[GrayboxServer, str]], tmp_path: Any
) -> None:
    _, base = make_server()
    config = graybox_config(base)
    config["effect_counter"] = [sys.executable, "-c", "print(7)"]
    outcome, _, detail = verdicts(base, tmp_path, config)["mrtr-retries-are-idempotent"]
    assert outcome is Outcome.INDETERMINATE
    assert "not measuring" in detail


def test_a_failing_audit_verifier_is_a_failure_and_a_missing_one_is_not(
    make_server: Callable[..., tuple[GrayboxServer, str]], tmp_path: Any
) -> None:
    _, base = make_server()
    broken = graybox_config(base)
    broken["audit_verify"] = [sys.executable, "-c", "import sys;sys.exit(3)"]
    outcome, _, detail = verdicts(base, tmp_path, broken)["invocations-are-audited"]
    assert outcome is Outcome.FAIL
    assert "not intact" in detail

    absent = graybox_config(base)
    absent["audit_verify"] = ["/nonexistent/verifier"]
    outcome, _, detail = verdicts(base, tmp_path, absent)["invocations-are-audited"]
    assert outcome is Outcome.INDETERMINATE
    assert "could not run" in detail


# ------------------------------------------------------------------- safety


def test_a_command_is_never_run_through_a_shell() -> None:
    result = run_command(["echo", "a; echo b && echo $HOME"])
    assert result.stdout.strip() == "a; echo b && echo $HOME"


def test_a_command_given_as_a_string_is_rejected_at_load_time() -> None:
    with pytest.raises(ConfigError, match="argv list"):
        validate_graybox({"audit_verify": "broker audit verify"})
    with pytest.raises(ConfigError, match="non-empty list of strings"):
        validate_graybox({"effect_counter": [1, 2]})
    with pytest.raises(ConfigError, match="unknown key"):
        validate_graybox({"audit_verfy": ["x"]})


def test_a_command_runs_with_a_minimal_environment() -> None:
    result = run_command([sys.executable, "-c", "import os;print(sorted(os.environ))"])
    assert "SENTINEL_TOKEN" not in result.stdout
    assert "AWS_SECRET_ACCESS_KEY" not in result.stdout


def test_a_command_that_hangs_is_killed() -> None:
    result = run_command([sys.executable, "-c", "import time;time.sleep(30)"], timeout=0.5)
    assert result.timed_out
    assert not result.ok


def test_evidence_status_distinguishes_absent_incomplete_and_ready() -> None:
    absent = Evidence(config={}, env={})
    assert absent.status("wrong_audience_token") == ("absent", "")
    incomplete = Evidence(config={"wrong_audience_token_env": "X"}, env={})
    state, why = incomplete.status("wrong_audience_token")
    assert state == "incomplete" and "'X'" in why
    ready = Evidence(config={"wrong_audience_token_env": "X"}, env={"X": "t"})
    assert ready.status("wrong_audience_token") == ("ready", "")
    assert ready.has("wrong_audience_token")
