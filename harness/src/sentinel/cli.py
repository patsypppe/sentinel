"""Typer entrypoint for the `sentinel` command.

Exit-code contract (docs/HANDOFF.md §8.8), enforced here and nowhere else:

* ``scan --gate must`` exits **1** if any MUST rule FAILs, **0** otherwise.
* ``INDETERMINATE`` never fails a gate, but is always printed.
* Every other subcommand reserves non-zero for *harness* errors, so CI can
  distinguish "the server is wrong" from "the scanner broke".
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
from typing import Annotated

import typer

from sentinel import SPEC_REVISION, __version__
from sentinel.budget import BudgetPolicy
from sentinel.catalog.base import REGISTRY, Severity, validate_registry
from sentinel.grade import (
    EXIT_GATE_FAILED,
    EXIT_HARNESS_ERROR,
    EXIT_OK,
    run_scan,
    unverifiable_rules,
)
from sentinel.plan import build_plan
from sentinel.plan import render_json as render_plan_json
from sentinel.plan import render_text as render_plan_text
from sentinel.report import FORMATS
from sentinel.report.text import render as render_text

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=f"Conformance harness for MCP {SPEC_REVISION}.",
)
catalog_app = typer.Typer(no_args_is_help=True, help="Inspect the rule catalog.")
fixture_app = typer.Typer(no_args_is_help=True, help="Run the oracle fixture servers.")
app.add_typer(catalog_app, name="catalog")
app.add_typer(fixture_app, name="fixture")

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]


@app.callback()
def main() -> None:
    """Grade an MCP server against the normative specification."""


@app.command()
def version() -> None:
    """Print the harness version and the spec revision it grades against."""
    typer.echo(f"sentinel {__version__} (grades MCP {SPEC_REVISION})")


def _fail(message: str) -> typer.Exit:
    typer.echo(f"sentinel: {message}", err=True)
    return typer.Exit(EXIT_HARNESS_ERROR)


def _tls(insecure: bool, ca_bundle: pathlib.Path | None) -> bool | str:
    if insecure and ca_bundle is not None:
        raise _fail("--insecure and --ca-bundle contradict each other; pass one")
    if insecure:
        # A scan of a server whose certificate you did not check is a scan you
        # cannot attribute: anything on the path could have answered, and the
        # report would name the endpoint you meant rather than the one you got.
        typer.echo(
            "sentinel: WARNING --insecure disables TLS certificate verification. "
            "Any host on the path can answer for this endpoint, so the findings "
            "below cannot be attributed to it.",
            err=True,
        )
        return False
    return str(ca_bundle) if ca_bundle is not None else True


def _emit(rendered: str, out: pathlib.Path | None, summary: str | None) -> None:
    if out is not None:
        out.write_text(rendered)
        typer.echo(f"wrote {out}")
        # The summary still goes to the terminal: a scan whose only output is a
        # file a human never opens is a scan nobody reads.
        if summary is not None:
            typer.echo(summary, nl=False)
    else:
        typer.echo(rendered, nl=False)


@app.command()
def scan(
    endpoint: Annotated[
        str | None, typer.Option(help="The MCP endpoint to scan (or scan.endpoint in the config).")
    ] = None,
    gate: Annotated[
        str | None,
        typer.Option(
            help=(
                "Fail with exit 1 if any rule of this severity FAILs: must | should, "
                "or a beyond-spec category: security | style | ops."
            )
        ),
    ] = None,
    fmt: Annotated[
        str, typer.Option("--format", help="text | json | sarif | markdown | junit | html")
    ] = "text",
    out: Annotated[
        pathlib.Path | None, typer.Option(help="Write the report here instead of stdout.")
    ] = None,
    config: Annotated[
        pathlib.Path | None,
        typer.Option(help="A sentinel.toml. Default: ./sentinel.toml, then ./.sentinel.toml."),
    ] = None,
    baseline: Annotated[
        pathlib.Path | None,
        typer.Option(help="Gate only on findings absent from this baseline."),
    ] = None,
    snapshot: Annotated[
        pathlib.Path | None,
        typer.Option(help="A snapshot to compare against (enables the manifest-drift rule)."),
    ] = None,
    timeout: Annotated[float | None, typer.Option(help="Per-request timeout, seconds.")] = None,
    concurrency: Annotated[
        int | None, typer.Option(help="Rules evaluated in parallel, each on its own connection.")
    ] = None,
    token: Annotated[
        str | None,
        typer.Option(help="Bearer token. Prefer the SENTINEL_TOKEN environment variable."),
    ] = None,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable ANSI colour.")] = False,
    include_deprecated_rules: Annotated[
        bool | None,
        typer.Option(
            "--include-deprecated-rules/--exclude-deprecated-rules",
            help=(
                "Also run rules this catalog has deprecated. Each is reported with the "
                "rule that replaced it, so an archived report stays reproducible."
            ),
        ),
    ] = None,
    sarif_anchor: Annotated[
        str,
        typer.Option(
            help=(
                "Repo-relative file an SARIF annotation attaches to. A conformance "
                "finding is about a service, not a file, but GitHub code scanning "
                "requires a checked-in path."
            )
        ),
    ] = "README.md",
    schema_version: Annotated[
        int, typer.Option(help="JSON report schema: 2 (default) or 1 (legacy).")
    ] = 2,
    insecure: Annotated[
        bool,
        typer.Option("--insecure", help="Do not verify the target's TLS certificate."),
    ] = False,
    ca_bundle: Annotated[
        pathlib.Path | None,
        typer.Option(help="Verify the target's certificate against this CA bundle instead."),
    ] = None,
    proxy: Annotated[
        str | None, typer.Option(help="Send every request through this proxy URL.")
    ] = None,
    client_cert: Annotated[
        pathlib.Path | None,
        typer.Option(help="PEM file holding the client certificate and its key, for mTLS."),
    ] = None,
    retries: Annotated[
        int | None,
        typer.Option(
            help=(
                "Retry a request this many times when it never reached the server. "
                "A response the server actually sent is never retried."
            )
        ),
    ] = None,
    max_manifest_tokens: Annotated[
        int | None,
        typer.Option(help="Fail SENTINEL/OPS/manifest-token-budget above this many tokens."),
    ] = None,
    max_tool_tokens: Annotated[
        int | None,
        typer.Option(help="Fail SENTINEL/OPS/per-tool-token-budget above this many tokens."),
    ] = None,
    max_schema_depth: Annotated[
        int | None,
        typer.Option(help="Fail SENTINEL/OPS/schema-depth-budget above this nesting depth."),
    ] = None,
    max_p95_ms: Annotated[
        int | None,
        typer.Option(help="Fail SENTINEL/OPS/latency-budget above this p95, in milliseconds."),
    ] = None,
    safe: Annotated[
        bool | None,
        typer.Option(
            "--safe/--no-safe",
            help=(
                "For servers you do not own: never invoke a tool the server has not "
                "annotated readOnlyHint=true. Rules that need such a call report "
                "INDETERMINATE ('skipped in safe mode') instead of a verdict."
            ),
        ),
    ] = None,
    target_name: Annotated[
        str | None, typer.Option(help="A stable name for this target, used in fingerprints.")
    ] = None,
    no_exec: Annotated[
        bool,
        typer.Option(
            "--no-exec",
            help=(
                "Never run a command named in [graybox]. Token-shaped evidence still "
                "works; command-shaped evidence is reported as incomplete."
            ),
        ),
    ] = False,
    targets: Annotated[
        pathlib.Path | None,
        typer.Option(
            help=(
                "Scan every target in this fleet file (YAML or TOML), each with its own "
                "credential and gate, and write one report per target plus a rollup."
            )
        ),
    ] = None,
    out_dir: Annotated[
        pathlib.Path,
        typer.Option(help="With --targets: the directory for per-target reports and the rollup."),
    ] = pathlib.Path("sentinel-fleet"),
) -> None:
    """Scan an MCP server and grade it against the rule catalog."""
    from sentinel import baseline as baseline_mod
    from sentinel import snapshot as snapshot_mod
    from sentinel.config import load_policy
    from sentinel.report import render_report
    from sentinel.runner import ScanOptions, parse_gate, scan_target
    from sentinel.waivers import ConfigError

    try:
        policy = load_policy(
            config=config,
            cli={
                "endpoint": endpoint,
                "gate": gate,
                "timeout": timeout,
                "concurrency": concurrency,
                "retries": retries,
                "safe": safe,
                "include_deprecated": include_deprecated_rules,
            },
        )
        severity = parse_gate(policy.gate)
        loaded_baseline = baseline_mod.load(baseline) if baseline is not None else None
        loaded_snapshot = snapshot_mod.load(snapshot) if snapshot is not None else None
    except ConfigError as exc:
        raise _fail(str(exc)) from exc

    if fmt not in FORMATS:
        raise _fail(f"--format {fmt!r} is not one of {', '.join(FORMATS)}")
    verify = _tls(insecure, ca_bundle)
    budgets = BudgetPolicy(
        manifest_tokens=max_manifest_tokens,
        per_tool_tokens=max_tool_tokens,
        schema_depth=max_schema_depth,
        latency_p95_ms=max_p95_ms,
    )

    if targets is not None:
        from sentinel import fleet as fleet_mod

        try:
            fleet = fleet_mod.load_fleet(targets)
        except ConfigError as exc:
            raise _fail(str(exc)) from exc
        results = fleet_mod.scan_fleet(
            fleet,
            policy,
            concurrency=concurrency,
            options=lambda _t: {
                "verify": verify,
                "proxy": proxy,
                "client_cert": None if client_cert is None else str(client_cert),
                "budgets": budgets,
            },
        )
        extension = {"markdown": "md", "sarif": "sarif", "text": "txt"}.get(fmt, fmt)
        written = fleet_mod.write_reports(
            results,
            out_dir,
            fmt,
            lambda f, r: render_report(
                f, r, sarif_anchor=sarif_anchor, schema_version=schema_version, color=False
            ),
            extension,
        )
        summary = fleet_mod.rollup(results)
        typer.echo(summary.to_text(), nl=False)
        typer.echo(f"wrote {len(written)} file(s) to {out_dir}")
        raise typer.Exit(fleet_mod.exit_code(results))

    if policy.endpoint is None:
        raise _fail(
            "no endpoint: pass --endpoint, set SENTINEL_ENDPOINT, or set scan.endpoint "
            "in sentinel.toml"
        )

    try:
        report = scan_target(
            ScanOptions(
                endpoint=policy.endpoint,
                policy=policy,
                token=token or policy.token(),
                verify=verify,
                proxy=proxy,
                client_cert=None if client_cert is None else str(client_cert),
                budgets=budgets,
                baseline=loaded_baseline,
                snapshot=loaded_snapshot,
                target_name=target_name,
                allow_exec=not no_exec,
            )
        )
    except Exception as exc:
        raise _fail(f"the scan could not run: {exc}") from exc

    code = report.gate(severity)
    try:
        rendered = render_report(
            fmt,
            report,
            color=not no_color and out is None,
            sarif_anchor=sarif_anchor,
            schema_version=schema_version,
            gate_failed=code == EXIT_GATE_FAILED if severity is not None else None,
        )
    except ValueError as exc:
        raise _fail(str(exc)) from exc

    _emit(rendered, out, render_text(report, color=not no_color))
    raise typer.Exit(code)


baseline_app = typer.Typer(
    no_args_is_help=True, help="Adopt the scanner without fixing everything first."
)
app.add_typer(baseline_app, name="baseline")


def _scan_for_baseline(
    endpoint: str | None, config: pathlib.Path | None, token: str | None, timeout: float | None
) -> tuple[object, object]:
    from sentinel.config import load_policy
    from sentinel.runner import ScanOptions, scan_target
    from sentinel.waivers import ConfigError

    try:
        policy = load_policy(config=config, cli={"endpoint": endpoint, "timeout": timeout})
    except ConfigError as exc:
        raise _fail(str(exc)) from exc
    if policy.endpoint is None:
        raise _fail("no endpoint: pass --endpoint or set scan.endpoint in sentinel.toml")
    try:
        # No waivers and no baseline: a baseline records what the server does,
        # not what a policy chose to forgive.
        report = scan_target(
            ScanOptions(endpoint=policy.endpoint, policy=policy, token=token or policy.token())
        )
    except Exception as exc:
        raise _fail(f"the scan could not run: {exc}") from exc
    return report, policy


@baseline_app.command("create")
def baseline_create(
    out: Annotated[pathlib.Path, typer.Option(help="Where to write the baseline.")] = pathlib.Path(
        "sentinel-baseline.json"
    ),
    endpoint: Annotated[str | None, typer.Option(help="The MCP endpoint to baseline.")] = None,
    config: Annotated[pathlib.Path | None, typer.Option(help="A sentinel.toml.")] = None,
    token: Annotated[str | None, typer.Option(help="Bearer token.")] = None,
    timeout: Annotated[float | None, typer.Option(help="Per-request timeout, seconds.")] = None,
) -> None:
    """Record every current failure, so the gate fires only on what is new."""
    from sentinel import baseline as baseline_mod

    report, _ = _scan_for_baseline(endpoint, config, token, timeout)
    created = baseline_mod.create(report)  # type: ignore[arg-type]
    baseline_mod.save(created, out)
    typer.echo(f"wrote {out}: {len(created.entries)} known failure(s) on {created.target}")
    raise typer.Exit(EXIT_OK)


@baseline_app.command("prune")
def baseline_prune(
    baseline: Annotated[pathlib.Path, typer.Argument(help="The baseline to prune.")],
    endpoint: Annotated[str | None, typer.Option(help="The MCP endpoint to rescan.")] = None,
    config: Annotated[pathlib.Path | None, typer.Option(help="A sentinel.toml.")] = None,
    token: Annotated[str | None, typer.Option(help="Bearer token.")] = None,
    timeout: Annotated[float | None, typer.Option(help="Per-request timeout, seconds.")] = None,
) -> None:
    """Drop baseline entries that now pass, so the file only ever shrinks as you fix things."""
    from sentinel import baseline as baseline_mod
    from sentinel.waivers import ConfigError

    try:
        existing = baseline_mod.load(baseline)
    except ConfigError as exc:
        raise _fail(str(exc)) from exc
    report, _ = _scan_for_baseline(endpoint, config, token, timeout)
    pruned, dropped = baseline_mod.prune(existing, report)  # type: ignore[arg-type]
    baseline_mod.save(pruned, baseline)
    typer.echo(
        f"pruned {len(dropped)} fixed entr{'y' if len(dropped) == 1 else 'ies'}; "
        f"{len(pruned.entries)} remain"
    )
    raise typer.Exit(EXIT_OK)


@app.command("snapshot")
def snapshot_command(
    endpoint: Annotated[str, typer.Option(help="The MCP endpoint to record.")],
    out: Annotated[pathlib.Path, typer.Option(help="Where to write the snapshot.")],
    timeout: Annotated[float, typer.Option(help="Per-request timeout, seconds.")] = 10.0,
    token: Annotated[str | None, typer.Option(help="Bearer token.")] = None,
    insecure: Annotated[bool, typer.Option("--insecure", help="Do not verify TLS.")] = False,
    ca_bundle: Annotated[pathlib.Path | None, typer.Option(help="CA bundle.")] = None,
) -> None:
    """Record what a server advertises, to detect it changing later."""
    from sentinel import snapshot as snapshot_mod
    from sentinel.probe.client import Probe
    from sentinel.waivers import ConfigError

    verify = _tls(insecure, ca_bundle)
    try:
        bearer = token or os.environ.get("SENTINEL_TOKEN")
        with Probe(endpoint, timeout=timeout, bearer_token=bearer, verify=verify) as probe:
            taken = snapshot_mod.capture(probe)
    except ConfigError as exc:
        raise _fail(str(exc)) from exc
    except Exception as exc:
        raise _fail(f"the snapshot could not be taken: {exc}") from exc
    snapshot_mod.save(taken, out)
    typer.echo(f"wrote {out}: {len(taken.tools)} tool(s), manifest {taken.manifest_hash[:16]}")
    raise typer.Exit(EXIT_OK)


@app.command("diff")
def diff_command(
    snapshot: Annotated[pathlib.Path, typer.Argument(help="The snapshot to compare against.")],
    endpoint: Annotated[
        str | None, typer.Option(help="The live endpoint. Default: the one in the snapshot.")
    ] = None,
    gate: Annotated[
        bool,
        typer.Option("--gate", help="Exit 1 on any high-severity change (rug pull, wider scope)."),
    ] = False,
    fmt: Annotated[str, typer.Option("--format", help="text | json")] = "text",
    out: Annotated[pathlib.Path | None, typer.Option(help="Write the report here.")] = None,
    timeout: Annotated[float, typer.Option(help="Per-request timeout, seconds.")] = 10.0,
    token: Annotated[str | None, typer.Option(help="Bearer token.")] = None,
    insecure: Annotated[bool, typer.Option("--insecure", help="Do not verify TLS.")] = False,
    ca_bundle: Annotated[pathlib.Path | None, typer.Option(help="CA bundle.")] = None,
) -> None:
    """Compare a live server to a snapshot and classify every change.

    Exits 1 only with --gate and only on a high-severity change. Run it on a
    schedule against a third-party server you depend on and do not control.
    """
    from sentinel import snapshot as snapshot_mod
    from sentinel.probe.client import Probe
    from sentinel.waivers import ConfigError

    if fmt not in ("text", "json"):
        raise _fail(f"--format {fmt!r} is not one of text, json")
    verify = _tls(insecure, ca_bundle)
    try:
        before = snapshot_mod.load(snapshot)
        target = endpoint or before.endpoint
        bearer = token or os.environ.get("SENTINEL_TOKEN")
        with Probe(target, timeout=timeout, bearer_token=bearer, verify=verify) as probe:
            after = snapshot_mod.capture(probe)
    except ConfigError as exc:
        raise _fail(str(exc)) from exc
    except Exception as exc:
        raise _fail(f"the diff could not run: {exc}") from exc

    changes = snapshot_mod.diff(before, after)
    if fmt == "json":
        rendered = json.dumps(snapshot_mod.render_json(changes, before, after), indent=2) + "\n"
    else:
        rendered = snapshot_mod.render_text(changes, before, after)
    _emit(rendered, out, snapshot_mod.render_text(changes, before, after))
    high = any(c.level is snapshot_mod.Level.HIGH for c in changes)
    raise typer.Exit(EXIT_GATE_FAILED if gate and high else EXIT_OK)


@app.command("registry-scan")
def registry_scan(
    out_dir: Annotated[
        pathlib.Path, typer.Option(help="Directory for results.jsonl, summary.json, summary.md.")
    ] = pathlib.Path("registry-scan"),
    registry: Annotated[
        str, typer.Option(help="Registry base URL.")
    ] = "https://registry.modelcontextprotocol.io",
    listing: Annotated[
        pathlib.Path | None,
        typer.Option(
            help=(
                "Read the listing from this JSON file (a GET /v0.1/servers page or a "
                "list of entries) instead of the registry."
            )
        ),
    ] = None,
    concurrency: Annotated[
        int,
        typer.Option(help="Hosts scanned in parallel. Each host gets one connection at a time."),
    ] = 8,
    timeout: Annotated[float, typer.Option(help="Per-request timeout, seconds.")] = 10.0,
    limit: Annotated[int | None, typer.Option(help="Scan at most this many endpoints.")] = None,
) -> None:
    """Scan every remote server in the MCP registry, in safe mode, and summarize."""
    import datetime

    from sentinel import population

    try:
        if listing is not None:
            raw = json.loads(listing.read_text())
            entries = raw.get("servers", []) if isinstance(raw, dict) else raw
        else:
            entries = list(population.fetch_listing(registry))
    except Exception as exc:
        typer.echo(f"sentinel: could not read the registry listing: {exc}", err=True)
        raise typer.Exit(EXIT_HARNESS_ERROR) from exc

    targets = population.targets_from_listing(entries)
    listed = len({t.server for t in targets})
    if limit is not None:
        targets = targets[:limit]
    typer.echo(
        f"{len(entries)} registry entries; {listed} servers with a remote endpoint; "
        f"scanning {len(targets)} endpoint(s) across {len({t.host for t in targets})} host(s)",
        err=True,
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl = out_dir / "results.jsonl"
    jsonl.write_text("")
    done = 0

    def record(result: population.Result) -> None:
        nonlocal done
        done += 1
        with jsonl.open("a") as fh:
            fh.write(population.to_jsonl([result]))
        typer.echo(f"[{done}/{len(targets)}] {result.classification:<12} {result.url}", err=True)

    results = population.scan_population(
        targets, concurrency=concurrency, timeout=timeout, on_result=record
    )
    scanned_at = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d")
    summary = population.summarize(results, listed=listed, scanned_at=scanned_at)
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (out_dir / "summary.md").write_text(population.render_markdown(summary))
    typer.echo(population.render_markdown(summary))
    raise typer.Exit(EXIT_OK)


@app.command()
def migrate(
    endpoint: Annotated[str, typer.Option(help="The MCP endpoint to size a migration for.")],
    fmt: Annotated[str, typer.Option("--format", help="text | json")] = "text",
    out: Annotated[
        pathlib.Path | None, typer.Option(help="Write the report here instead of stdout.")
    ] = None,
    timeout: Annotated[float, typer.Option(help="Per-request timeout, seconds.")] = 10.0,
    token: Annotated[
        str | None, typer.Option(help="Bearer token to present to the target.")
    ] = None,
) -> None:
    """Size the migration to 2026-07-28 for a server built against an older revision.

    Always exits 0 unless the harness itself broke. A migration report describes
    work, and work is not a verdict: a team should be able to run this against a
    server they already know is non-conformant without CI going red twice for
    the same reason. `scan --gate must` is where a verdict belongs.
    """
    try:
        report = run_scan(endpoint, timeout=timeout, bearer_token=token)
    except Exception as exc:
        typer.echo(f"sentinel: the scan could not run: {exc}", err=True)
        raise typer.Exit(EXIT_HARNESS_ERROR) from exc

    plan_ = build_plan(report)
    if fmt == "text":
        rendered = render_plan_text(plan_) + "\n"
    elif fmt == "json":
        rendered = json.dumps(render_plan_json(plan_), indent=2) + "\n"
    else:
        typer.echo(f"--format {fmt!r} is not one of text, json", err=True)
        raise typer.Exit(EXIT_HARNESS_ERROR)

    if out is not None:
        out.write_text(rendered)
        typer.echo(f"wrote {out}")
        typer.echo(render_plan_text(plan_))
    else:
        typer.echo(rendered, nl=False)

    raise typer.Exit(EXIT_OK)


@app.command()
def deprecations(
    endpoint: Annotated[str, typer.Option(help="The MCP endpoint to inventory.")],
    as_of: Annotated[
        str | None,
        typer.Option(help="Compute remaining windows against this date (YYYY-MM-DD)."),
    ] = None,
    fmt: Annotated[str, typer.Option("--format", help="text | json")] = "text",
    out: Annotated[pathlib.Path | None, typer.Option(help="Write the report here.")] = None,
    timeout: Annotated[float, typer.Option(help="Per-request timeout, seconds.")] = 10.0,
    token: Annotated[str | None, typer.Option(help="Bearer token.")] = None,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable ANSI colour.")] = False,
) -> None:
    """Inventory the deprecated features a server still depends on.

    This never fails a gate. A deprecated feature that still works is a
    migration to plan, not a defect to block on, and conflating the two would
    make the inventory something people route around.
    """
    import datetime

    if as_of is None:
        stamp = datetime.date.today()
    else:
        try:
            stamp = datetime.date.fromisoformat(as_of)
        except ValueError:
            typer.echo(f"--as-of {as_of!r} is not YYYY-MM-DD; try 2026-09-23", err=True)
            raise typer.Exit(EXIT_HARNESS_ERROR) from None

    from sentinel.catalog.deprecations import build_inventory, render_json, render_text
    from sentinel.probe.client import Probe

    try:
        with Probe(endpoint, timeout=timeout, bearer_token=token) as probe:
            inventory = build_inventory(probe, stamp)
    except Exception as exc:
        typer.echo(f"sentinel: the inventory could not run: {exc}", err=True)
        raise typer.Exit(EXIT_HARNESS_ERROR) from exc

    if fmt == "text":
        rendered = render_text(inventory, color=not no_color and out is None)
    elif fmt == "json":
        rendered = json.dumps(render_json(inventory), indent=2) + "\n"
    else:
        typer.echo(f"--format {fmt!r} is not one of text, json", err=True)
        raise typer.Exit(EXIT_HARNESS_ERROR)

    if out is not None:
        out.write_text(rendered)
        typer.echo(f"wrote {out}")
        typer.echo(render_text(inventory, color=not no_color), nl=False)
    else:
        typer.echo(rendered, nl=False)

    raise typer.Exit(EXIT_OK)


@catalog_app.command("validate")
def catalog_validate() -> None:
    """Check that every rule declares an id, citation, severity and remediation."""
    problems = validate_registry()
    if problems:
        for p in problems:
            typer.echo(f"{p.rule_id}: {p.problem}", err=True)
        typer.echo(
            f"\n{len(problems)} problem(s) in {len(REGISTRY.all(include_deprecated=True))} rules",
            err=True,
        )
        raise typer.Exit(EXIT_HARNESS_ERROR)

    live = REGISTRY.all()
    must = REGISTRY.by_severity(Severity.MUST)
    unverifiable = unverifiable_rules()
    # len(REGISTRY) counts deprecated rules too. Reporting that as the catalog
    # size would overstate what a scan actually runs, so the headline is the
    # live count and the deprecated ones get their own line.
    typer.echo(
        f"{len(live)} rules validate: {len(must)} MUST, "
        f"{len(REGISTRY.by_severity(Severity.SHOULD))} SHOULD"
    )
    retired = [r for r in REGISTRY.all(include_deprecated=True) if r.is_deprecated]
    if retired:
        typer.echo(
            f"{len(retired)} deprecated rule(s) keep their ids and are skipped unless "
            "--include-deprecated-rules is passed:"
        )
        for r in retired:
            typer.echo(f"  {r.id} -> {r.superseded_by}")
    typer.echo(
        f"{len(unverifiable)} MUST rule(s) are UNVERIFIABLE black-box and always "
        "report INDETERMINATE:"
    )
    for r in unverifiable:
        typer.echo(f"  {r.id}")
    raise typer.Exit(EXIT_OK)


@catalog_app.command("list")
def catalog_list(
    severity: Annotated[str | None, typer.Option(help="must | should | may")] = None,
) -> None:
    """List the rule catalog."""
    rules = REGISTRY.all()
    if severity is not None:
        rules = [r for r in rules if r.severity.value == severity.lower()]
    for r in rules:
        typer.echo(f"{r.id}\n    {r.title}\n    {r.verifiability.value} · {r.citation}")
    raise typer.Exit(EXIT_OK)


@fixture_app.command("serve")
def fixture_serve(
    profile: Annotated[str, typer.Option(help="nonconformant | conformant | partial")],
    port: Annotated[int | None, typer.Option(help="Port to listen on.")] = None,
) -> None:
    """Run one of the oracle fixture servers."""
    if profile not in ("nonconformant", "conformant", "partial"):
        typer.echo(
            f"--profile {profile!r} is not 'nonconformant', 'conformant' or 'partial'", err=True
        )
        raise typer.Exit(EXIT_HARNESS_ERROR)

    fixtures = REPO_ROOT / "fixtures"
    if not (fixtures / "server" / f"{profile}.py").exists():
        typer.echo(f"sentinel: cannot find the fixtures at {fixtures}", err=True)
        raise typer.Exit(EXIT_HARNESS_ERROR)

    argv = [sys.executable, "-m", f"server.{profile}"]
    if port is not None:
        argv.append(str(port))

    # Run as a module from the fixtures directory so the package's relative
    # imports resolve, and so the fixture keeps importing nothing from
    # `sentinel` — a fixture sharing code with the harness could hide a bug from
    # both sides.
    raise typer.Exit(subprocess.call(argv, cwd=fixtures))


if __name__ == "__main__":  # pragma: no cover - module-level entrypoint
    app()
