"""Typer entrypoint for the `sentinel` command.

Exit-code contract (docs/HANDOFF.md §8.8), enforced here and nowhere else:

* ``scan --gate must`` exits **1** if any MUST rule FAILs, **0** otherwise.
* ``INDETERMINATE`` never fails a gate, but is always printed.
* Every other subcommand reserves non-zero for *harness* errors, so CI can
  distinguish "the server is wrong" from "the scanner broke".
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
from typing import Annotated

import typer

from sentinel import SPEC_REVISION, __version__
from sentinel.catalog.base import REGISTRY, Severity, validate_registry
from sentinel.grade import (
    EXIT_HARNESS_ERROR,
    EXIT_OK,
    run_scan,
    unverifiable_rules,
)
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


@app.command()
def scan(
    endpoint: Annotated[str, typer.Option(help="The MCP endpoint to scan.")],
    gate: Annotated[
        str | None,
        typer.Option(help="Fail with exit 1 if any rule of this severity FAILs: must | should."),
    ] = None,
    fmt: Annotated[
        str, typer.Option("--format", help="text | json | sarif")
    ] = "text",
    out: Annotated[
        pathlib.Path | None, typer.Option(help="Write the report here instead of stdout.")
    ] = None,
    timeout: Annotated[float, typer.Option(help="Per-request timeout, seconds.")] = 10.0,
    token: Annotated[
        str | None, typer.Option(help="Bearer token to present to the target.")
    ] = None,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable ANSI colour.")] = False,
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
) -> None:
    """Scan an MCP server and grade it against the rule catalog."""
    severity: Severity | None = None
    if gate is not None:
        try:
            severity = Severity(gate.lower())
        except ValueError:
            typer.echo(
                f"--gate {gate!r} is not a severity; use 'must' or 'should'", err=True
            )
            raise typer.Exit(EXIT_HARNESS_ERROR) from None

    try:
        report = run_scan(endpoint, timeout=timeout, bearer_token=token)
    except Exception as exc:
        typer.echo(f"sentinel: the scan could not run: {exc}", err=True)
        raise typer.Exit(EXIT_HARNESS_ERROR) from exc

    if fmt == "text":
        rendered = render_text(report, color=not no_color and out is None)
    elif fmt == "json":
        from sentinel.report.json_report import render as render_json

        rendered = json.dumps(render_json(report), indent=2) + "\n"
    elif fmt == "sarif":
        from sentinel.report.sarif import render as render_sarif

        rendered = json.dumps(render_sarif(report, anchor=sarif_anchor), indent=2) + "\n"
    else:
        typer.echo(f"--format {fmt!r} is not one of text, json, sarif", err=True)
        raise typer.Exit(EXIT_HARNESS_ERROR)

    if out is not None:
        out.write_text(rendered)
        typer.echo(f"wrote {out}")
        # The summary still goes to the terminal: a scan whose only output is a
        # file a human never opens is a scan nobody reads.
        typer.echo(render_text(report, color=not no_color), nl=False)
    else:
        typer.echo(rendered, nl=False)

    raise typer.Exit(report.gate(severity))


@catalog_app.command("validate")
def catalog_validate() -> None:
    """Check that every rule declares an id, citation, severity and remediation."""
    problems = validate_registry()
    if problems:
        for p in problems:
            typer.echo(f"{p.rule_id}: {p.problem}", err=True)
        typer.echo(f"\n{len(problems)} problem(s) in {len(REGISTRY)} rules", err=True)
        raise typer.Exit(EXIT_HARNESS_ERROR)

    must = REGISTRY.by_severity(Severity.MUST)
    unverifiable = unverifiable_rules()
    typer.echo(f"{len(REGISTRY)} rules validate: {len(must)} MUST, "
               f"{len(REGISTRY.by_severity(Severity.SHOULD))} SHOULD")
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
    profile: Annotated[str, typer.Option(help="nonconformant | conformant")],
    port: Annotated[int | None, typer.Option(help="Port to listen on.")] = None,
) -> None:
    """Run one of the oracle fixture servers."""
    if profile not in ("nonconformant", "conformant"):
        typer.echo(f"--profile {profile!r} is not 'nonconformant' or 'conformant'", err=True)
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
