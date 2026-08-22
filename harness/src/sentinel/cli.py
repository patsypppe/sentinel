"""Typer entrypoint for the `sentinel` command.

Exit-code contract (docs/HANDOFF.md §8.8), enforced here and nowhere else:

* ``scan --gate must`` exits **1** if any MUST rule FAILs, **0** otherwise.
* ``INDETERMINATE`` never fails a gate, but is always printed.
* Every other subcommand reserves non-zero for *harness* errors, so CI can
  distinguish "the server is wrong" from "the scanner broke".
"""

from __future__ import annotations

import typer

from sentinel import SPEC_REVISION, __version__

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=f"Conformance harness for MCP {SPEC_REVISION}.",
)


@app.callback()
def main() -> None:
    """Grade an MCP server against the normative specification.

    Declared explicitly so Typer keeps subcommand dispatch even when only one
    command is registered; without it a single-command app collapses into the
    root and `sentinel version` becomes an unexpected argument.
    """


@app.command()
def version() -> None:
    """Print the harness version and the spec revision it grades against."""
    typer.echo(f"sentinel {__version__} (grades MCP {SPEC_REVISION})")


if __name__ == "__main__":  # pragma: no cover - module-level entrypoint
    app()
