"""Report rendering. One entry point, so every command offers the same formats."""

from __future__ import annotations

import json

from sentinel.grade import ScanReport

__all__ = ["FORMATS", "render_report"]

FORMATS = ("text", "json", "sarif", "markdown", "junit", "html")


def render_report(
    fmt: str,
    report: ScanReport,
    *,
    color: bool = False,
    sarif_anchor: str = "README.md",
    schema_version: int = 2,
    gate_failed: bool | None = None,
    gate: str | None = None,
) -> str:
    """Render `report` in `fmt`. Raises ValueError for an unknown format."""
    if fmt == "text":
        from sentinel.report.text import render

        return render(report, color=color)
    if fmt == "json":
        from sentinel.report.json_report import render as render_json

        verdict = None if gate is None else {"selected": gate, "failed": bool(gate_failed)}
        rendered = render_json(report, schema_version=schema_version, gate=verdict)
        return json.dumps(rendered, indent=2) + "\n"
    if fmt == "sarif":
        from sentinel.report.sarif import render as render_sarif

        return json.dumps(render_sarif(report, anchor=sarif_anchor), indent=2) + "\n"
    if fmt == "markdown":
        from sentinel.report.markdown import render as render_markdown

        return render_markdown(report, gate_failed=gate_failed)
    if fmt == "junit":
        from sentinel.report.junit import render as render_junit

        return render_junit(report)
    if fmt == "html":
        from sentinel.report.html import render as render_html

        return render_html(report, gate_failed=gate_failed)
    raise ValueError(f"--format {fmt!r} is not one of {', '.join(FORMATS)}")
