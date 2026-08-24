"""The human-readable scan report."""

from __future__ import annotations

from sentinel.catalog.base import Outcome, Severity, Verifiability
from sentinel.grade import Finding, ScanReport

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"

MARK = {
    Outcome.PASS: ("PASS", GREEN),
    Outcome.FAIL: ("FAIL", RED),
    Outcome.NOT_APPLICABLE: ("n/a ", DIM),
    Outcome.INDETERMINATE: ("????", YELLOW),
}


def render(report: ScanReport, *, color: bool = True) -> str:
    def paint(text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if color else text

    def label(f: Finding, ident: str, *, plain: bool = False) -> str:
        """A deprecated rule keeps its id and is marked, never hidden.

        `plain` is for lines the caller paints as a whole: painting the marker
        separately would RESET the enclosing colour mid-line.
        """
        if not f.rule.is_deprecated:
            return ident
        mark = "DEPRECATED" if plain else paint("DEPRECATED", YELLOW)
        return f"{mark} {ident}"

    def detail(f: Finding) -> str:
        """A deprecated finding names its successor where the finding is read."""
        if f.rule.is_deprecated and f.rule.superseded_by:
            return f"{f.result.detail} (superseded by {f.rule.superseded_by})"
        return f.result.detail

    lines: list[str] = []
    lines.append(paint(f"sentinel scan · MCP {report.spec_revision}", BOLD))
    lines.append(f"target: {report.endpoint}")
    lines.append("")

    # Failures first: a report whose first screen is passes buries its own point.
    failures = report.by_outcome(Outcome.FAIL)
    if failures:
        lines.append(paint(f"{len(failures)} FAILING", BOLD + RED))
        lines.append("")
        for f in failures:
            lines.append(f"  {paint('FAIL', RED)}  {label(f, paint(f.rule.id, BOLD))}")
            lines.append(f"        {f.rule.title}")
            lines.append(f"        {paint('observed:', DIM)}    {detail(f)}")
            lines.append(f"        {paint('remediation:', DIM)} {f.rule.remediation}")
            lines.append(f"        {paint('spec:', DIM)}        {paint(f.rule.citation, BLUE)}")
            if f.result.evidence:
                lines.append(f"        {paint('evidence:', DIM)}    {f.result.evidence[:200]}")
            lines.append("")

    indeterminate = report.indeterminate
    if indeterminate:
        lines.append(
            paint(
                f"{len(indeterminate)} INDETERMINATE — not verifiable from the wire",
                BOLD + YELLOW,
            )
        )
        lines.append(
            paint(
                "  These are MUST requirements this scan CANNOT settle. They are not passes.",
                DIM,
            )
        )
        lines.append("")
        for f in indeterminate:
            lines.append(f"  {paint('????', YELLOW)}  {label(f, paint(f.rule.id, BOLD))}")
            lines.append(f"        {f.rule.title}")
            lines.append(f"        {paint('why:', DIM)}  {detail(f)}")
            lines.append(f"        {paint('spec:', DIM)} {paint(f.rule.citation, BLUE)}")
            lines.append("")

    passes = report.by_outcome(Outcome.PASS)
    if passes:
        lines.append(paint(f"{len(passes)} passing", GREEN))
        for f in passes:
            lines.append(f"  {paint('PASS', GREEN)}  {label(f, f.rule.id)}")
        lines.append("")

    skipped = report.by_outcome(Outcome.NOT_APPLICABLE)
    if skipped:
        lines.append(paint(f"{len(skipped)} not applicable", DIM))
        for f in skipped:
            lines.append(
                paint(f"  n/a   {label(f, f.rule.id, plain=True)} — {detail(f)}", DIM)
            )
        lines.append("")

    lines.append(paint("─" * 72, DIM))
    must = report.counts(Severity.MUST)
    indet_color = YELLOW if must["indeterminate"] else DIM
    lines.append(
        f"MUST: {paint(str(must['pass']) + ' pass', GREEN)}, "
        f"{paint(str(must['fail']) + ' fail', RED if must['fail'] else DIM)}, "
        f"{paint(str(must['indeterminate']) + ' indeterminate', indet_color)}, "
        f"{must['not_applicable']} n/a"
    )
    should = report.counts(Severity.SHOULD)
    if any(should.values()):
        lines.append(
            f"SHOULD: {should['pass']} pass, {should['fail']} fail, "
            f"{should['not_applicable']} n/a"
        )
    lines.append(f"{len(report.findings)} rules in {report.elapsed_s:.2f}s")

    unverifiable = [
        f for f in report.findings if f.rule.verifiability is Verifiability.UNVERIFIABLE
    ]
    if unverifiable:
        lines.append("")
        lines.append(
            paint(
                f"{len(unverifiable)} MUST rule(s) cannot be verified black-box and were "
                "excluded from the gate.",
                DIM,
            )
        )

    return "\n".join(lines) + "\n"
