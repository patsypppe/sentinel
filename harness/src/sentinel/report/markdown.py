"""Markdown: the pull-request comment and `$GITHUB_STEP_SUMMARY` target.

Layout is decided by who is reading. The verdict and every gating failure are
unwrapped, because they are the reason anyone opened the comment. Everything else
sits inside `<details>`. GitHub rejects a comment over 65,536 characters, so the
document is hard-capped below that and truncates from the **least** severe end,
saying how much it dropped; a report that is cut from the top loses its point.
"""

from __future__ import annotations

from sentinel.catalog.base import Namespace, Outcome
from sentinel.grade import Finding, ScanReport

__all__ = ["MAX_CHARS", "render"]

#: GitHub's comment limit is 65,536. Leave headroom for the truncation notice.
MAX_CHARS = 60_000


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _citation(f: Finding) -> str:
    if f.rule.namespace is Namespace.MCP and f.rule.citation:
        return f" · [spec]({f.rule.citation})"
    return ""


def _failure_block(f: Finding) -> str:
    lines = [f"#### ❌ `{f.rule.id}`", f"{f.rule.title}", ""]
    lines.append(f"**Observed:** {f.result.detail}")
    lines.append(f"**Fix:** {f.rule.remediation}{_citation(f)}")
    if f.waiver_expired is not None:
        lines.append(
            f"> ⚠️ A waiver for this rule **expired {f.waiver_expired.expires_at.isoformat()}** "
            f"({f.waiver_expired.reason}). The finding gates again."
        )
    if f.rule_is_new:
        lines.append("> **Note:** this rule did not exist when the baseline was taken.")
    return "\n".join(lines) + "\n"


def _section(title: str, rows: list[str], *, open_: bool = False) -> str:
    if not rows:
        return ""
    attr = " open" if open_ else ""
    body = "\n".join(rows)
    return f"<details{attr}><summary>{title} ({len(rows)})</summary>\n\n{body}\n\n</details>\n"


def render(report: ScanReport, *, gate_failed: bool | None = None) -> str:
    fails = report.by_outcome(Outcome.FAIL)
    gating = [f for f in fails if not f.suppressed]
    accepted = [f for f in fails if f.suppressed]
    passes = report.by_outcome(Outcome.PASS)
    indeterminate = report.indeterminate
    not_applicable = report.by_outcome(Outcome.NOT_APPLICABLE)

    if gate_failed is None:
        gate_failed = bool(gating)
    verdict = "❌ **FAIL**" if gate_failed else "✅ **PASS**"
    header = [
        f"## sentinel · MCP {report.spec_revision} · {verdict}",
        "",
        f"`{report.target}`  ·  {len(report.findings)} rules in {report.elapsed_s:.1f}s  ·  "
        f"{len(passes)} pass · {len(gating)} failing · {len(accepted)} accepted · "
        f"{len(indeterminate)} indeterminate · {len(not_applicable)} n/a",
        "",
    ]
    if report.manifest_hash:
        header.append(f"Manifest `{report.manifest_hash[:16]}`")
        header.append("")

    blocks: list[str] = ["\n".join(header)]
    blocks.extend(_failure_block(f) for f in gating)
    if report.fixed:
        blocks.append(
            f"🎉 **{len(report.fixed)} finding(s) fixed** since the baseline. "
            "Run `sentinel baseline prune` to drop them.\n"
        )
    if report.waiver_notes:
        blocks.append(
            "**Waivers**\n\n" + "\n".join(f"- {note}" for note in report.waiver_notes) + "\n"
        )
    blocks.append(
        _section(
            "Accepted (waived or baselined)",
            [
                f"- `{f.rule.id}` — "
                + (
                    f"waived until {f.waived_by.expires_at.isoformat()}: {f.waived_by.reason}"
                    if f.waived_by is not None
                    else "baselined"
                )
                for f in accepted
            ],
        )
    )
    blocks.append(
        _section(
            "Indeterminate — not verifiable from the wire",
            [f"- `{f.rule.id}` — {f.result.detail}" for f in indeterminate],
        )
    )
    table = ["| Rule | Title |", "|---|---|"] + [
        f"| `{f.rule.id}` | {_cell(f.rule.title)} |" for f in passes
    ]
    if passes:
        blocks.append(
            f"<details><summary>Passing ({len(passes)})</summary>\n\n"
            + "\n".join(table)
            + "\n\n</details>\n"
        )
    blocks.append(
        _section(
            "Not applicable",
            [f"- `{f.rule.id}` — {f.result.detail}" for f in not_applicable],
        )
    )

    out: list[str] = []
    used = 0
    dropped = 0
    for block in (b for b in blocks if b):
        if used + len(block) > MAX_CHARS:
            dropped += 1
            continue
        out.append(block)
        used += len(block) + 1
    if dropped:
        out.append(
            f"\n_{dropped} section(s) omitted to stay under GitHub's comment size limit. "
            "They were the least severe; run `sentinel scan --format html` for everything._\n"
        )
    return "\n".join(out)
