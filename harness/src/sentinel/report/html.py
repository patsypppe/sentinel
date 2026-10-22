"""HTML: one self-contained file, readable offline.

No external request of any kind: no font, no script, no stylesheet, no image. The
whole point of a conformance report is that someone can attach it to a ticket and
a reviewer on a locked-down network can open it. Colours follow the system theme.
"""

from __future__ import annotations

import html

from sentinel.catalog.base import Namespace, Outcome
from sentinel.grade import Finding, ScanReport

__all__ = ["render"]

STYLE = """
:root{--bg:#fff;--fg:#1b1f24;--muted:#59636e;--line:#d1d9e0;--fail:#cf222e;--ok:#1a7f37;
--warn:#9a6700;--card:#f6f8fa}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9198a1;
--line:#30363d;--fail:#ff7b72;--ok:#3fb950;--warn:#d29922;--card:#161b22}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,sans-serif}main{max-width:900px;margin:0 auto;padding:24px 16px}
h1{font-size:1.4rem;margin:0 0 4px}h2{font-size:1.05rem;margin:28px 0 8px}
.sub{color:var(--muted);margin:0 0 16px;word-break:break-all}
.verdict{display:inline-block;padding:2px 10px;border-radius:12px;font-weight:600;color:#fff}
.v-fail{background:var(--fail)}.v-pass{background:var(--ok)}
.stats{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}
.stat{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:6px 12px}
.stat b{display:block;font-size:1.2rem}
.card{border:1px solid var(--line);border-radius:8px;padding:10px 14px;margin:8px 0;
background:var(--card)}
.card.fail{border-left:4px solid var(--fail)}.card.warn{border-left:4px solid var(--warn)}
code{font:13px ui-monospace,monospace;word-break:break-all}
.k{color:var(--muted)}details{margin:8px 0}summary{cursor:pointer;font-weight:600}
ul{padding-left:20px}a{color:inherit}
"""


def _e(text: object) -> str:
    return html.escape(str(text), quote=True)


def _card(f: Finding, kind: str) -> str:
    cite = ""
    if f.rule.namespace is Namespace.MCP and f.rule.citation:
        cite = f' · <a href="{_e(f.rule.citation)}" rel="noreferrer">spec</a>'
    extra = ""
    if f.waiver_expired is not None:
        extra += (
            f'<p class="k">Waiver expired {_e(f.waiver_expired.expires_at.isoformat())}: '
            f"{_e(f.waiver_expired.reason)}</p>"
        )
    return (
        f'<div class="card {kind}"><code>{_e(f.rule.id)}</code>'
        f"<div>{_e(f.rule.title)}</div>"
        f'<div><span class="k">Observed:</span> {_e(f.result.detail)}</div>'
        f'<div><span class="k">Fix:</span> {_e(f.rule.remediation)}{cite}</div>{extra}</div>'
    )


def render(report: ScanReport, *, gate_failed: bool | None = None) -> str:
    fails = report.by_outcome(Outcome.FAIL)
    gating = [f for f in fails if not f.suppressed]
    accepted = [f for f in fails if f.suppressed]
    if gate_failed is None:
        gate_failed = bool(gating)
    passes = report.by_outcome(Outcome.PASS)
    indeterminate = report.indeterminate
    not_applicable = report.by_outcome(Outcome.NOT_APPLICABLE)

    def stat(label: str, n: int) -> str:
        return f'<div class="stat"><b>{n}</b>{_e(label)}</div>'

    parts = [
        "<!doctype html><html lang=en><head><meta charset=utf-8>",
        '<meta name=viewport content="width=device-width,initial-scale=1">',
        f"<title>sentinel · {_e(report.target)}</title><style>{STYLE}</style></head><body><main>",
        f"<h1>sentinel scan · MCP {_e(report.spec_revision)} "
        f'<span class="verdict {"v-fail" if gate_failed else "v-pass"}">'
        f"{'FAIL' if gate_failed else 'PASS'}</span></h1>",
        f'<p class="sub">{_e(report.target)}'
        + (
            f" · manifest <code>{_e(report.manifest_hash[:16])}</code>"
            if report.manifest_hash
            else ""
        )
        + f" · {len(report.findings)} rules in {report.elapsed_s:.1f}s</p>",
        '<div class="stats">',
        stat("passing", len(passes)),
        stat("failing", len(gating)),
        stat("accepted", len(accepted)),
        stat("indeterminate", len(indeterminate)),
        stat("not applicable", len(not_applicable)),
        "</div>",
    ]
    if gating:
        parts.append("<h2>Failing</h2>")
        parts.extend(_card(f, "fail") for f in gating)
    if report.waiver_notes:
        parts.append("<h2>Waivers</h2><ul>")
        parts.extend(f"<li>{_e(n)}</li>" for n in report.waiver_notes)
        parts.append("</ul>")
    if report.fixed:
        parts.append(f"<h2>Fixed since the baseline ({len(report.fixed)})</h2>")
    if accepted:
        parts.append(f"<details><summary>Accepted ({len(accepted)})</summary><ul>")
        for f in accepted:
            why = (
                f"waived until {f.waived_by.expires_at.isoformat()}: {f.waived_by.reason}"
                if f.waived_by is not None
                else "baselined"
            )
            parts.append(f"<li><code>{_e(f.rule.id)}</code> — {_e(why)}</li>")
        parts.append("</ul></details>")
    if indeterminate:
        parts.append(
            f"<details open><summary>Indeterminate ({len(indeterminate)}) — not verifiable "
            "from the wire, and not passes</summary>"
        )
        parts.extend(_card(f, "warn") for f in indeterminate)
        parts.append("</details>")
    if passes:
        parts.append(f"<details><summary>Passing ({len(passes)})</summary><ul>")
        parts.extend(f"<li><code>{_e(f.rule.id)}</code></li>" for f in passes)
        parts.append("</ul></details>")
    if not_applicable:
        parts.append(f"<details><summary>Not applicable ({len(not_applicable)})</summary><ul>")
        parts.extend(
            f"<li><code>{_e(f.rule.id)}</code> — {_e(f.result.detail)}</li>" for f in not_applicable
        )
        parts.append("</ul></details>")
    parts.append("</main></body></html>\n")
    return "".join(parts)
