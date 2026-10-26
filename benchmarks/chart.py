"""Draw benchmarks/POPULAR_SERVERS.json as an SVG: share of parameters documented, per server.

    uv run python benchmarks/chart.py

Plain string templating, no plotting library, so the chart rebuilds anywhere the benchmark runs.
"""

from __future__ import annotations

import json
import pathlib
from xml.sax.saxutils import escape

HERE = pathlib.Path(__file__).resolve().parent
ROW, LEFT, BAR, TOP = 22, 190, 360, 62
GOOD, WARN, BAD, OBV = "#2e9d5b", "#e0a030", "#d6453d", "#b9c2cc"


def render(rows: list[dict[str, object]]) -> str:
    data = sorted(
        (r for r in rows if r.get("status") == "ok" and r["params"]),  # type: ignore[index]
        key=lambda r: int(r["params_undocumented"]) / int(r["params"]),  # type: ignore[arg-type]
        reverse=True,
    )
    height = TOP + ROW * len(data) + 34
    width = LEFT + BAR + 170
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        'font-family="Helvetica,Arial,sans-serif" font-size="12">',
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
        '<text x="16" y="26" font-size="16" font-weight="bold" fill="#111">'
        "Are tool parameters documented where a model can read them?</text>",
        '<text x="16" y="45" fill="#555">Where each parameter is documented, '
        f"{len(data)} published MCP servers, linted by Sentinel</text>",
    ]
    for i, r in enumerate(data):
        schema, prose, obvious, none = (
            int(r["params_schema"]),  # type: ignore[arg-type]
            int(r["params_prose"]),  # type: ignore[arg-type]
            int(r["params_obvious"]),  # type: ignore[arg-type]
            int(r["params_undocumented"]),  # type: ignore[arg-type]
        )
        total = schema + prose + obvious + none
        y = TOP + i * ROW
        out += [
            f'<text x="{LEFT - 8}" y="{y + 14}" text-anchor="end" fill="#222">'
            f"{escape(str(r['server']))}</text>",
            f'<rect x="{LEFT}" y="{y + 2}" width="{BAR}" height="14" fill="#eee"/>',
        ]
        x = LEFT
        for count, colour in ((schema, GOOD), (prose, WARN), (obvious, OBV), (none, BAD)):
            w = round(BAR * count / total)
            if count and w:
                out.append(f'<rect x="{x}" y="{y + 2}" width="{w}" height="14" fill="{colour}"/>')
                x += w
        label = f"{none} of {total} undocumented" if none else f"all {total} documented"
        out.append(f'<text x="{LEFT + BAR + 8}" y="{y + 14}" fill="#333">{label}</text>')
    ly = height - 14
    for x, colour, label in (
        (LEFT, GOOD, "in the schema"),
        (LEFT + 105, WARN, "description text only"),
        (LEFT + 255, OBV, "self-evident name"),
        (LEFT + 380, BAD, "documented nowhere"),
    ):
        out += [
            f'<rect x="{x}" y="{ly - 10}" width="12" height="12" fill="{colour}"/>',
            f'<text x="{x + 18}" y="{ly}" fill="#333">{label}</text>',
        ]
    out.append("</svg>")
    return "\n".join(out) + "\n"


def main() -> int:
    rows = json.loads((HERE / "POPULAR_SERVERS.json").read_text())
    (HERE / "popular_servers.svg").write_text(render(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
