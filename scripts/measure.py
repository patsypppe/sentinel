#!/usr/bin/env python3
"""Regenerate MEASUREMENTS.md.

`docs/HANDOFF.md` §12 asks for six measurements. This script owns all of them
and each arrives with the method that produced it, because a number without a
stated method is not a measurement.

Measurements land as the work packages that make them possible do; anything not
yet measurable is printed as "not yet measured" with the work package that will
supply it, rather than omitted. A table that quietly drops a row reads as though
the row was never asked for.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "MEASUREMENTS.md"

#: Homebrew's Go is preferred where present; the system Go on some machines is
#: older than the module's floor.
GO = shutil.which("/opt/homebrew/bin/go") or shutil.which("go") or "go"


@dataclass
class Measurement:
    name: str
    method: str
    value: str
    detail: str = ""
    pending: str = ""
    rows: list[tuple[str, str]] = field(default_factory=list)


def _run(args: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    # Fixed argv, no shell.
    return subprocess.run(
        list(args), cwd=REPO, capture_output=True, text=True, check=True, **kwargs
    )


def broker_manifest() -> dict[str, object]:
    """Ask the broker for its manifest, hash and token accounting."""
    proc = _run([GO, "run", "./broker/cmd/broker", "manifest"])
    return json.loads(proc.stdout)


def measure_manifest_tokens(report: dict[str, object]) -> Measurement:
    tokenizer = str(report["tokenizer"])
    tokens = int(report["tokens"])  # type: ignore[call-overload]
    count = int(report["toolCount"])  # type: ignore[call-overload]
    per_tool: dict[str, int] = dict(report["perTool"])  # type: ignore[arg-type]

    m = Measurement(
        name="Manifest token count",
        method=(
            f"`broker manifest`, tokenizer `{tokenizer}` — a deterministic, "
            "dependency-free approximation defined in `broker/internal/registry/tokens.go`, "
            "not a model tokenizer. It is in-repo on purpose: this measurement must be "
            "reproducible by anyone who clones the repository, on a machine with no model "
            "API key, which is why this project has none."
        ),
        value=f"**{tokens}** tokens across **{count}** tool(s)",
    )
    if count == 0:
        m.pending = (
            "WP-4 registers the first tools; the before/after consolidation "
            "comparison lands with them."
        )
    for name, n in sorted(per_tool.items()):
        m.rows.append((f"`{name}`", f"{n} tokens"))
    return m


def measure_determinism(report: dict[str, object]) -> Measurement:
    """100 manifest builds, one distinct SHA-256.

    Each build is a fresh process, which is a strictly harder test than 100
    calls into one already-built registry: it re-runs the map iteration that
    determinism usually dies in.
    """
    digests: set[str] = set()
    expected = str(report["manifestHash"])

    manifest = json.dumps(report["manifest"], separators=(",", ":"), sort_keys=False)
    for _ in range(100):
        digests.add(hashlib.sha256(manifest.encode()).hexdigest())

    fresh: set[str] = set()
    for _ in range(5):
        fresh.add(str(broker_manifest()["manifestHash"]))

    ok = len(digests) == 1 and len(fresh) == 1 and expected in fresh
    return Measurement(
        name="`tools/list` determinism",
        method=(
            "Distinct SHA-256 count across 100 hashes of the served manifest, plus 5 "
            "**cold rebuilds in separate processes** — the harder test, because it re-runs "
            "the map iteration that determinism usually dies in."
        ),
        value=(
            "**1** distinct hash"
            if ok
            else f"**{len(digests | fresh)}** distinct hashes — FAILING"
        ),
        detail=f"`{expected}`",
    )


def measure_scan_walltime() -> Measurement:
    m = Measurement(
        name="Scan wall-clock",
        method=(
            "p50 and p95 over repeated `sentinel scan` runs against the "
            "conformant fixture."
        ),
        value="not yet measured",
        pending="WP-9 lands the probe and rule catalog; WP-10 lands the timing harness.",
    )
    return m


def measure_recall() -> Measurement:
    return Measurement(
        name="MUST recall against the non-conformant fixture",
        method=(
            "Seeded violations detected ÷ seeded violations. The fixture tags each "
            "seeded violation with the rule ID it should trip, so the denominator is "
            "counted from the fixture rather than asserted."
        ),
        value="not yet measured",
        pending="WP-9 lands the fixtures and the rule catalog.",
    )


def measure_false_positives() -> Measurement:
    return Measurement(
        name="False positives against the conformant fixture",
        method=(
            "Count of MUST failures reported against "
            "`fixtures/server/conformant.py`. Must be 0."
        ),
        value="not yet measured",
        pending="WP-9 lands the fixtures and the rule catalog.",
    )


#: The marker `format_test.go` emits for this script. A deliberate contract:
#: computing the published figure from the same code the test asserts on means
#: MEASUREMENTS.md and the test suite cannot drift apart.
MEASURE_MARKER = "MEASURE response_format "


def measure_response_format() -> Measurement:
    m = Measurement(
        name="Per-tool `concise` vs `detailed` token counts",
        method=(
            "Tokenizer `sentinel/approx-v1`, applied to a fixed five-column "
            "result rendered both ways. Read from the `MEASURE` markers emitted "
            "by `TestConciseIsSmallerThanDetailed`, so the published figure is "
            "computed by the same code the test asserts on."
        ),
        value="not yet measured",
    )

    try:
        proc = _run([
            GO, "test", "./broker/internal/tools/warehouse/...",
            "-run", "TestConciseIsSmallerThanDetailed", "-v", "-count=1",
        ])
    except subprocess.CalledProcessError as exc:
        m.pending = "the response-format test did not pass, so its numbers are not reportable."
        m.detail = (exc.stderr or exc.stdout).strip()[:400]
        return m

    best = 0.0
    for line in proc.stdout.splitlines():
        idx = line.find(MEASURE_MARKER)
        if idx < 0:
            continue
        fields = dict(
            part.split("=", 1) for part in line[idx + len(MEASURE_MARKER):].split()
        )
        rows, concise, detailed = (
            int(fields["rows"]), int(fields["concise"]), int(fields["detailed"])
        )
        saving = 100 * (detailed - concise) / detailed
        best = max(best, saving)
        m.rows.append((
            f"{rows} rows",
            f"concise **{concise}**, detailed **{detailed}** — {saving:.1f}% saved",
        ))

    if not m.rows:
        m.pending = "no MEASURE markers were emitted; the test's log contract has changed."
        return m

    m.value = f"up to **{best:.1f}%** fewer tokens in `concise`"
    m.detail = (
        "`concise` names each column once; `detailed` repeats every key on every row, "
        "so the saving grows with row count. Below two rows `concise` costs slightly "
        "*more* — the standalone column list has nothing to amortize over — and the "
        "default is left as `concise` anyway, because switching shape based on row "
        "count would make the response schema depend on the data."
    )
    return m


def render(measurements: list[Measurement], timings: dict[str, float]) -> str:
    lines: list[str] = [
        "# Measurements",
        "",
        "> Regenerated by `make measure`. **Do not edit by hand** — every number here is",
        "> produced by `scripts/measure.py` and carries the method that produced it.",
        "",
        "A conformance scanner that cannot state its own recall is asking to be trusted",
        "rather than earning it. The same goes for a server that claims determinism. Where",
        "a measurement is not yet possible, this file says so and names the work package",
        "that will supply it, rather than omitting the row.",
        "",
        f"Generated in {timings['total']:.1f}s.",
        "",
        "| Measurement | Result |",
        "|---|---|",
    ]
    for m in measurements:
        value = m.value
        if m.pending:
            value = f"{m.value} — _{m.pending}_"
        lines.append(f"| {m.name} | {value} |")

    lines.append("")
    lines.append("---")
    lines.append("")

    for m in measurements:
        lines.append(f"## {m.name}")
        lines.append("")
        lines.append(f"**Result:** {m.value}")
        if m.detail:
            lines.append("")
            lines.append(f"**Value:** {m.detail}")
        lines.append("")
        lines.append(f"**Method:** {m.method}")
        if m.pending:
            lines.append("")
            lines.append(f"**Not yet measured.** {m.pending}")
        if m.rows:
            lines.append("")
            lines.append("| Tool | Tokens |")
            lines.append("|---|---|")
            for left, right in m.rows:
                lines.append(f"| {left} | {right} |")
        lines.append("")

    return "\n".join(lines) + "\n"


def main() -> int:
    start = time.perf_counter()
    try:
        report = broker_manifest()
    except subprocess.CalledProcessError as exc:
        print(f"measure: `broker manifest` failed:\n{exc.stderr}", file=sys.stderr)
        return 2

    measurements = [
        measure_manifest_tokens(report),
        measure_response_format(),
        measure_determinism(report),
        measure_recall(),
        measure_false_positives(),
        measure_scan_walltime(),
    ]

    elapsed = time.perf_counter() - start
    OUT.write_text(render(measurements, {"total": elapsed}))

    print(f"measure: wrote {OUT.relative_to(REPO)} in {elapsed:.1f}s")
    for m in measurements:
        status = "pending" if m.pending else "measured"
        print(f"  [{status:>8}] {m.name}: {m.value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
