# Changelog

## 0.4.0

The harness stops being a one-shot grader and becomes something a team runs.

### Added: operating it

- **`sentinel.toml`**: endpoint, gate, timeouts, rule toggles, severity overrides, waivers.
  Precedence is CLI > `SENTINEL_*` > file > `extends` > default, tested cell by cell, and every
  resolved value records its source in the report.
- **Waivers** with a required `expires_at`. A malformed date is an error; an expired waiver stops
  applying and the finding fails again, labelled.
- **Severity overrides that can only tighten.** Demoting a MUST is rejected.
- **Baselines** (`baseline create`, `baseline prune`, `scan --baseline`): the gate fires only on
  new findings, and the report shows what was fixed. Finding fingerprints are
  `sha256(rule, target, evidence key)` and never contain a request id or timestamp.
- **`snapshot` / `diff`**: rug-pull detection. A rewritten tool description, a widened scope or a
  dropped read-only promise is high severity; `diff --gate` exits 1 on those.
- **Gray-box evidence** for the five unverifiable MUSTs: a wrong-audience token, a second
  principal, an egress capture, an effect counter, an audit verifier. Commands run with
  `shell=False`, a timeout and a minimal environment; `--no-exec` disables them. Absence of
  evidence is never a pass.
- **Fleet scans** (`scan --targets`): named, separately credentialed targets, each judged by its
  own gate, with a rollup. An unreachable target is an error for that target, never a pass.
- **Formats**: `markdown` (size-capped PR comment), `junit`, `html` (self-contained), JSON schema 2,
  SARIF with fingerprints and suppressions. `--also FORMAT=PATH` writes several from one scan.
- Rules run **concurrently**, each on its own connection; the report is identical regardless of
  completion order.

### Added: 17 rules

`x-mcp-header` constraints (5), `tools-declare-valid-input-schema`, tool-name hygiene (2), tools
capability agreement, `tampered-requeststate-rejected`, `input-required-carries-requests-or-state`,
`input-requests-respect-declared-capabilities`, and the beyond-spec `SENTINEL/SECURITY/`
`tool-description-injection`, `wildcard-scopes`, `manifest-drift`, `tls-posture` and
`SENTINEL/OPS/latency-budget`. A third fixture, `partial`, exercises every `NOT_APPLICABLE` branch.

Eleven of the new `MCP/` rules cite a page, not a heading anchor; see `docs/CITATIONS.md`.

### Added: distribution

Docker image (non-root, multi-arch in the release workflow), GitHub Action inputs for config,
baseline, snapshot, fleet and `--no-exec` with a Markdown job summary, a GitLab template that
publishes JUnit, pre-commit hooks, cosign keyless signing of the image and wheel, and a CycloneDX
SBOM on each release.

### Added: the Go side

- **`mcp/`**: the reusable packages extracted from `broker/internal/` into a module of their own,
  with `server.New`, `server.InsecureAnonymous`, an in-memory audit sink, and `mcp/example`, a
  one-tool server the build scans with `--gate must` and `--gate security`.
- **`fleet/` (`sentinel-server`)**: ingest, history, posture, drift, expiring waivers, an API and a
  server-rendered dashboard with a strict CSP. Memory or Postgres behind one contract suite.
  `scan --publish` sends a report and never changes the exit code.

### Changed

- JSON reports are schema 2 (additive over 1; `--schema-version 1` still works).
- `transport.NewServer` takes `transport.Settings` instead of the broker's configuration struct.
- Unit tests run in parallel: 94 s to about 30 s.
- Measured scan wall-clock is now 68 rules in about 260 ms (it was 35 rules in 62 ms, one at a
  time, in one process). The measurement runs the fixture in its own process; sharing one
  interpreter measured the two fighting over a GIL.

### Fixed

- `baseline create` and `prune` take `--target-name`; a finding's identity includes it, so a
  baseline could not otherwise match a target scanned by name.

### Not done

- `handles`, `mrtr` and the Postgres audit sink still carry their pgx code in the same packages;
  splitting them behind storage interfaces into `mcp/postgres` is the next step.
- Citations for eleven rules are page-level (see above).
- The OTLP exporter is not wired into the broker.
- No release has been cut; PyPI trusted publishing and the GHCR image still need a first release.

## 0.3.0

`--safe`, `registry-scan`, SSE-framed response parsing, the GitHub Action, PyPI packaging.

## 0.2.0

Rule lifecycle (`deprecated_in`, `superseded_by`), three severity corrections, the beyond-spec
`SENTINEL/` namespace, error codes moved out of the range the specification retired.

## 0.1.0

The MVP: the broker, the harness, the oracle fixtures, the deprecation inventory.
