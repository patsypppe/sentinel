# Changelog

## 0.4.0

The harness stops being a one-shot grader and becomes something a team runs.

### Changed: lint shares one server process

The lint rules only read, so they share one child process instead of starting the server per rule:
4.4x to 6.7x faster with identical results. `benchmarks/chart.py` draws the 27-server result as an SVG.

### Added: `sentinel lint` and stdio servers

- `sentinel lint --command "npx -y <server>"` runs the manifest rules against a server started as a
  child process (newline-delimited JSON over pipes), or `--endpoint` for HTTP. Most published MCP
  servers are stdio programs, which Sentinel could not reach before.
- `benchmarks/popular_servers.py`: lints 29 published servers; 27 started, 335 tools, 28% of
  parameters undocumented.

### Added: legacy-session mode

Against a server that has not migrated to the current protocol, the rules that only read the tool
manifest (names, descriptions, injection, schema validity, Origin) now open a previous-revision
session and run, instead of every rule reporting the server unreachable.

### Added: benchmarks against servers this project did not write

- `benchmarks/official_negatives.py`: runs the broken fixtures from the official conformance repo and
  reports which labelled violations Sentinel catches (7 of 7 gradable; one fixture is unusable and one violation has no rule, both listed).
- `benchmarks/sdk_readiness.py`: scans servers built with the official SDKs.
- Reports now say which protocol generation answered, and a scan of a legacy-only server says so at
  the top instead of presenting a wall of failures as independent bugs.
- The stub-description threshold is 12 characters, not 20 ("Add two numbers." is a description).

### Added: `sentinel demo` and tool-description lint

- `sentinel demo`: starts two bundled practice servers (one broken, one correct), scans both and
  prints the verdicts. Works from a plain `uvx` install because the practice servers ship in the wheel.
- `SENTINEL/STYLE/description-states-purpose` and `SENTINEL/STYLE/parameters-are-described`,
  grounded in two 2026 studies of MCP tool descriptions (arXiv 2602.14878, 2602.18914).

### Fixed: rules that were stricter than the specification

Every `MCP/` rule was audited against the 2026-07-28 specification source and the official
`modelcontextprotocol/conformance` suite. Rule ids are permanent, so a withdrawn rule is
deprecated and points at its successor.

- `MUST/discover-without-negotiated-version` withdrawn: the specification never exempts
  `server/discover` from version negotiation, so it failed conformant servers.
- Demoted to SHOULD (new ids): `discover-reports-server-info`, `list-changed-advertised-truthfully`
  (now INDETERMINATE when the probe cannot tell), `malformed-json-is-parse-error`.
- Moved out of the spec namespace to `SENTINEL/STYLE/`: `tools-have-descriptions`, and the
  `initialize` / `ping` / `logging/setLevel` / `resources/(un)subscribe` removed-method checks. A
  dual-era server MAY keep serving them. The `sampling` and `roots` checks were dropped: they remain
  functional during their deprecation window.
- Loosened to INDETERMINATE instead of FAIL where the wire cannot tell a violation from a
  permitted behaviour: a headerless request that is served, a tampered `requestState` answered
  with a fresh `input_required`, a populated result for an unknown resource URI, a tool list that
  differs once between two connections, a tool list whose payload (not order) varies.
- `missing-protocol-version-rejected` accepts `-32020` as well as `-32602`;
  `missing-capability-error-shape` reads `requiredCapabilities` as an object, as the schema types it;
  `x-mcp-header` rules no longer FAIL an untyped or union-typed property; the token-syntax rule uses a
  full match; the rate-limit rule no longer treats the word "quota" as a throttle.
- Three security rules cited a specification page that does not exist; every `MCP/` rule now cites a
  heading that does.

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

Every `MCP/` rule cites a heading anchor, checked against the specification source. Three security rules had cited a page that does not exist (`basic/security_best_practices`; the page lives at `docs/2026-07-28/tutorials/security/`) and now point at the real one.

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
- No release has been cut; PyPI trusted publishing and the GHCR image still need a first release.

## 0.3.0

`--safe`, `registry-scan`, SSE-framed response parsing, the GitHub Action, PyPI packaging.

## 0.2.0

Rule lifecycle (`deprecated_in`, `superseded_by`), three severity corrections, the beyond-spec
`SENTINEL/` namespace, error codes moved out of the range the specification retired.

## 0.1.0

The MVP: the broker, the harness, the oracle fixtures, the deprecation inventory.
