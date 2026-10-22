# Using Sentinel on a real server

`sentinel scan --gate must` answers one question: is this server conformant right now? Everything
below is what turns that into something a team can run on every commit, against servers it does
and does not own, without the gate being ignored.

## Adopting it on a server that already has failures

Fixing everything before turning the gate on means the gate never gets turned on.

```bash
sentinel baseline create --endpoint https://mcp.internal/mcp --out sentinel-baseline.json
sentinel scan --endpoint https://mcp.internal/mcp --baseline sentinel-baseline.json --gate must
```

With a baseline the gate fires **only on findings it has not seen**. The report always shows all
three sets, because a baseline that only ever grows is how a tool becomes something teams route
around:

- **new**: not in the baseline. These gate.
- **baselined**: in the baseline and still failing. Listed under *ACCEPTED*, never hidden.
- **fixed**: in the baseline and now passing. Run `sentinel baseline prune` to drop them.

A baseline records the catalog it was taken against. A rule that did not exist then and fails now
is **new by construction**, and the report says so. A baseline cannot carry across a spec revision
(rule ids embed it), and loading one from another revision is an error.

A finding's identity is `sha256(rule id, target, evidence key)`. It never contains a request id,
a timestamp or a handle, so it is the same on every scan of an unchanged server. The target is
the endpoint with credentials, query and default port stripped, **or the target's name** if you
scan by name. Create the baseline the way you will scan: `--target-name broker-prod` on both, or
on neither.

## Living with a finding for a while: waivers

```toml
[[waivers]]
rule        = "MCP/2026-07-28/MUST/invalid-origin-rejected"
endpoint    = "https://legacy.internal/mcp"
reason      = "Behind an ingress that strips Origin; tracked in PLAT-4412"
expires_at  = 2026-11-30
approved_by = "security@example.com"
```

`expires_at` is **required**, and a malformed value is a hard error. (Snyk's `.snyk` treats a
malformed date as "ignore forever", which turns an operator's typo into a permanent blind spot.) A
waiver past its date stops applying: the finding fails again, labelled *waiver expired*, and the
report says which one lapsed. A waiver for a rule that is not failing is reported as unused so it
gets removed. One expiring within 14 days is called out.

A waived failure is still in the report, under *ACCEPTED*, and in SARIF as a suppression with the
justification. It is accounted for, not erased.

## Being stricter than the specification

```toml
[rules.severity]
"MCP/2026-07-28/SHOULD/tool-names-well-formed" = "must"
```

A severity override may only make a rule **stricter**. Promoting a SHOULD to a MUST is a policy a
company is entitled to hold. Demoting a MUST to get a green gate is laundering, and the file is
rejected with that explanation. To stop a rule failing your gate, use `rules.disable` (listed in
every report) or a waiver (which expires). A rule id that does not exist is an error, with a
"did you mean" when one is close.

## Where each setting comes from

CLI flag **>** `SENTINEL_*` environment variable **>** `sentinel.toml` **>** the file it `extends`
**>** built-in default. Discovery: `--config`, else `./sentinel.toml`, else `./.sentinel.toml`.
Every resolved value carries its source into the report's `policy` block, and a test asserts the
whole matrix. Secrets are never in the file: `token_env` names the variable that holds one.

| Setting | File key | Environment | Default |
|---|---|---|---|
| endpoint | `scan.endpoint` | `SENTINEL_ENDPOINT` | none |
| gate | `scan.gate` | `SENTINEL_GATE` | none (report only) |
| timeout | `scan.timeout` | `SENTINEL_TIMEOUT` | 10 s |
| concurrency | `scan.concurrency` | `SENTINEL_CONCURRENCY` | 8 |
| retries | `scan.retries` | `SENTINEL_RETRIES` | 2 |
| safe mode | `scan.safe` | `SENTINEL_SAFE` | false |
| bearer token | `scan.token_env` names it | `SENTINEL_TOKEN` | none |
| deprecated rules | `rules.include_deprecated` | `SENTINEL_INCLUDE_DEPRECATED` | false |

A complete, tested example is [`examples/sentinel.toml`](examples/sentinel.toml).

## Watching a server you depend on and do not control

```bash
sentinel snapshot --endpoint https://vendor.example/mcp --out snapshots/vendor.json
sentinel diff snapshots/vendor.json --gate        # on a schedule
```

A tool description is text an LLM is steered by. A server can rewrite one after you approved it,
without changing a single type signature, and a schema-diff tool would call that no change. `diff`
classifies every difference by severity and `--gate` exits 1 only on the **high** ones:

| Change | Severity |
|---|---|
| `DESCRIPTION_CHANGED`: a tool or argument description was rewritten (the rug pull) | **high** |
| `SCOPES_WIDENED`: a tool now claims more authority | **high** |
| `ANNOTATIONS_WEAKENED`: a `readOnlyHint` or `destructiveHint=false` promise was dropped | **high** |
| `SCHEMA_WIDENED` / `SCHEMA_NARROWED` / `SCHEMA_CHANGED` | warn |
| `TOOL_REMOVED`, `CAPABILITY_CHANGED` | warn |
| `TOOL_ADDED`, `SCOPES_NARROWED`, `SERVER_INFO_CHANGED` | info |

A snapshot is checked on load: edit one by hand and it is refused, because it is a record of what
a server said. `scan --snapshot` runs the same comparison as the beyond-spec rule
`SENTINEL/SECURITY/manifest-drift`. Combine it with `--safe` for a server you do not own.

## Settling the five rules a scan cannot

Five MUSTs cannot be verified from the wire, so a plain scan reports them `INDETERMINATE`. Give the
scanner the evidence and each returns a real verdict, recorded in the report as `verifiedBy`.

| Rule | Evidence | Verdict |
|---|---|---|
| `token-audience-validated` | `wrong_audience_token_env`: a token signed by your issuer for another audience | served: FAIL. Refused *differently from a garbage token*: PASS. Refused the same way: still INDETERMINATE, because the refusal may be the signature check. |
| `handle-possession-is-not-authentication` | `second_principal_token_env`, `[graybox.handle]` | mint as A, present as B. Served: FAIL. |
| `no-token-passthrough` | `egress_capture` command, `egress_token_env`, `egress_tool` | the caller's token appears in the capture: FAIL. An empty capture proves nothing: INDETERMINATE. |
| `mrtr-retries-are-idempotent` | `effect_counter` command, `[graybox.mrtr]` | the counter moves on a replay of a consumed flow: FAIL. A counter that does not move proves nothing. |
| `SENTINEL/SECURITY/invocations-are-audited` | `audit_verify` command, `audit_tool` | three invocations must add exactly three rows and the verifier must exit 0. |

**Absence of evidence is never a pass.** Evidence that is started and not finished (an environment
variable that is not set) says exactly what is missing instead of silently falling back.

**Commands** come only from the config file, run with `shell=False`, a 15 second timeout and a
minimal environment, and a command given as a single string is rejected at load time. No value a
scanned server returns ever reaches a command line. `--no-exec` disables every command-shaped kind
and keeps the token-shaped ones.

## Probing for rate limiting

`MCP/2026-07-28/MUST/tool-invocations-rate-limited` needs traffic, so it is off unless you opt in:
`sentinel scan URL --probe-rate-limit N` sends up to N rapid `tools/call` requests (capped at
2000) to the first callable tool. A 429, or a refusal that says so, is a PASS. A server that
serves them all is INDETERMINATE, never a FAIL, because the limit may sit above N or be keyed to
something the probe does not present. Do not point it at a server you do not own.

## Output formats

`--format text | json | sarif | markdown | junit | html`, and `--also FORMAT=PATH` writes more
than one from a single scan.

- **markdown**: a PR comment or `$GITHUB_STEP_SUMMARY`. Verdict and failures unwrapped, everything
  else inside `<details>`, hard-capped under GitHub's 65,536-character limit and truncating from
  the *least* severe end.
- **junit**: one `<testcase>` per rule. INDETERMINATE and not-applicable are `<skipped>`, never a
  pass. GitLab shows it in the merge request.
- **html**: one self-contained file, readable offline, no external request.
- **sarif**: carries the fingerprint as `partialFingerprints` so GitHub tracks a finding across
  runs, and marks a waived or baselined failure as a suppression.
- **json**: schema 2, additive over 1. `--schema-version 1` still emits the old shape.

## Wiring it in

| Where | How |
|---|---|
| GitHub | `uses: patsypppe/sentinel@v0.4.0`. Inputs: `endpoint`, `gate`, `config`, `baseline`, `snapshot`, `targets`, `safe`, `no-exec`, `token`. Writes a Markdown job summary, uploads SARIF. |
| GitLab | `include:` [`ci/gitlab/sentinel.gitlab-ci.yml`](../ci/gitlab/sentinel.gitlab-ci.yml) and `extends: .sentinel-scan`. Publishes JUnit. |
| Any CI | `docker run ghcr.io/patsypppe/sentinel scan --endpoint ...` |
| pre-commit | the `sentinel-scan` hook (`pre-push`, so a few hundred requests do not run on every commit) |
| PyPI | `uvx sentinel-mcp-conformance scan --endpoint ...` |

Releases are signed with cosign (keyless, from the release workflow's own identity, so there is no
key to leak) and ship a CycloneDX SBOM. `sentinel` makes no network call except to the endpoint you
give it, and sends no telemetry. `--publish` sends a report only to a service you named.

## Exit codes

**0** passed, **1** the *target* failed the gate, **2** the *scanner* could not run. A fleet scan
exits 1 if any target fails its own gate, otherwise 2 if any target could not be scanned. They are
never conflated: "the server is wrong" and "the scanner broke" need different people.
