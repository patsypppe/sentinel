# Runbook

Running, operating and debugging the stack.

## The stack

```bash
make up      # postgres, broker, envoy, smokescreen, otel-collector
make down    # tear down, volumes included
make logs    # follow the broker
```

| Service | Port | Notes |
|---|---|---|
| `broker` | 8080 | The MCP endpoint, `POST /mcp`. `GET /healthz` for liveness. |
| `envoy` | 10000 / 10001 | Trusted and untrusted listeners. Admin on 9901. |
| `postgres` | 5432 | Migrations run at broker start, as the **migration** role. |
| `smokescreen` | — | Egress proxy. Present for topology honesty; SSRF containment (`SN-CAP-22`) is **out of scope** for the MVP. |
| `otel-collector` | — | Receives spans; `traceparent` is ingested from request `_meta`. |

## Configuration

Every knob, with its default.

| Variable | Default | Notes |
|---|---|---|
| `BROKER_ADDR` | `:8080` | |
| `BROKER_DATABASE_URL` | — | The **application** role. Cannot UPDATE or DELETE the audit log. |
| `BROKER_MIGRATE_DATABASE_URL` | — | The **migration** role. Deliberately different: a role that could migrate could drop the audit log's `REVOKE`. |
| `BROKER_HANDLE_DEFAULT_TTL` | `15m` | |
| `BROKER_MRTR_FLOW_TTL` | `5m` | How long a flow may sit **awaiting input**. |
| `BROKER_MRTR_REPLAY_WINDOW` | `24h` | How long a **consumed** flow keeps its recorded result. Must be ≥ the flow TTL — the broker refuses to start otherwise. |
| `BROKER_MRTR_SEAL_KEY` | generated | Hex, 32 bytes. **Unset generates an ephemeral key**, so every in-flight approval becomes unreplayable on restart and a second replica cannot unseal the first's `requestState`. Set it in anything with more than one process. |
| `BROKER_CACHE_TOOLS_LIST_TTL_MS` | `300000` | |
| `BROKER_DEFAULT_TOKEN_CAP` | `25000` | Per-tool ceiling; over it, a tool returns a handle plus a summary. |
| `BROKER_ALLOW_LEGACY_UNVERSIONED` | `true` | Serve unversioned requests as `2025-11-25`, recording a deprecation event. |
| `BROKER_OAUTH_ISSUER` | `https://issuer.sentinel.local` | |
| `BROKER_OAUTH_AUDIENCE` | `https://broker.sentinel.local` | Every token's `aud` is checked against this by **exact** membership. |
| `BROKER_OAUTH_JWKS_PATH` | — | Production token validation. Takes precedence over the dev seed. |
| `BROKER_OAUTH_DEV_SEED` | — | **Development only.** Derives a keypair so `broker mint-token` and the server reach the same key. Signature, issuer, audience and expiry are all validated for real; only the key's provenance is a shortcut. |
| `BROKER_DEV_AUTH` | — | `1` reads the principal from headers and validates **no token**. Local development only. |

With none of the authentication variables set, the broker **refuses every authenticated method**.
That is deliberate: an authentication layer nobody configured must not serve anonymously.

## Minting a token

```bash
export BROKER_OAUTH_DEV_SEED=$(printf 'a%.0s' {1..64})
export BROKER_OAUTH_ISSUER=https://issuer.sentinel.local
export BROKER_OAUTH_AUDIENCE=https://broker.sentinel.local

TOKEN=$(go run ./broker/cmd/broker mint-token \
  --principal 00000000-0000-0000-0000-0000000000a2 \
  --audience https://broker.sentinel.local \
  --scopes "ops:plan ops:apply warehouse:read warehouse:describe")
```

`--audience` has no default on purpose: demonstrating the specification's MUST NOT requires being
able to mint a **wrong**-audience token as easily as a right one, and watch the server refuse it.

The two demo principals:

| Principal | Scopes |
|---|---|
| `…0000a1` (analyst) | `warehouse:read`, `warehouse:describe` |
| `…0000a2` (operator) | the above plus `ops:plan`, `ops:apply` |

## Verifying the audit chain

```bash
broker audit verify --from 2026-09-01 --to 2026-09-30
```

Exit **0** every chain verified, **1** one did not, **2** the check could not run.

A break names the row and distinguishes *how* it broke:

```
chain break at seq 5 (…): the row's contents do not match its own hash — it was rewritten
chain break at seq 6 (…): the row's prev_hash does not match the previous row — a row was
                          removed, reordered, or inserted
```

Only the first break per tenant is reported: after a rewritten row every subsequent link fails
too, and printing a thousand breaks buries the one that matters.

## Common problems

**`the presented token was not accepted`** — every authentication failure returns this same
message, deliberately: which check failed is useful in a server log and is an oracle on the wire.
Check the broker's log for the specific cause, then confirm `aud` matches
`BROKER_OAUTH_AUDIENCE` **exactly** (not by prefix) and that the token has not expired.

**`-32020` on a request that looks right** — `Mcp-Method` must equal the JSON-RPC `method`, and
`Mcp-Name` must equal the tool/prompt/resource name where the method takes one. For `tools/call`
that is `params.name`; for `resources/read` it is `params.uri`. The error names which header
disagreed and what the body said.

**`-32022` on a method you expect to exist** — negotiation runs *before* dispatch, so an
unversioned request naming a method that never existed in `2025-11-25` reports a version failure
rather than method-not-found. Declare `io.modelcontextprotocol/protocolVersion` in `_meta`.

**`handle is not resolvable`** — one message for five causes (absent, wrong principal, wrong
tenant, expired, revoked), because distinguishing them turns the handle space into an enumeration
oracle. Check the handle was minted for *this* principal and has not aged past
`BROKER_HANDLE_DEFAULT_TTL`.

**`the retry's arguments differ from the call that was approved`** — the arguments are compared
against the ones the user approved, in canonical form, excluding `requestState` and
`inputResponses`. Re-serializing is fine; changing what the call *does* is not.

**Audit inserts failing at a month boundary** — should not happen: partitions for the current and
next month are created at boot, an hourly job rolls them forward, and a missing partition is
created on demand. If it does, `SELECT ensure_invocation_partition(now());`.

**Scan reports 25 MUST failures against a server you believe is fine** — check it is running.
`sentinel` reports an unreachable target as `INDETERMINATE`, but a server that is *up* and
answering everything with an error will genuinely fail most rules.

## Running the suites

```bash
make test-go              # unit, with -race
make test-go-integration  # Postgres-backed; needs `make up`
make test-py              # harness unit tests
make test-e2e             # compose-backed; needs `make up`
make measure              # regenerate MEASUREMENTS.md
```

The integration suite skips rather than fails when Postgres is unreachable, so `make check` is
useful without Docker running.
