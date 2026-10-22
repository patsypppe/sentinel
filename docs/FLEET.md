# A fleet of servers: scanning many, keeping history

One scan answers "is this server conformant now". A company with several MCP servers also needs
"which ones, since when, and what is about to break". That is two things: scanning many targets
in one command, and `sentinel-server`, which keeps the history.

## Scanning many targets

```yaml
# sentinel-fleet.yaml
concurrency: 5
targets:
  - name: broker-prod
    endpoint: https://broker.example.com/mcp
    token_env: BROKER_PROD_TOKEN
    gate: must
  - name: vendor-x                  # a third party you do not control
    endpoint: https://vendor-x.example/mcp
    token_env: VENDOR_X_TOKEN
    gate: should
    safe: true
    waivers_from: vendor-x.toml
```

```bash
sentinel scan --targets sentinel-fleet.yaml --out-dir sentinel-fleet --format junit
```

A target is a *named, separately credentialed connection*, not a bare URL, because each MCP
endpoint has its own token, its own tenant and its own acceptable gate. You hold your own broker
to `must` and a vendor to `should`. The same server can pass one gate and fail another.

- One report per target, plus `rollup.json` and `rollup.md`, in `--out-dir`.
- The exit code is **1** if any target fails *its own* gate, otherwise **2** if any target could
  not be scanned, otherwise **0**.
- A target that does not answer is an **error for that target only**. It is never reported as a
  pass, and it never stops the others.
- A target whose `token_env` variable is not set is **not scanned anonymously**: an
  unauthenticated scan would grade a login page. It reports an error naming the variable.
- A target's fingerprints use its **name**, so it keeps its identity (and its baseline) if its URL
  moves. Create a baseline with `--target-name` to match.
- `waivers_from` gives a target its own waivers without putting a vendor's exceptions in your
  project policy.

Targets run concurrently up to `concurrency`; within each, rules run concurrently on their own
connections, so wall-clock is roughly the slowest rule, not the sum.

## `sentinel-server`

```
sentinel scan --publish https://sentinel.internal   →   sentinel-server   →   dashboard + API
```

`--publish` is additive. The CLI never *requires* a service, a publish failure is a warning on
stderr, and **it never changes the exit code**: a scan's verdict is the product, and a service
that is down must neither turn a clean scan red nor a failing one green. The bearer token comes
from `SENTINEL_PUBLISH_TOKEN`, never a flag, so it stays out of shell history and CI logs.

### Run it

```bash
docker compose --profile fleet up          # postgres + the service on 127.0.0.1:8088
# or:
SENTINEL_SERVER_INGEST_TOKEN=... SENTINEL_SERVER_READ_TOKEN=... \
SENTINEL_SERVER_DATABASE_URL=postgres://... sentinel-server serve
```

| Variable | |
|---|---|
| `SENTINEL_SERVER_INGEST_TOKEN` | **Required.** What `--publish` presents. The server will not start without it: an open ingest endpoint would let anyone make any target look green. |
| `SENTINEL_SERVER_READ_TOKEN` | Optional. When set, the API and dashboard require it, as a bearer token or as the password of HTTP Basic, so a browser can prompt for it. When unset the server warns at start that reads are open. |
| `SENTINEL_SERVER_DATABASE_URL` | A Postgres URL. Unset, data is held in memory and lost on restart, and the server says so. |
| `SENTINEL_SERVER_MIGRATE_DATABASE_URL` | A role that may create tables. Migrations run under an advisory lock, each in a transaction. `sentinel-server migrate` runs them and exits. |
| `SENTINEL_SERVER_ADDR` | Default `127.0.0.1:8088`. Set `0.0.0.0:8088` deliberately. |
| `SENTINEL_SERVER_STALE_AFTER` | How old a target's latest scan may be before it stops counting as passing. Default 48h. |

The ingest and read tokens are **different credentials**. The one that lets CI publish a scan must
not let anyone read the fleet's weaknesses, and a read-only dashboard viewer must not be able to
forge a clean scan. Tokens are compared in constant time.

The database role needs `SELECT, INSERT` on `scan_runs`, `scan_findings` and `waiver_ledger` and
nothing else: scans are an append-only record and the service never updates or deletes one. It
needs `UPDATE` only on `targets` and `manifest_snapshots`. `deploy/postgres/init/02-fleet.sql`
creates exactly that for the compose topology.

### What it computes that the CLI cannot

Time.

- **Posture per day**: failing, accepted and indeterminate counts, and whether the gate failed.
  A day nobody scanned is *absent*, not zero: unknown is not clean.
- **How long a finding has been open.** The clock restarts if a fixed finding regresses, because
  "open for 200 days" for something that was fixed for 150 of them is false.
- **Time to remediation per rule**, and how often a fixed finding came back. A fix is only
  observed when the next scan runs, so these are upper bounds by up to one scan interval.
- **Manifest drift events**: when a target's tool manifest hash changed. The service knows *that*
  and *when*; `sentinel diff` against a snapshot says *what* and *how bad*.
- **Waivers about to lapse**, with the ones over a **still-failing** finding first. That is the
  list that prevents an outage: a waiver about to expire over a finding that still fails is a gate
  about to go red.
- **A stale target** is counted stale, not passing. An old green is not a current one.

### API

All JSON. Reads need the read token when one is set.

| | |
|---|---|
| `POST /api/v1/scans` | ingest a schema-2 report (ingest token). `201`; `400` for a report it cannot read, with the reason; `413` over 8 MiB. Publishing the same scan twice records it once. |
| `GET /api/v1/targets` | each target's latest verdict |
| `GET /api/v1/targets/{name}/posture?window=90d` | daily series, open findings with ages, remediation, drift |
| `GET /api/v1/targets/{name}/drift` | manifest change events |
| `GET /api/v1/waivers/expiring?within=30d` | waivers lapsing or lapsed, still-failing first |
| `GET /api/v1/fleet/summary` | counts by state, and the rules failing on the most targets |
| `GET /healthz` | no token |

`{name}` is the target's name or its identity. Durations take `d`, `h` or `m`.

### The dashboard

Server-rendered HTML at `/`: the fleet grid, a page per target with an inline-SVG chart of failing
findings per scanned day, and an expiring-waivers page. No JavaScript, no bundler, **no external
request of any kind**, and a strict `Content-Security-Policy` (`default-src 'none'`, no inline
styles) on every response. A hostile target name or finding detail in a stored report is escaped
and cannot become script in an operator's browser. It is a read of the API, not a second
implementation of it.

## What it does not do

- It does not scan. The CLI scans; the service stores what it is sent.
- It does not classify drift. It records that the manifest hash changed; `sentinel diff` classifies.
- It is not multi-tenant, has no users or roles beyond the two tokens, and is software you run, not
  a hosted service.
