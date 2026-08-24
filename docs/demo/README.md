# The demo

Nine steps, from `docs/HANDOFF.md` §13. `make demo` runs the whole thing; each step below is also
runnable on its own.

**Steps 1–2 and 6 are the ones worth remembering:** the scanner that grades other people's
servers, and exactly-once under retry.

## Setup

```bash
make up
make demo
```

`scripts/demo.py` brings up the stack, mints a token, runs all nine steps and prints each one's
command before its output.

---

### 1. Scan an unmigrated server

```bash
uv run sentinel fixture serve --profile nonconformant &
uv run sentinel scan --endpoint http://127.0.0.1:9000/mcp --gate must
```

**25 MUST failures**, each with a spec citation and a remediation, plus three SHOULDs and one
beyond-spec finding that do not affect the gate. Exit **1**.

### 2. Scan the broker

```bash
uv run sentinel scan --endpoint http://localhost:8080/mcp --gate must --token "$TOKEN"
```

**Zero.** Exit **0**. Five MUSTs report `INDETERMINATE` and are named — a clean scan is not a clean
bill of health, and the tool says so.

### 3. The deprecation inventory

```bash
uv run sentinel deprecations --endpoint http://127.0.0.1:9000/mcp
```

Six deprecated features, each with the date it was deprecated and the date it becomes removable
**on or after** — the window is a minimum, not a schedule.

### 4. `concise` versus `detailed`

```bash
uv run sentinel scan --endpoint … # or call warehouse.query directly, both ways
```

Up to **49.3%** fewer tokens in `concise`, because it names each column once instead of once per
row. Below two rows it costs slightly *more*; the crossover is documented rather than hidden.

### 5. An irreversible tool asks first

```bash
tools/call ops.deployment_apply {"plan": "hnd_…"}
```

```json
{"resultType": "input_required",
 "inputRequests": [{"name": "confirm", "prompt": "Deploy checkout 1.4.2 across 3 replicas? This is irreversible.", "destructive": true}],
 "requestState": "OvuGcbIj6KjctZDEnpFS0oV58Zhq…"}
```

Nothing has been deployed. The tool is `Irreversible` **by declaration**, so the confirmation is
required by the type system rather than by remembering.

### 6. Replay the identical retry

Six retries, six **different** JSON-RPC ids:

```
{"jsonrpc_id":3,"deploymentId":"d1cf3180-f2b4-4c49-8c05-bf07ee794ba5"}
{"jsonrpc_id":4,"deploymentId":"d1cf3180-f2b4-4c49-8c05-bf07ee794ba5"}
…
{"jsonrpc_id":8,"deploymentId":"d1cf3180-f2b4-4c49-8c05-bf07ee794ba5"}

deployments   = 1
effect ran    = 1 time(s)
```

One deployment. Correlation is the sealed `requestState`, never the id.

### 7. A leaked handle, presented as someone else

```bash
tools/call ops.deployment_apply {"plan": "<the operator's handle>"}   # as the analyst
```

```json
{"code": -32000,
 "message": "handle is not resolvable: it does not exist, is not yours, has expired, or was revoked"}
```

One message for every cause: distinguishing them would confirm the handle exists. And the refusal
is audited.

### 8. The joined trace

`traceparent` travels in `_meta` and the broker continues the client's trace rather than starting a
new one, so a client-to-server span tree is visible end to end.

### 9. A MUST regression fails CI

Introduce one — advertise `listChanged: true`, or drop `cacheScope` from a list result — and the
`conformance` workflow goes red with the rule name, the observed behaviour and the fix.

---

## The audit demonstration

Not in the nine steps, but the shortest way to show the audit log is real:

```bash
psql -U broker_app -c "UPDATE tool_invocations SET outcome='ok';"
# ERROR:  permission denied for table tool_invocations

broker audit verify --from 2026-08-01 --to 2026-09-30
# verified 25 row(s) … chain intact       exit 0

psql -U sentinel  -c "UPDATE tool_invocations SET outcome='denied' WHERE seq = 5;"   # superuser
broker audit verify --from 2026-08-01 --to 2026-09-30
# chain break at seq 5 … the row's contents do not match its own hash — it was rewritten
# exit 1
```

The grants stop the ordinary case; the chain catches whoever gets past them.
