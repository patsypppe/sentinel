# What changed in MCP `2026-07-28`, and what it costs you

On **28 July 2026** the Model Context Protocol shipped the largest breaking revision in its
history. It converted MCP from a stateful, session-based, bidirectional protocol into a
**stateless request/response protocol**.

Every MCP server written before that date was written against the old idioms. This document is
the change list with the *work* attached — what each change actually requires, and how
[`sentinel`](../harness) detects whether you still owe it.

> **Precedence.** Where this document and the
> [specification](https://modelcontextprotocol.io/specification/2026-07-28/) disagree, the
> specification is right and this document is wrong.

Run the inventory before you read any further; it will tell you which sections apply to you:

```bash
uv run sentinel scan --endpoint https://your-server.example/mcp --gate must
uv run sentinel deprecations --endpoint https://your-server.example/mcp
```

---

## The shape of the change

Four things drive everything else:

1. **There is no session.** Nothing may be keyed by connection.
2. **The server never calls the client.** That direction was removed, not deprecated.
3. **Results must say what kind of result they are, and how long they may be cached.**
4. **A gateway must be able to route and authorize without parsing the body.**

If you understand those four, the rest of the change list is consequences.

---

## Removed outright

These do not warn. They are gone, and a client on the new revision will get an error.

| Removed | Replaced by | What it costs you |
|---|---|---|
| `initialize` | `server/discover` | **Days.** The handshake was where most servers put version negotiation, capability exchange and session setup. Negotiation now happens on *every request* from `_meta`, so it has to be cheap; capabilities move into `server/discover`; and session setup has nowhere to go — see *State* below. |
| Sessions | Server-minted handles | **The big one.** Anything you kept per-connection has to become either a request argument or a handle you mint, store and re-authorize on every use. |
| Server-initiated requests | Multi Round-Trip Requests | **Days.** Any place your server asked the client something — a confirmation, an approval, a completion — inverts. See *MRTR* below. |
| `ping` | request timeouts | Minutes. There is no connection to keep alive. |
| `resources/subscribe` / `unsubscribe` | `subscriptions/listen` | Hours, if you used them. |
| `logging/setLevel` | `_meta.io.modelcontextprotocol/logLevel` | Minutes. The level travels per-request instead of per-session. |
| `notifications/roots/list_changed` | — | Minutes. |

**Detected by:** `MUST/initialize-removed`, `MUST/ping-removed`, `MUST/logging-set-level-removed`,
`MUST/resources-subscribe-removed`, `MUST/resources-unsubscribe-removed`,
`MUST/sampling-create-message-removed`, `MUST/roots-list-removed`.

> A removed method must return **method-not-found**, not vanish from your router. A client that
> gets a 404 from your endpoint cannot tell a removed method from a broken proxy. Answer, and name
> the replacement in the error — a migrating client is then told what to use.

---

## State: sessions become handles

This is the change with the most work in it.

**Before:** the server held a session. A query's results, an upload in progress, a
half-built plan — all lived in a map keyed by connection.

**After:** cross-call state exists only as a **server-minted handle passed as an ordinary tool
argument**. And the specification is explicit that **possession of a handle is not
authentication**.

That last sentence is the whole design. A handle is *data*, not a credential:

```sql
-- Every resolution. Not once at the start; every time.
SELECT payload FROM state_handles
 WHERE handle_id    = $1
   AND tenant_id    = $2   -- from the VALIDATED TOKEN, not from the handle
   AND principal_id = $3   -- likewise
   AND revoked_at IS NULL
   AND expires_at > now();
```

**What it costs you:** a table, a mint path, a resolve path, and the discipline to have exactly
*one* of the latter. Budget a day, plus however long your existing session code took to write.

**Three mistakes worth avoiding:**

- **An in-memory map "just for the query results."** That is the design the revision removed. It
  breaks the moment you run two replicas, and it breaks silently.
- **Distinguishable errors for "no such handle" and "not yours."** That turns your handle space
  into an enumeration oracle: one bit per guess is how a space gets mapped. Return the *same*
  error, with the same message, for both — and for expired and revoked too.
- **Caching a resolved handle.** The second use must re-check. A test that resolves each handle
  once cannot tell a re-check from a cache; make yours resolve, revoke, then resolve again.

**Detected by:** `MUST/handle-possession-is-not-authentication` — but see *Limits* below. This one
is **UNVERIFIABLE** black-box: proving it needs two authenticated principals, and a scan has one.
`sentinel` reports it as `INDETERMINATE` rather than pretending.

---

## MRTR: the server stops calling the client

**Before:** your server needed a confirmation, so it called the client and waited.

**After:** it returns a result and stops.

```json
{
  "resultType": "input_required",
  "inputRequests": [{"name": "confirm", "kind": "boolean", "prompt": "…", "destructive": true}],
  "requestState": "<opaque>"
}
```

The **client** then retries the original request — **as a new JSON-RPC request with a new id** —
carrying `inputResponses` and the `requestState` it was given.

**What it costs you:** two to three days, and it is the part most likely to be subtly wrong.

**Five mistakes, in the order people make them:**

1. **Correlating on the JSON-RPC id.** The retry has a *new* one. Correlate only through the
   sealed `requestState`.
2. **Encoding `requestState` instead of sealing it.** Base64 of JSON is client-editable: a caller
   can rewrite the correlation id or extend the expiry. AEAD-seal it, and **bind the tool name as
   additional authenticated data** so a state sealed for one tool cannot be replayed against
   another.
3. **Executing the effect before recording the result.** A crash between the two re-executes on
   the next retry. They belong in **one transaction**.
4. **Honouring a retry whose arguments changed.** The user approved a specific action. Hash the
   original arguments and reject a retry that does not match — but hash the *canonical* form, or
   a client that merely re-serialized will be rejected for nothing.
5. **Assuming retries arrive one at a time.** They do not. Lock the flow row, or two concurrent
   duplicates both read "awaiting input" and both execute.

**The property to test:** a duplicate retry returns the recorded result and performs **zero**
additional side effects. Assert on a **side-effect counter** — a row count, a call log — not on the
response. *The response looking right while the effect happened twice is the exact failure the test
exists to catch.*

**Detected by:** `MUST/mrtr-retries-are-idempotent` — also **UNVERIFIABLE**. A duplicate retry that
returns the right answer is indistinguishable from the wire from one that performed the effect
twice *and* returned the right answer again.

---

## `CacheableResult` became required

Every list and read result must carry `ttlMs` and `cacheScope`:

```json
{"resultType": "complete", "tools": [...], "ttlMs": 300000, "cacheScope": "private"}
```

**What it costs you:** an hour, plus one decision per endpoint that is worth taking seriously.

**`cacheScope` is the decision.** `public` means a shared intermediary may reuse the response for
*anyone*. If your `tools/list` varies by the caller's scopes — most do — `public` is a cross-tenant
disclosure. Choose `private` unless the response genuinely does not vary, and write down why.

**Detected by:** `MUST/cacheable-results-carry-ttl`, `MUST/cacheable-results-carry-scope`.

---

## Deterministic ordering

`tools/list` **SHOULD** return tools in deterministic order — explicitly so clients can cache, and
so LLM prompt-cache hit rates hold up.

**What it costs you:** twenty minutes, and it is the cheapest win in this document.

Build the manifest **once**, sort by name **byte-wise**, serve the precomputed bytes. Three things
break this:

- **Iterating a map.** Go randomizes it deliberately; most hash maps do not promise an order.
  This is the usual cause, and it is invisible in a test that calls the endpoint once.
- **Re-serializing per request.** Even a stable input can produce unstable bytes.
- **Case-insensitive or locale collation.** `Warehouse` and `warehouse` then sort differently
  depending on where the server runs.

**Test it like a measurement:** call `tools/list` a hundred times, hash each response, assert
exactly **one** distinct SHA-256 — then reload your registry and assert the hash is unchanged.
Reload is where determinism usually dies.

**Use a second connection for the hundred-and-first call.** Ordering is a SHOULD; the MUST in the
same paragraph is a different property — the tool set "MUST NOT vary per-connection or as a side
effect of other requests on the connection". A hundred calls down one connection cannot see that,
and per-connection state is exactly what a server carries over from the session-based revision. Two
clients holding the same credential must be told about the same tools.

**Detected by:** `MUST/tools-list-connection-independent`, `SHOULD/tools-list-is-deterministic`,
`SENTINEL/STYLE/tools-sorted-by-name` — the last is beyond-spec and never fails the gate.

---

## The header contract

Streamable HTTP POST requires `Mcp-Method` and `Mcp-Name`.

The reason is architectural: a gateway or WAF must be able to route and authorize **without
parsing the JSON body**. For a streaming JSON-RPC endpoint that also means without *buffering* it.

**What it costs you:** an hour on the server. The gateway config is where the value is.

Both halves are needed:

- **The gateway** routes on the headers. It never sees the body.
- **The server** validates the headers *against* the body, and returns `-32020` on any
  disagreement.

Without the second half the first is decorative — a caller lies in the header and the body is
served regardless. With both, the headers are **binding**: routed by header, rejected by body check.

**Detected by:** `MUST/mcp-method-header-required`, `MUST/mcp-name-header-required`,
`MUST/header-body-mismatch-rejected`.

---

## Error codes moved

The revision partitions the JSON-RPC server-error range:

| Range | Owner |
|---|---|
| `-32000` … `-32019` | **you** |
| `-32020` … `-32099` | **the specification** — only `-32020`, `-32021`, `-32022` are defined so far |

And one code moved: **resource-not-found is `-32602`**, not `-32002`.

**What it costs you:** an hour, and one test. Enumerate every error your server can emit and assert
none falls in the reserved range — a code you take today is a code a future revision will define,
and your clients will then act on the wrong meaning.

**Detected by:** `MUST/resource-not-found-is-invalid-params`, `MUST/no-errors-in-reserved-range`,
`MUST/unknown-method-is-method-not-found`, `MUST/malformed-json-is-parse-error`.

---

## Deprecated, on a twelve-month clock

These still work. They are **removable on or after 28 July 2027** — the window is a *minimum*, not
a schedule, so plan against it rather than to it.

| Deprecated | Replace with | Why |
|---|---|---|
| **Roots** (SEP-2577) | explicit tool arguments naming the paths | No session to hold the answer. |
| **Sampling** (SEP-2577) | multi round-trip requests | The server never initiates. |
| **Logging** (SEP-2577) | `_meta.…/logLevel` per request | No session to scope the level to. |
| **HTTP+SSE transport** | Streamable HTTP | Two endpoints and a held connection became one POST. |
| **OAuth Dynamic Client Registration** | Client ID Metadata Documents | A client's identity becomes a document the authorization server can fetch and check. |
| `includeContext: "thisServer"` / `"allServers"` | explicit arguments | Both asked the client to gather context for you; `"allServers"` also leaked one server's context to another. |

**Detected by:** `sentinel deprecations`, which reports each with its deprecation date, its
earliest removal, and what to replace it with.

---

## Security: the two MUST NOTs

Neither is new advice. Both are now normative.

**1. Validate the audience.**

> *"MCP servers MUST NOT accept any token not explicitly issued for the MCP server."*

Check that the token's `aud` contains **your** identifier, **by exact string equality**. Not a
prefix — `https://you.example` must not be satisfied by `https://you.example.evil.example`, which
an attacker who can register a domain will happily supply. Not a substring, not a normalizing
compare.

**2. Never forward the inbound token downstream.**

Use your own credential. Forwarding *feels helpful* when you write it — the downstream service
wants to know who the user is, and the token says so — but a token issued for you, presented
elsewhere, makes that service a confused deputy and makes you the thing that handed it the weapon.

The durable fix is structural: keep the inbound token **out of** whatever type represents your
authenticated principal. Then there is nothing to forward, even by accident.

**Detected by:** `MUST/token-audience-validated`, `MUST/no-token-passthrough` — both
**UNVERIFIABLE**. What your server sends to its own dependencies is invisible from the client side,
and a scanner cannot mint a token signed by your issuer.

---

## Limits: what a scan cannot tell you

Five MUST rules cannot be settled from the wire, and `sentinel` reports them as **`INDETERMINATE`**
rather than as passes:

| Rule | What would settle it |
|---|---|
| `token-audience-validated` | Mint a token with **your** issuer and a different audience; confirm your server refuses it. |
| `no-token-passthrough` | Capture your server's egress while it serves an authenticated call; confirm the inbound token appears in none of it. |
| `handle-possession-is-not-authentication` | Mint a handle as one principal, present it as another; confirm the refusal. |
| `mrtr-retries-are-idempotent` | Retry a completed flow and count the effect **at its source**, not in the reply. |
| `invocations-are-audited` | Read the log directly and verify its chain. |

A clean scan is not a clean bill of health, and a tool that implied otherwise would be worse than
no tool. These five are where you still have to look yourself.

---

## A migration order that works

1. **`server/discover` first.** Everything else is unreachable until a client can find you.
2. **The envelope** — `resultType`, `serverInfo`, `ttlMs`, `cacheScope`. Mechanical, and it
   unblocks scanning yourself for real feedback.
3. **Error codes.** An hour, and it stops you building on the wrong ones.
4. **The header contract.** Server-side first; the gateway config can follow.
5. **Sessions → handles.** The big one. Do it before MRTR — MRTR flows reference handles.
6. **MRTR.** Budget three days and do not compress it.
7. **Audience validation.** Small, and it is a MUST NOT.
8. **The deprecated features.** You have until at least July 2027. Do them last, deliberately.

Scan after each step. The gate is the point:

```bash
uv run sentinel scan --endpoint http://localhost:8080/mcp --gate must
# exit 0 → you passed. exit 1 → a MUST failed. exit 2 → the scanner broke.
```
