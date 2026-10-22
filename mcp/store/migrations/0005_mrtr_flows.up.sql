-- MRTR flows and the deployment side effect they gate.
-- SN-CAP-09 / SN-CAP-10, docs/HANDOFF.md §7.5 and §8.5.

CREATE TABLE mrtr_flows (
    -- Correlation is via this id, sealed into requestState. NEVER via the
    -- JSON-RPC id: the retry is a new request with a new one (§14 gotcha 4).
    correlation_id   text PRIMARY KEY,

    tenant_id        uuid NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    principal_id     uuid NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
    tool_name        text NOT NULL,

    -- The hash of the ORIGINAL arguments. A retry whose arguments differ is
    -- rejected rather than silently honoured: the user approved a specific
    -- action, and honouring a different one would make the approval a lie.
    arguments_hash   text NOT NULL,

    input_requests   jsonb NOT NULL,
    status           text NOT NULL
        CHECK (status IN ('awaiting_input', 'consumed', 'expired', 'abandoned')),

    -- Replayed VERBATIM on a duplicate retry -- which is why this column is
    -- `json` and not `jsonb`.
    --
    -- jsonb is a parsed representation: it re-emits with its own spacing, sorts
    -- object keys and drops duplicates. Storing the recorded result as jsonb
    -- therefore returns the same VALUE but different BYTES, and §8.5 asks for
    -- the recorded result verbatim. A client that hashes or signs a response,
    -- or diffs two retries, would see the replay differ from the original.
    --
    -- The `json` type stores the exact input text. It cannot be indexed or
    -- queried efficiently, and neither matters here: this column is written
    -- once and read back whole.
    recorded_result  json,

    created_at       timestamptz NOT NULL DEFAULT now(),

    -- flow_ttl: how long the flow may sit AWAITING INPUT.
    expires_at       timestamptz NOT NULL,

    consumed_at      timestamptz,
    -- replay_window: how long a CONSUMED flow keeps its recorded result. A
    -- separate clock from expires_at, per the divergence recorded in docs/PRD.md
    -- -- the design wants a short approval window with a long replay guarantee,
    -- and one value cannot be both.
    replay_until     timestamptz,

    -- A consumed flow must have a result and a replay deadline; one that is not
    -- consumed must have neither. Without this, "consumed with no recorded
    -- result" is representable, and that state re-executes on the next retry.
    CONSTRAINT mrtr_consumed_is_complete CHECK (
        (status = 'consumed' AND recorded_result IS NOT NULL
                             AND consumed_at IS NOT NULL
                             AND replay_until IS NOT NULL)
     OR (status <> 'consumed' AND recorded_result IS NULL
                              AND consumed_at IS NULL
                              AND replay_until IS NULL)
    )
);

CREATE INDEX mrtr_flows_principal_idx ON mrtr_flows (tenant_id, principal_id);
CREATE INDEX mrtr_flows_expiry_idx ON mrtr_flows (expires_at) WHERE status = 'awaiting_input';
CREATE INDEX mrtr_flows_replay_idx ON mrtr_flows (replay_until) WHERE status = 'consumed';

-- The side effect ops.deployment_apply performs. It exists to make the MRTR
-- demo real: what matters is that it is irreversible by declaration and that
-- its row count is a thing a test can assert on.
CREATE TABLE deployments (
    deployment_id   uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    principal_id    uuid NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
    plan            jsonb NOT NULL,
    applied_at      timestamptz NOT NULL DEFAULT now(),

    -- Exactly-once at the database level too. This is a BACKSTOP behind the
    -- engine, not the mechanism: see deployment_attempts below for why the
    -- distinction is load-bearing.
    correlation_id  text NOT NULL UNIQUE
);

-- Every time the effect actually RUNS, unconstrained.
--
-- This table exists so TestDuplicateRetryIsIdempotent can count real
-- executions. If the test counted rows in `deployments`, the UNIQUE constraint
-- above would hold the count at 1 even with a completely broken engine, and the
-- test would report success while the property it names had been lost.
-- Counting attempts measures the engine; counting deployments measures the
-- constraint. The suite does both, separately.
CREATE TABLE deployment_attempts (
    attempt_id      bigserial PRIMARY KEY,
    correlation_id  text NOT NULL,
    attempted_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX deployment_attempts_correlation_idx ON deployment_attempts (correlation_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON mrtr_flows TO broker_app;
GRANT SELECT, INSERT ON deployments TO broker_app;
GRANT SELECT, INSERT ON deployment_attempts TO broker_app;
GRANT USAGE, SELECT ON SEQUENCE deployment_attempts_attempt_id_seq TO broker_app;
