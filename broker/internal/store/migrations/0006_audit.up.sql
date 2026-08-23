-- The immutable audit log. SN-CAP-25 / docs/HANDOFF.md §7.6 and §8.7.
--
-- Rule 4 of §2: every tool invocation writes an append-only, hash-chained row,
-- and the audit write FAILS THE INVOCATION if it fails. An unauditable action
-- does not happen.
--
-- Two things here are load-bearing and easy to skip:
--
--   1. Append-only is enforced by GRANTS, not by convention. broker_app may
--      INSERT and SELECT and nothing else, so an UPDATE from application code
--      is refused by Postgres rather than by a code review.
--   2. Partitions are created AUTOMATICALLY. Without that, inserts fail hard at
--      a month boundary -- at midnight on the first, which is exactly when
--      nobody is looking.

CREATE TABLE tool_invocations (
    seq                bigserial,
    occurred_at        timestamptz NOT NULL DEFAULT now(),

    tenant_id          uuid NOT NULL,
    principal_id       uuid NOT NULL,

    tool_name          text NOT NULL,
    scopes_exercised   text[] NOT NULL,

    -- `json`, not `jsonb`, for the same reason mrtr_flows.recorded_result is.
    --
    -- Verification recomputes each row's hash from the stored fields and
    -- compares it to the stored hash. jsonb is a parsed representation: it
    -- re-emits with its own spacing and sorts keys, so the bytes that come back
    -- out are not the bytes that went in, and every row would verify as
    -- tampered. `json` stores the exact input text.
    arguments_redacted json NOT NULL,

    protocol_version   text NOT NULL,
    trace_id           text NOT NULL DEFAULT '',
    correlation_id     text NOT NULL DEFAULT '',

    outcome            text NOT NULL CHECK (outcome IN ('ok', 'error', 'denied')),
    error_code         integer,

    -- Integer milliseconds. §8.7 forbids floats in the hashed fields: languages
    -- disagree on how to print one, and a hash that depends on a float's
    -- rendering is not portable.
    duration_ms        bigint NOT NULL CHECK (duration_ms >= 0),

    -- The chain. Per tenant; the first row's prev_hash is 64 zeros.
    prev_hash          text NOT NULL CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
    row_hash           text NOT NULL CHECK (row_hash ~ '^[0-9a-f]{64}$'),

    -- The partition key must be part of the primary key.
    PRIMARY KEY (seq, occurred_at)
) PARTITION BY RANGE (occurred_at);

CREATE INDEX tool_invocations_chain_idx ON tool_invocations (tenant_id, seq DESC);
CREATE INDEX tool_invocations_principal_idx ON tool_invocations (tenant_id, principal_id, occurred_at DESC);

-- Partition automation.
--
-- ensure_invocation_partition is idempotent and applies the same restricted
-- grants to every partition it creates. A grant applied to the parent does not
-- reach a partition created later, so doing it here rather than once at the top
-- is what keeps the property true in three months' time.
-- SECURITY DEFINER, because broker_app deliberately has no CREATE on the
-- schema. Letting the application create arbitrary tables to solve a partition
-- problem would trade a narrow capability for a broad one; instead it may
-- invoke exactly this function, which creates exactly one shape of table and
-- applies the restricted grants itself.
--
-- search_path is pinned on the function, which is mandatory for a
-- SECURITY DEFINER function: without it, a caller can prepend a schema of their
-- own and have their to_regclass or format resolved instead of the intended one.
CREATE OR REPLACE FUNCTION ensure_invocation_partition(at timestamptz)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    start_at date := date_trunc('month', at)::date;
    end_at   date := (date_trunc('month', at) + interval '1 month')::date;
    part     text := format('tool_invocations_%s', to_char(start_at, 'YYYY_MM'));
BEGIN
    IF to_regclass(part) IS NOT NULL THEN
        RETURN part;
    END IF;

    EXECUTE format(
        'CREATE TABLE %I PARTITION OF tool_invocations FOR VALUES FROM (%L) TO (%L)',
        part, start_at, end_at);

    -- Append-only, on this partition specifically.
    EXECUTE format('REVOKE ALL ON %I FROM broker_app', part);
    EXECUTE format('GRANT INSERT, SELECT ON %I TO broker_app', part);

    RETURN part;
END;
$$;

-- The current month and the next one, so a deployment on the 31st does not
-- fail at midnight.
SELECT ensure_invocation_partition(now());
SELECT ensure_invocation_partition(now() + interval '1 month');

-- The application role may only APPEND.
--
-- This is the line that makes the log immutable. Everything else -- the hash
-- chain, the verification command -- detects tampering; this prevents the
-- ordinary kind.
REVOKE ALL ON tool_invocations FROM broker_app;
GRANT INSERT, SELECT ON tool_invocations TO broker_app;
GRANT USAGE, SELECT ON SEQUENCE tool_invocations_seq_seq TO broker_app;
GRANT EXECUTE ON FUNCTION ensure_invocation_partition(timestamptz) TO broker_app;
