-- Server-minted state handles. SN-CAP-07 / docs/HANDOFF.md §7.4.
--
-- There is no session. Cross-call state exists ONLY as a handle passed as an
-- ordinary tool argument, and the specification is explicit that possession of
-- a handle is not authentication: every resolution re-verifies principal and
-- tenant against the validated token.
--
-- The shape of this table follows from that. principal_id and tenant_id are
-- columns, not metadata, because they are part of the WHERE clause on every
-- single read — not a check performed somewhere else and trusted afterwards.

CREATE TABLE state_handles (
    handle_id     text PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    principal_id  uuid NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,

    -- The binding, stored explicitly as "<principal_id>:<handle_id>". It is
    -- redundant with the two columns above by construction, and that is the
    -- point: it is verified on every use, so a row whose binding disagrees with
    -- its own columns is detectable rather than merely unlikely.
    binding       text NOT NULL,

    kind          text NOT NULL,
    payload       jsonb NOT NULL,

    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    revoked_at    timestamptz,

    CONSTRAINT state_handles_binding_matches
        CHECK (binding = principal_id::text || ':' || handle_id)
);

-- The resolution index covers the exact predicate resolve.go uses, in the same
-- order, so the one query that matters is an index-only lookup.
CREATE INDEX state_handles_resolution_idx
    ON state_handles (handle_id, tenant_id, principal_id)
    WHERE revoked_at IS NULL;

-- The GC sweep's predicate.
CREATE INDEX state_handles_expiry_idx ON state_handles (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON state_handles TO broker_app;
