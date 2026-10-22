-- Core identity. Taken from SN-PRD-001 §6.2.
--
-- tenant_id columns exist throughout and the schema is multi-tenant, but
-- ENFORCEMENT of tenant isolation is out of scope for the MVP (docs/HANDOFF.md
-- §3.2). Single tenant, two principals — enough to prove handle binding, which
-- is the property that actually needs proving.

CREATE TABLE tenants (
    tenant_id   uuid PRIMARY KEY,
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE principals (
    principal_id  uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    subject       text NOT NULL,
    display_name  text NOT NULL,
    scopes        text[] NOT NULL DEFAULT '{}',
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, subject)
);

CREATE INDEX principals_tenant_idx ON principals (tenant_id);

-- The demo tenant and its two principals. Two is the minimum that can
-- demonstrate a cross-principal refusal, which is the point of having them.
INSERT INTO tenants (tenant_id, name) VALUES
    ('00000000-0000-0000-0000-000000000001', 'acme');

INSERT INTO principals (principal_id, tenant_id, subject, display_name, scopes) VALUES
    ('00000000-0000-0000-0000-0000000000a1',
     '00000000-0000-0000-0000-000000000001',
     'analyst@acme.example',
     'Ada the analyst',
     ARRAY['warehouse:read', 'warehouse:describe']),
    ('00000000-0000-0000-0000-0000000000a2',
     '00000000-0000-0000-0000-000000000001',
     'operator@acme.example',
     'Ola the operator',
     ARRAY['warehouse:read', 'warehouse:describe', 'ops:plan', 'ops:apply']);

GRANT SELECT ON tenants, principals TO broker_app;
