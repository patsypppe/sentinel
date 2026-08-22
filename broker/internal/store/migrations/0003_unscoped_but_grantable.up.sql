-- A table the application role CAN read but no demo principal's scopes confer.
--
-- Without it the two guard layers cannot be told apart in a test. Every denied
-- relation would be one Postgres itself refuses (warehouse_restricted), so the
-- scope allowlist would never actually be the thing doing the refusing, and a
-- broken allowlist would still look green.
--
-- Layer separation, made testable:
--
--   warehouse.internal_notes       broker_app may SELECT it; no scope confers it
--                                  → the ALLOWLIST refuses
--   warehouse_restricted.payroll   broker_app may not SELECT it at all
--                                  → POSTGRES refuses, and the error is
--                                    translated into the same actionable shape

CREATE TABLE warehouse.internal_notes (
    note_id     bigint PRIMARY KEY,
    author      text NOT NULL,
    body        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO warehouse.internal_notes (note_id, author, body) VALUES
    (1, 'ops', 'Readable by the role, not conferred by any demo scope.');

GRANT SELECT ON warehouse.internal_notes TO broker_app;
