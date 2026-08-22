-- The application role. Deliberately NOT the owner of anything.
--
-- The audit table's append-only property (docs/HANDOFF.md §7.6) is enforced by
-- grants, not by convention: the migration that creates `tool_invocations`
-- REVOKEs UPDATE, DELETE and TRUNCATE from this role. A test asserts that both
-- an UPDATE and a DELETE attempted as broker_app are refused by Postgres.
CREATE ROLE broker_app WITH LOGIN PASSWORD 'broker_app_dev_only';

-- Migrations run as the owner, which is the bootstrap superuser. Keeping the
-- two roles distinct is the whole point: if the app could migrate, it could
-- also drop the REVOKE.
GRANT CONNECT ON DATABASE sentinel TO broker_app;
GRANT USAGE ON SCHEMA public TO broker_app;
