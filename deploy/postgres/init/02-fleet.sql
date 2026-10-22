-- The fleet service's database and its two roles.
--
-- Scans are an append-only record: the application role may read and insert scans,
-- findings and waivers and may not update or delete them, so a compromised service
-- cannot rewrite a target's history. It may update `targets` and `manifest_snapshots`
-- (last_seen) and nothing else. Migrations run as the owner, which creates the
-- tables; the grants below are applied to whatever the owner creates.
CREATE DATABASE fleet;
CREATE ROLE fleet_app WITH LOGIN PASSWORD 'fleet_app_dev_only';
GRANT CONNECT ON DATABASE fleet TO fleet_app;

\connect fleet
GRANT USAGE ON SCHEMA public TO fleet_app;
ALTER DEFAULT PRIVILEGES FOR ROLE sentinel IN SCHEMA public
    GRANT SELECT, INSERT ON TABLES TO fleet_app;
ALTER DEFAULT PRIVILEGES FOR ROLE sentinel IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO fleet_app;
