-- The fleet service's schema.
--
-- Scans are an append-only record. The application role needs INSERT and SELECT on
-- scan_runs, scan_findings and waiver_ledger and nothing more: nothing in the service
-- updates or deletes a scan, and a role that cannot is a role that cannot rewrite
-- history. `targets` and `manifest_snapshots` are the two tables the service updates
-- (last_seen), so they alone need UPDATE.
--
--   GRANT SELECT, INSERT ON scan_runs, scan_findings, waiver_ledger TO sentinel_app;
--   GRANT SELECT, INSERT, UPDATE ON targets, manifest_snapshots TO sentinel_app;
--   GRANT USAGE ON SEQUENCE scan_runs_id_seq TO sentinel_app;

CREATE TABLE targets (
    target     text PRIMARY KEY,
    name       text NOT NULL DEFAULT '',
    endpoint   text NOT NULL DEFAULT '',
    first_seen timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL
);

CREATE TABLE scan_runs (
    id             bigserial PRIMARY KEY,
    target         text NOT NULL REFERENCES targets (target),
    scanned_at     timestamptz NOT NULL,
    spec_revision  text NOT NULL DEFAULT '',
    manifest_hash  text NOT NULL DEFAULT '',
    gate           text NOT NULL DEFAULT '',
    gate_failed    boolean NOT NULL DEFAULT false,
    passing        integer NOT NULL,
    failing        integer NOT NULL,
    accepted       integer NOT NULL,
    indeterminate  integer NOT NULL,
    not_applicable integer NOT NULL,
    -- A retried publish of the same scan must not double-count a day.
    CONSTRAINT scan_runs_once UNIQUE (target, scanned_at)
);

CREATE INDEX scan_runs_target_time ON scan_runs (target, scanned_at DESC);

CREATE TABLE scan_findings (
    scan_id     bigint NOT NULL REFERENCES scan_runs (id) ON DELETE CASCADE,
    fingerprint text NOT NULL,
    rule_id     text NOT NULL,
    severity    text NOT NULL,
    detail      text NOT NULL DEFAULT '',
    accepted    boolean NOT NULL,
    PRIMARY KEY (scan_id, fingerprint)
);

CREATE INDEX scan_findings_fingerprint ON scan_findings (fingerprint);

CREATE TABLE waiver_ledger (
    scan_id     bigint NOT NULL REFERENCES scan_runs (id) ON DELETE CASCADE,
    rule        text NOT NULL,
    endpoint    text NOT NULL DEFAULT '',
    reason      text NOT NULL,
    expires_at  date NOT NULL,
    approved_by text NOT NULL DEFAULT ''
);

CREATE INDEX waiver_ledger_scan ON waiver_ledger (scan_id);

CREATE TABLE manifest_snapshots (
    target        text NOT NULL REFERENCES targets (target),
    manifest_hash text NOT NULL,
    first_seen    timestamptz NOT NULL,
    last_seen     timestamptz NOT NULL,
    PRIMARY KEY (target, manifest_hash)
);
