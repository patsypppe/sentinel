package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/patsypppe/sentinel/fleet/internal/model"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// advisoryLockKey serialises migrations across replicas that start together.
const advisoryLockKey int64 = 7_262_026_001

// Postgres is a Store backed by PostgreSQL.
type Postgres struct{ pool *pgxpool.Pool }

// OpenPostgres connects. It does not migrate; call Migrate with a role that may.
func OpenPostgres(ctx context.Context, url string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) Close() { p.pool.Close() }

// Migrate applies every migration not yet applied, in order, each in its own
// transaction, under an advisory lock. It returns the versions it applied. Running
// it twice applies nothing the second time.
func Migrate(ctx context.Context, url string) ([]string, error) {
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", advisoryLockKey); err != nil {
		return nil, fmt.Errorf("lock: %w", err)
	}
	defer func() { _, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", advisoryLockKey) }()

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return nil, fmt.Errorf("schema_migrations: %w", err)
	}

	names, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)

	var applied []string
	for _, name := range names {
		version := strings.TrimSuffix(strings.TrimPrefix(name, "migrations/"), ".sql")
		var done bool
		if err := conn.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)", version,
		).Scan(&done); err != nil {
			return applied, err
		}
		if done {
			continue
		}
		sqlText, err := migrationFiles.ReadFile(name)
		if err != nil {
			return applied, err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return applied, err
		}
		if _, err := tx.Exec(ctx, string(sqlText)); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("migration %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
			_ = tx.Rollback(ctx)
			return applied, err
		}
		if err := tx.Commit(ctx); err != nil {
			return applied, err
		}
		applied = append(applied, version)
	}
	return applied, nil
}

func (p *Postgres) SaveScan(ctx context.Context, run model.ScanRun) (int64, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		INSERT INTO targets (target, name, endpoint, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $4)
		ON CONFLICT (target) DO UPDATE SET
			name = EXCLUDED.name, endpoint = EXCLUDED.endpoint,
			last_seen = GREATEST(targets.last_seen, EXCLUDED.last_seen),
			first_seen = LEAST(targets.first_seen, EXCLUDED.first_seen)`,
		run.Target, run.Name, run.Endpoint, run.ScannedAt); err != nil {
		return 0, fmt.Errorf("target: %w", err)
	}

	var id int64
	err = tx.QueryRow(ctx, `
		INSERT INTO scan_runs (target, scanned_at, spec_revision, manifest_hash, gate, gate_failed,
			passing, failing, accepted, indeterminate, not_applicable)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (target, scanned_at) DO NOTHING
		RETURNING id`,
		run.Target, run.ScannedAt, run.SpecRevision, run.ManifestHash, run.Gate, run.GateFailed,
		run.Passing, run.Failing, run.Accepted, run.Indeterminate, run.NotApplicable,
	).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		// Already recorded: a retried publish. Return the original, change nothing.
		if err := tx.QueryRow(ctx,
			"SELECT id FROM scan_runs WHERE target = $1 AND scanned_at = $2",
			run.Target, run.ScannedAt).Scan(&id); err != nil {
			return 0, err
		}
		return id, tx.Commit(ctx)
	}
	if err != nil {
		return 0, fmt.Errorf("scan: %w", err)
	}

	batch := &pgx.Batch{}
	for _, f := range run.Findings {
		batch.Queue(`INSERT INTO scan_findings (scan_id, fingerprint, rule_id, severity, detail, accepted)
			VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
			id, f.Fingerprint, f.RuleID, f.Severity, f.Detail, f.Accepted)
	}
	for _, w := range run.Waivers {
		batch.Queue(`INSERT INTO waiver_ledger (scan_id, rule, endpoint, reason, expires_at, approved_by)
			VALUES ($1,$2,$3,$4,$5,$6)`, id, w.Rule, w.Endpoint, w.Reason, w.ExpiresAt, w.ApprovedBy)
	}
	if run.ManifestHash != "" {
		batch.Queue(`INSERT INTO manifest_snapshots (target, manifest_hash, first_seen, last_seen)
			VALUES ($1,$2,$3,$3)
			ON CONFLICT (target, manifest_hash) DO UPDATE SET
				last_seen = GREATEST(manifest_snapshots.last_seen, EXCLUDED.last_seen),
				first_seen = LEAST(manifest_snapshots.first_seen, EXCLUDED.first_seen)`,
			run.Target, run.ManifestHash, run.ScannedAt)
	}
	results := tx.SendBatch(ctx, batch)
	for i := 0; i < batch.Len(); i++ {
		if _, err := results.Exec(); err != nil {
			_ = results.Close()
			return 0, fmt.Errorf("detail row %d: %w", i, err)
		}
	}
	if err := results.Close(); err != nil {
		return 0, err
	}
	return id, tx.Commit(ctx)
}

const runColumns = `r.id, r.target, t.name, t.endpoint, r.scanned_at, r.spec_revision, r.manifest_hash,
	r.gate, r.gate_failed, r.passing, r.failing, r.accepted, r.indeterminate, r.not_applicable`

func scanRun(row pgx.Row) (model.ScanRun, error) {
	var r model.ScanRun
	err := row.Scan(&r.ID, &r.Target, &r.Name, &r.Endpoint, &r.ScannedAt, &r.SpecRevision,
		&r.ManifestHash, &r.Gate, &r.GateFailed, &r.Passing, &r.Failing, &r.Accepted,
		&r.Indeterminate, &r.NotApplicable)
	r.ScannedAt = r.ScannedAt.UTC()
	return r, err
}

func (p *Postgres) LatestPerTarget(ctx context.Context) ([]model.ScanRun, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT DISTINCT ON (r.target) `+runColumns+`
		FROM scan_runs r JOIN targets t ON t.target = r.target
		ORDER BY r.target, r.scanned_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.ScanRun
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if err := p.attach(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (p *Postgres) Scans(ctx context.Context, target string, since time.Time) ([]model.ScanRun, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT `+runColumns+`
		FROM scan_runs r JOIN targets t ON t.target = r.target
		WHERE r.target = $1 AND r.scanned_at >= $2
		ORDER BY r.scanned_at ASC`, target, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.ScanRun
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if err := p.attach(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// attach loads a scan's findings and waivers.
func (p *Postgres) attach(ctx context.Context, r *model.ScanRun) error {
	frows, err := p.pool.Query(ctx,
		`SELECT fingerprint, rule_id, severity, detail, accepted FROM scan_findings
		 WHERE scan_id = $1 ORDER BY rule_id, fingerprint`, r.ID)
	if err != nil {
		return err
	}
	for frows.Next() {
		var f model.Finding
		if err := frows.Scan(&f.Fingerprint, &f.RuleID, &f.Severity, &f.Detail, &f.Accepted); err != nil {
			frows.Close()
			return err
		}
		r.Findings = append(r.Findings, f)
	}
	frows.Close()
	if err := frows.Err(); err != nil {
		return err
	}

	wrows, err := p.pool.Query(ctx,
		`SELECT rule, endpoint, reason, expires_at, approved_by FROM waiver_ledger
		 WHERE scan_id = $1 ORDER BY rule`, r.ID)
	if err != nil {
		return err
	}
	defer wrows.Close()
	for wrows.Next() {
		var w model.Waiver
		if err := wrows.Scan(&w.Rule, &w.Endpoint, &w.Reason, &w.ExpiresAt, &w.ApprovedBy); err != nil {
			return err
		}
		w.ExpiresAt = time.Date(w.ExpiresAt.Year(), w.ExpiresAt.Month(), w.ExpiresAt.Day(), 0, 0, 0, 0, time.UTC)
		r.Waivers = append(r.Waivers, w)
	}
	return wrows.Err()
}
