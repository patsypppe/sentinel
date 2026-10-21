package store

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Migrations are plain SQL up/down files a reviewer can read, applied by a
// runner short enough to read as well.
//
// docs/HANDOFF.md §6 names golang-migrate. This runs the same file layout
// (NNNN_name.up.sql / .down.sql) with about sixty lines instead of a dependency
// tree, and keeps the property that mattered in the choice: the SQL is plain and
// legible. Swapping in golang-migrate later needs no file changes.
//
//go:embed migrations/*.sql
var migrationFS embed.FS

const schemaTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     text PRIMARY KEY,
    applied_at  timestamptz NOT NULL DEFAULT now()
);`

// Migration is one versioned step.
type Migration struct {
	Version string
	Up      string
	Down    string
}

// LoadMigrations reads the embedded migrations in version order.
func LoadMigrations() ([]Migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("store: read migrations: %w", err)
	}

	byVersion := map[string]*Migration{}
	for _, e := range entries {
		name := e.Name()
		version, direction, ok := splitMigrationName(name)
		if !ok {
			return nil, fmt.Errorf("store: %q is not NNNN_name.up.sql or NNNN_name.down.sql", name)
		}
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, fmt.Errorf("store: read %s: %w", name, err)
		}
		m, ok := byVersion[version]
		if !ok {
			m = &Migration{Version: version}
			byVersion[version] = m
		}
		if direction == "up" {
			m.Up = string(body)
		} else {
			m.Down = string(body)
		}
	}

	out := make([]Migration, 0, len(byVersion))
	for _, m := range byVersion {
		if m.Up == "" {
			return nil, fmt.Errorf("store: migration %s has no up file", m.Version)
		}
		if m.Down == "" {
			return nil, fmt.Errorf("store: migration %s has no down file; "+
				"a migration you cannot reverse is a migration you cannot deploy twice", m.Version)
		}
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

func splitMigrationName(name string) (version, direction string, ok bool) {
	switch {
	case strings.HasSuffix(name, ".up.sql"):
		direction = "up"
		name = strings.TrimSuffix(name, ".up.sql")
	case strings.HasSuffix(name, ".down.sql"):
		direction = "down"
		name = strings.TrimSuffix(name, ".down.sql")
	default:
		return "", "", false
	}
	idx := strings.Index(name, "_")
	if idx <= 0 {
		return "", "", false
	}
	return name[:idx], direction, true
}

// Migrate applies every unapplied migration, each in its own transaction, in
// version order.
//
// It connects with the MIGRATION url, not the application one. broker_app must
// not be able to migrate: the audit table's append-only property is a REVOKE
// that a migrating role could simply drop.
func Migrate(ctx context.Context, migrationURL string) (applied []string, err error) {
	conn, err := pgx.Connect(ctx, migrationURL)
	if err != nil {
		return nil, fmt.Errorf("store: migrate connect: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	if _, err := conn.Exec(ctx, schemaTable); err != nil {
		return nil, fmt.Errorf("store: create schema_migrations: %w", err)
	}

	rows, err := conn.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("store: read schema_migrations: %w", err)
	}
	done := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: scan schema_migrations: %w", err)
		}
		done[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate schema_migrations: %w", err)
	}

	migrations, err := LoadMigrations()
	if err != nil {
		return nil, err
	}

	for _, m := range migrations {
		if done[m.Version] {
			continue
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return applied, fmt.Errorf("store: begin %s: %w", m.Version, err)
		}
		if _, err := tx.Exec(ctx, m.Up); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("store: apply %s: %w", m.Version, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (version) VALUES ($1)`, m.Version); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("store: record %s: %w", m.Version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return applied, fmt.Errorf("store: commit %s: %w", m.Version, err)
		}
		applied = append(applied, m.Version)
	}
	return applied, nil
}
