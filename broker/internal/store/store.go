// Package store owns the Postgres connection pool and the migration runner.
//
// No ORM. The queries in this repository are short, and the two that matter
// most — handle resolution and the audit append — are security-critical enough
// that a reviewer should be able to read the exact SQL that runs.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Store is a pgx pool plus the small amount of policy that belongs with it.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects and verifies reachability. A broker that cannot reach its
// database cannot write an audit row, and an unauditable action does not
// happen, so failing here is failing closed.
func Open(ctx context.Context, url string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("store: parse database url: %w", err)
	}
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConns = 10

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Pool exposes the underlying pool for packages that own their own SQL.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

func (s *Store) Close() { s.pool.Close() }
