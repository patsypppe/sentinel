package audit

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolSink writes an audit row in its own transaction.
//
// It is used for invocations whose effect is NOT a database write — a refused
// call, a scope denial, a read that touched nothing. §8.7 splits the two cases:
// the row is committed "in the same transaction as the side effect where the
// effect is a database write, and before the response is written otherwise".
//
// Tools whose effect IS a database write take the other path: mrtr.Engine hands
// its transaction to the effect, and the effect appends through Writer.Append
// so both commit together. That is why Append takes a pgx.Tx rather than
// opening its own — a writer that opened a connection could not be inside the
// effect's transaction, and the two could then diverge under a crash.
type PoolSink struct {
	pool   *pgxpool.Pool
	writer *Writer
}

func NewPoolSink(pool *pgxpool.Pool) *PoolSink {
	return &PoolSink{pool: pool, writer: NewWriter(pool)}
}

func (s *PoolSink) Record(ctx context.Context, r Record) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%w: begin: %w", ErrUnauditable, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := s.writer.Append(ctx, tx, r); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("%w: commit: %w", ErrUnauditable, err)
	}
	return nil
}

// EnsurePartitions exposes the writer's partition maintenance.
func (s *PoolSink) EnsurePartitions(ctx context.Context) error {
	return s.writer.EnsurePartitions(ctx)
}

// Writer returns the underlying writer, for effects that need to append inside
// their own transaction.
func (s *PoolSink) Writer() *Writer { return s.writer }
