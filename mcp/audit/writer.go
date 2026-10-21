package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrUnauditable is returned when a row could not be written. Callers must
// treat it as fatal to the invocation: an unauditable action does not happen.
var ErrUnauditable = errors.New("audit: the invocation could not be recorded and therefore did not happen")

// Writer appends to the chain.
type Writer struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

func NewWriter(pool *pgxpool.Pool) *Writer {
	return &Writer{pool: pool, now: time.Now}
}

// WithClock replaces the clock, for tests.
func (w *Writer) WithClock(now func() time.Time) *Writer {
	return &Writer{pool: w.pool, now: now}
}

// chainHeadSQL reads the tenant's current chain head.
const chainHeadSQL = `
SELECT row_hash
  FROM tool_invocations
 WHERE tenant_id = $1
 ORDER BY seq DESC
 LIMIT 1`

const insertSQL = `
INSERT INTO tool_invocations (
    occurred_at, tenant_id, principal_id, tool_name, scopes_exercised,
    arguments_redacted, protocol_version, trace_id, correlation_id,
    outcome, error_code, duration_ms, prev_hash, row_hash
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
RETURNING seq`

// Append writes one row, inside the caller's transaction.
//
// §8.7's ordering rule: the audit row is committed IN THE SAME TRANSACTION as
// the side effect where the effect is a database write. Taking a pgx.Tx rather
// than opening one is what makes that possible — a writer that opened its own
// connection could not be in the effect's transaction, and the two could then
// diverge under a crash.
func (w *Writer) Append(ctx context.Context, tx pgx.Tx, r Record) (seq int64, err error) {
	if r.TenantID == "" || r.PrincipalID == "" || r.ToolName == "" {
		return 0, fmt.Errorf("%w: tenant, principal and tool are all required", ErrUnauditable)
	}
	if r.OccurredAt.IsZero() {
		r.OccurredAt = w.now()
	}

	// Serialize the tenant's chain for the rest of this transaction.
	//
	// Without this, two concurrent invocations both read the same head and both
	// chain off it, producing two rows with the same prev_hash. Verification
	// would then report a break that never happened — a false alarm on an
	// honest server, which is worse than useless.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, r.TenantID); err != nil {
		return 0, fmt.Errorf("%w: lock chain: %w", ErrUnauditable, err)
	}

	prev := GenesisHash
	err = tx.QueryRow(ctx, chainHeadSQL, r.TenantID).Scan(&prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("%w: read chain head: %w", ErrUnauditable, err)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		prev = GenesisHash
	}

	rowHash, err := RowHash(prev, r)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrUnauditable, err)
	}

	args := r.ArgumentsRedacted
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	// The stored bytes must be the CANONICAL ones, because verification
	// recomputes the hash from what it reads back. Storing the raw form and
	// hashing the canonical one would make every row verify as tampered.
	canonicalArgs, err := canonicalArguments(args)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrUnauditable, err)
	}

	scopes := r.ScopesExercised
	if scopes == nil {
		scopes = []string{}
	}

	seq, err = w.insert(ctx, tx, r, canonicalArgs, scopes, prev, rowHash)
	if err != nil {
		return 0, err
	}
	return seq, nil
}

func (w *Writer) insert(
	ctx context.Context, tx pgx.Tx, r Record,
	args []byte, scopes []string, prev, rowHash string,
) (int64, error) {
	exec := func(q pgx.Tx) (int64, error) {
		var seq int64
		err := q.QueryRow(ctx, insertSQL,
			r.OccurredAt, r.TenantID, r.PrincipalID, r.ToolName, scopes,
			args, r.ProtocolVersion, r.TraceID, r.CorrelationID,
			r.Outcome, nullableCode(r.ErrorCode), r.DurationMs, prev, rowHash,
		).Scan(&seq)
		return seq, err
	}

	// The first attempt runs inside a SAVEPOINT.
	//
	// This is not defensive style, it is required: a failed statement aborts
	// the whole Postgres transaction, and every subsequent command in it is
	// refused with "current transaction is aborted". Without a savepoint to
	// roll back to, the partition-creation retry below could not run — and
	// crucially, neither could the CALLER's transaction, which the audit row
	// shares with the side effect. A missing partition would take the effect
	// down with it.
	sp, err := tx.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("%w: savepoint: %w", ErrUnauditable, err)
	}

	seq, err := exec(sp)
	if err == nil {
		if err := sp.Commit(ctx); err != nil {
			return 0, fmt.Errorf("%w: release savepoint: %w", ErrUnauditable, err)
		}
		return seq, nil
	}
	if rbErr := sp.Rollback(ctx); rbErr != nil {
		return 0, fmt.Errorf("%w: rollback savepoint: %w", ErrUnauditable, rbErr)
	}

	// The month rolled over and no partition exists. This is §14 gotcha 9, and
	// it happens at midnight on the first, which is exactly when nobody is
	// looking. A rollover job creates partitions ahead of time; this is the
	// backstop for when it did not run.
	if isMissingPartition(err) {
		if _, ensureErr := tx.Exec(ctx,
			`SELECT ensure_invocation_partition($1)`, r.OccurredAt); ensureErr != nil {
			return 0, fmt.Errorf("%w: create partition: %w", ErrUnauditable, ensureErr)
		}
		seq, retryErr := exec(tx)
		if retryErr == nil {
			return seq, nil
		}
		return 0, fmt.Errorf("%w: %w", ErrUnauditable, retryErr)
	}

	return 0, fmt.Errorf("%w: %w", ErrUnauditable, err)
}

// isMissingPartition reports whether an insert failed for want of a partition.
func isMissingPartition(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		// 23514 is check_violation, which is what Postgres raises for
		// "no partition of relation ... found for row".
		if pgErr.Code == "23514" && strings.Contains(pgErr.Message, "partition") {
			return true
		}
	}
	return strings.Contains(err.Error(), "no partition of relation")
}

func nullableCode(code int) any {
	if code == 0 {
		return nil
	}
	return code
}

func canonicalArguments(args json.RawMessage) ([]byte, error) {
	return canonicalStrict(args)
}

// EnsurePartitions creates the partitions for now and the next month.
//
// Called at start and on a schedule. §14 gotcha 9: without this, inserts fail
// hard at a month boundary.
func (w *Writer) EnsurePartitions(ctx context.Context) error {
	now := w.now()
	for _, at := range []time.Time{now, now.AddDate(0, 1, 0)} {
		if _, err := w.pool.Exec(ctx, `SELECT ensure_invocation_partition($1)`, at); err != nil {
			return fmt.Errorf("audit: ensure partition for %s: %w", at.Format("2006-01"), err)
		}
	}
	return nil
}

// RunPartitionRollover keeps partitions ahead of the clock.
func (w *Writer) RunPartitionRollover(ctx context.Context, every time.Duration, onSweep func(error)) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.EnsurePartitions(ctx); onSweep != nil {
				onSweep(err)
			}
		}
	}
}
