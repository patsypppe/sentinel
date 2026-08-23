//go:build integration

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/patsypppe/sentinel/broker/internal/store"
)

const (
	demoTenant = "00000000-0000-0000-0000-000000000001"
	analystID  = "00000000-0000-0000-0000-0000000000a1"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func appURL() string {
	return envOr("BROKER_DATABASE_URL",
		"postgres://broker_app:broker_app_dev_only@localhost:5432/sentinel?sslmode=disable")
}

func ownerURL() string {
	return envOr("BROKER_MIGRATE_DATABASE_URL",
		"postgres://sentinel:sentinel_dev_only@localhost:5432/sentinel?sslmode=disable")
}

// appPool connects as broker_app — the role the server actually uses, and the
// one the grants restrict.
func appPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	if _, err := store.Migrate(ctx, ownerURL()); err != nil {
		t.Skipf("postgres is not reachable (run `make up`): %v", err)
	}
	s, err := store.Open(ctx, appURL())
	if err != nil {
		t.Skipf("postgres is not reachable (run `make up`): %v", err)
	}
	t.Cleanup(s.Close)
	return s.Pool()
}

// ownerConn connects as the migration role, which CAN rewrite rows. Tamper
// detection is only meaningful if something is able to tamper.
func ownerConn(t *testing.T) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), ownerURL())
	if err != nil {
		t.Skipf("postgres is not reachable: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// tenant returns a fresh tenant id so each test owns its own chain and the
// tests do not interfere with one another's verification windows.
func tenant(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	conn := ownerConn(t)
	var id string
	if err := conn.QueryRow(context.Background(),
		`INSERT INTO tenants (tenant_id, name) VALUES (gen_random_uuid(), $1)
		 RETURNING tenant_id::text`, "test-"+t.Name()).Scan(&id); err != nil {
		t.Fatal(err)
	}
	// The audit table has no FK to tenants, deliberately: an audit row must
	// survive its tenant being deleted. The row here exists only so the test's
	// principal has somewhere to belong.
	if _, err := conn.Exec(context.Background(),
		`INSERT INTO principals (principal_id, tenant_id, subject, display_name, scopes)
		 VALUES ($1, $2, $3, $3, '{}')`, analystID+"", id, "t-"+t.Name()); err != nil {
		// The shared analyst principal already exists; that is fine.
		_ = err
	}
	return id
}

func appendN(t *testing.T, w *Writer, pool *pgxpool.Pool, tenantID string, n int) []int64 {
	t.Helper()
	ctx := context.Background()
	var seqs []int64

	for i := 0; i < n; i++ {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		seq, err := w.Append(ctx, tx, Record{
			TenantID:          tenantID,
			PrincipalID:       analystID,
			ToolName:          "warehouse.query",
			ScopesExercised:   []string{"warehouse:read"},
			ArgumentsRedacted: json.RawMessage(`{"sql":"SELECT 1","n":` + itoa(i) + `}`),
			ProtocolVersion:   "2026-07-28",
			Outcome:           OutcomeOK,
			DurationMs:        int64(10 + i),
		})
		if err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("append %d: %v", i, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, seq)
	}
	return seqs
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func window() (time.Time, time.Time) {
	now := time.Now()
	return now.AddDate(0, -1, 0), now.AddDate(0, 2, 0)
}

// TestAppRoleCannotUpdateOrDelete.
//
// This is the line that makes the log immutable, and it is enforced by
// Postgres rather than by a code review. Both statements are attempted AS
// broker_app — the role the server actually runs as.
func TestAppRoleCannotUpdateOrDelete(t *testing.T) {
	pool := appPool(t)
	w := NewWriter(pool)
	tenantID := tenant(t, pool)
	appendN(t, w, pool, tenantID, 1)

	ctx := context.Background()

	_, updateErr := pool.Exec(ctx,
		`UPDATE tool_invocations SET outcome = 'ok' WHERE tenant_id = $1`, tenantID)
	if updateErr == nil {
		t.Error("broker_app was able to UPDATE the audit log")
	} else if !strings.Contains(updateErr.Error(), "permission denied") {
		t.Errorf("UPDATE failed for the wrong reason: %v", updateErr)
	}

	_, deleteErr := pool.Exec(ctx,
		`DELETE FROM tool_invocations WHERE tenant_id = $1`, tenantID)
	if deleteErr == nil {
		t.Error("broker_app was able to DELETE from the audit log")
	} else if !strings.Contains(deleteErr.Error(), "permission denied") {
		t.Errorf("DELETE failed for the wrong reason: %v", deleteErr)
	}

	_, truncateErr := pool.Exec(ctx, `TRUNCATE tool_invocations`)
	if truncateErr == nil {
		t.Error("broker_app was able to TRUNCATE the audit log")
	}
}

// TestGrantsApplyToPartitionsCreatedLater.
//
// A grant on the parent does not reach a partition created afterwards. Without
// the REVOKE/GRANT inside ensure_invocation_partition, the log would become
// mutable again at the next month boundary — silently, and only for new rows.
func TestGrantsApplyToPartitionsCreatedLater(t *testing.T) {
	pool := appPool(t)
	ctx := context.Background()

	future := time.Now().AddDate(0, 6, 0)
	var part string
	if err := pool.QueryRow(ctx, `SELECT ensure_invocation_partition($1)`, future).Scan(&part); err != nil {
		t.Fatal(err)
	}

	var canUpdate bool
	if err := pool.QueryRow(ctx,
		`SELECT has_table_privilege('broker_app', $1, 'UPDATE')`, part).Scan(&canUpdate); err != nil {
		t.Fatal(err)
	}
	if canUpdate {
		t.Fatalf("broker_app can UPDATE partition %s, which was created after the parent's "+
			"grants were applied", part)
	}

	var canInsert bool
	if err := pool.QueryRow(ctx,
		`SELECT has_table_privilege('broker_app', $1, 'INSERT')`, part).Scan(&canInsert); err != nil {
		t.Fatal(err)
	}
	if !canInsert {
		t.Fatalf("broker_app cannot INSERT into partition %s; the log is now write-only "+
			"in the wrong direction", part)
	}
}

func TestChainVerifiesWhenIntact(t *testing.T) {
	pool := appPool(t)
	w := NewWriter(pool)
	tenantID := tenant(t, pool)
	appendN(t, w, pool, tenantID, 20)

	from, to := window()
	res, err := NewVerifier(pool).Verify(context.Background(), tenantID, from, to)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("an untouched chain failed to verify: %s", res.Break)
	}
	if res.Rows != 20 {
		t.Fatalf("verified %d rows, want 20", res.Rows)
	}
	if !res.StartedFromGenesis {
		t.Fatal("a chain starting at its first row should be reported as starting from genesis")
	}
}

// TestChainDetectsTampering — one of the nine negative tests of §11.
//
// The mutation is made through a SUPERUSER connection, because broker_app
// cannot make it: the grants already stop the ordinary case. The hash chain
// exists for the case where someone gets past them.
func TestChainDetectsTampering(t *testing.T) {
	pool := appPool(t)
	w := NewWriter(pool)
	tenantID := tenant(t, pool)
	seqs := appendN(t, w, pool, tenantID, 10)

	target := seqs[4] // the fifth row
	conn := ownerConn(t)
	if _, err := conn.Exec(context.Background(),
		`UPDATE tool_invocations SET outcome = 'denied' WHERE tenant_id = $1 AND seq = $2`,
		tenantID, target); err != nil {
		t.Fatal(err)
	}

	from, to := window()
	res, err := NewVerifier(pool).Verify(context.Background(), tenantID, from, to)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("a rewritten row was not detected")
	}
	if res.Break.Seq != target {
		t.Fatalf("verification points at seq %d, want exactly %d — an investigator following "+
			"this would look at the wrong row", res.Break.Seq, target)
	}
	if res.Break.Reason != ReasonRowRewritten {
		t.Fatalf("reason = %q, want the rewritten-row reason", res.Break.Reason)
	}
}

// TestChainDetectsDeletion, and reports it as a BROKEN LINK rather than a
// rewritten row. A deletion leaves every remaining row internally consistent,
// so reporting "contents rewritten" would send an investigator looking for the
// wrong thing.
func TestChainDetectsDeletion(t *testing.T) {
	pool := appPool(t)
	w := NewWriter(pool)
	tenantID := tenant(t, pool)
	seqs := appendN(t, w, pool, tenantID, 10)

	conn := ownerConn(t)
	if _, err := conn.Exec(context.Background(),
		`DELETE FROM tool_invocations WHERE tenant_id = $1 AND seq = $2`,
		tenantID, seqs[4]); err != nil {
		t.Fatal(err)
	}

	from, to := window()
	res, err := NewVerifier(pool).Verify(context.Background(), tenantID, from, to)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("a deleted row was not detected")
	}
	if res.Break.Seq != seqs[5] {
		t.Fatalf("break reported at seq %d, want %d — the row AFTER the deletion is where "+
			"the link fails", res.Break.Seq, seqs[5])
	}
	if res.Break.Reason != ReasonLinkBroken {
		t.Fatalf("reason = %q, want the broken-link reason: a deletion leaves every "+
			"remaining row internally consistent", res.Break.Reason)
	}
}

// TestChainsAreIndependentPerTenant. One tenant's tampering must not make
// another tenant's log unverifiable.
func TestChainsAreIndependentPerTenant(t *testing.T) {
	pool := appPool(t)
	w := NewWriter(pool)

	a, b := tenant(t, pool), tenant(t, pool)
	appendN(t, w, pool, a, 5)
	seqsB := appendN(t, w, pool, b, 5)

	conn := ownerConn(t)
	if _, err := conn.Exec(context.Background(),
		`UPDATE tool_invocations SET tool_name = 'tampered' WHERE tenant_id = $1 AND seq = $2`,
		b, seqsB[2]); err != nil {
		t.Fatal(err)
	}

	from, to := window()
	v := NewVerifier(pool)

	resA, err := v.Verify(context.Background(), a, from, to)
	if err != nil {
		t.Fatal(err)
	}
	if !resA.OK() {
		t.Fatalf("tenant A's chain broke because tenant B's was tampered with: %s", resA.Break)
	}

	resB, err := v.Verify(context.Background(), b, from, to)
	if err != nil {
		t.Fatal(err)
	}
	if resB.OK() {
		t.Fatal("tenant B's tampering was not detected")
	}
}

// TestConcurrentAppendsProduceAValidChain.
//
// Without the per-tenant advisory lock, two concurrent invocations both read
// the same chain head and both chain off it — producing a break on an entirely
// honest server, which is worse than useless.
func TestConcurrentAppendsProduceAValidChain(t *testing.T) {
	pool := appPool(t)
	w := NewWriter(pool)
	tenantID := tenant(t, pool)

	const concurrency = 12
	errs := make(chan error, concurrency)
	start := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		go func(i int) {
			<-start
			ctx := context.Background()
			tx, err := pool.Begin(ctx)
			if err != nil {
				errs <- err
				return
			}
			_, err = w.Append(ctx, tx, Record{
				TenantID: tenantID, PrincipalID: analystID,
				ToolName: "warehouse.query", ScopesExercised: []string{"warehouse:read"},
				ArgumentsRedacted: json.RawMessage(`{"n":` + itoa(i) + `}`),
				ProtocolVersion:   "2026-07-28", Outcome: OutcomeOK, DurationMs: int64(i),
			})
			if err != nil {
				_ = tx.Rollback(ctx)
				errs <- err
				return
			}
			errs <- tx.Commit(ctx)
		}(i)
	}
	close(start)

	for i := 0; i < concurrency; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent append failed: %v", err)
		}
	}

	from, to := window()
	res, err := NewVerifier(pool).Verify(context.Background(), tenantID, from, to)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("concurrent appends produced a broken chain on an honest server: %s", res.Break)
	}
	if res.Rows != concurrency {
		t.Fatalf("verified %d rows, want %d", res.Rows, concurrency)
	}
}

// TestAuditFailureFailsInvocation. Fail closed: if the row cannot be written,
// the caller must be told, and the transaction it shares with the effect must
// not commit.
func TestAuditFailureFailsInvocation(t *testing.T) {
	pool := appPool(t)
	w := NewWriter(pool)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// A record missing its principal cannot be attributed to anyone, so it
	// cannot be audited, so the invocation did not happen.
	_, err = w.Append(ctx, tx, Record{
		TenantID: demoTenant, ToolName: "warehouse.query", Outcome: OutcomeOK,
	})
	if !errors.Is(err, ErrUnauditable) {
		t.Fatalf("err = %v, want ErrUnauditable", err)
	}
	if !strings.Contains(err.Error(), "did not happen") {
		t.Fatalf("the error must say the invocation did not happen: %v", err)
	}
}

// TestEffectAndAuditCommitTogether. §8.7's ordering rule: the audit row is
// committed in the SAME TRANSACTION as the side effect. Rolling back must take
// both.
func TestEffectAndAuditCommitTogether(t *testing.T) {
	pool := appPool(t)
	w := NewWriter(pool)
	tenantID := tenant(t, pool)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, tx, Record{
		TenantID: tenantID, PrincipalID: analystID, ToolName: "warehouse.query",
		ScopesExercised: []string{"warehouse:read"},
		ProtocolVersion: "2026-07-28", Outcome: OutcomeOK, DurationMs: 1,
	}); err != nil {
		t.Fatal(err)
	}
	// The "effect" fails, so the whole transaction rolls back.
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM tool_invocations WHERE tenant_id = $1`, tenantID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d audit rows survived a rolled-back transaction; the row and the effect "+
			"must commit together or not at all", n)
	}
}

// TestPartitionAutoCreated. §14 gotcha 9: without automation, inserts fail hard
// at a month boundary — at midnight on the first, which is exactly when nobody
// is looking.
//
// The database clock cannot be advanced, so the row's own occurred_at is placed
// several months out, which reaches the same code path: no partition exists for
// it until one is created.
func TestPartitionAutoCreated(t *testing.T) {
	pool := appPool(t)
	w := NewWriter(pool)
	tenantID := tenant(t, pool)
	ctx := context.Background()

	future := time.Now().AddDate(0, 4, 0)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := w.Append(ctx, tx, Record{
		OccurredAt: future,
		TenantID:   tenantID, PrincipalID: analystID, ToolName: "warehouse.query",
		ScopesExercised: []string{"warehouse:read"},
		ProtocolVersion: "2026-07-28", Outcome: OutcomeOK, DurationMs: 1,
	}); err != nil {
		t.Fatalf("an insert four months out failed; the partition was not created on demand: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestEnsurePartitionsIsIdempotent(t *testing.T) {
	pool := appPool(t)
	w := NewWriter(pool)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := w.EnsurePartitions(ctx); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
}

// TestStoredArgumentsAreTheHashedArguments. Storing the raw form and hashing
// the canonical one would make every row verify as tampered — which is the
// mistake `json` vs `jsonb` also produces, from the other direction.
func TestStoredArgumentsAreTheHashedArguments(t *testing.T) {
	pool := appPool(t)
	w := NewWriter(pool)
	tenantID := tenant(t, pool)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately non-canonical: unsorted keys, irregular spacing.
	if _, err := w.Append(ctx, tx, Record{
		TenantID: tenantID, PrincipalID: analystID, ToolName: "warehouse.query",
		ScopesExercised:   []string{"warehouse:read"},
		ArgumentsRedacted: json.RawMessage(`{"zebra":1,   "alpha":2}`),
		ProtocolVersion:   "2026-07-28", Outcome: OutcomeOK, DurationMs: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	from, to := window()
	res, err := NewVerifier(pool).Verify(ctx, tenantID, from, to)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("a row with non-canonical arguments failed to verify: %s", res.Break)
	}
}
