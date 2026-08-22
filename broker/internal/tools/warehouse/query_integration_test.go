//go:build integration

package warehouse

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/patsypppe/sentinel/broker/internal/envelope"
	"github.com/patsypppe/sentinel/broker/internal/registry"
	"github.com/patsypppe/sentinel/broker/internal/store"
)

// These tests run against a real Postgres because the SQL guard's whole design
// is to use Postgres's own planner. A guard tested against a mocked planner
// would be testing the mock, which is exactly the gap the design exists to
// close.
//
//	make up && make test-go-integration

const (
	analystPrincipal  = "00000000-0000-0000-0000-0000000000a1"
	operatorPrincipal = "00000000-0000-0000-0000-0000000000a2"
	demoTenant        = "00000000-0000-0000-0000-000000000001"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	appURL := envOr("BROKER_DATABASE_URL",
		"postgres://broker_app:broker_app_dev_only@localhost:5432/sentinel?sslmode=disable")
	migrateURL := envOr("BROKER_MIGRATE_DATABASE_URL",
		"postgres://sentinel:sentinel_dev_only@localhost:5432/sentinel?sslmode=disable")

	ctx := context.Background()
	if _, err := store.Migrate(ctx, migrateURL); err != nil {
		t.Skipf("postgres is not reachable (run `make up`): %v", err)
	}

	s, err := store.Open(ctx, appURL)
	if err != nil {
		t.Skipf("postgres is not reachable (run `make up`): %v", err)
	}
	t.Cleanup(s.Close)
	return s.Pool()
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func analyst() registry.Principal {
	return registry.Principal{
		TenantID: demoTenant,
		ID:       analystPrincipal,
		Scopes:   []string{"warehouse:read", "warehouse:describe"},
	}
}

// recordingMinter stands in for the real handle store (WP-5) and records what
// it was asked to mint, so the overflow path can be asserted on directly.
type recordingMinter struct {
	calls   int
	kind    string
	payload json.RawMessage
}

func (m *recordingMinter) Mint(_ context.Context, _ registry.Principal, kind string,
	payload json.RawMessage, _ time.Duration) (string, error) {
	m.calls++
	m.kind = kind
	m.payload = payload
	return "hnd_TESTHANDLE", nil
}

func newTool(t *testing.T, minter Minter, opts QueryOptions) *QueryTool {
	t.Helper()
	return NewQueryTool(testPool(t), minter, opts)
}

func callQuery(t *testing.T, tool *QueryTool, p registry.Principal, args string) (registry.Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return tool.Call(ctx, p, json.RawMessage(args))
}

func TestQueryReadsPermittedRelations(t *testing.T) {
	tool := newTool(t, &recordingMinter{}, QueryOptions{RowCap: 10})

	res, err := callQuery(t, tool, analyst(),
		`{"sql":"SELECT order_id, status FROM warehouse.orders ORDER BY order_id LIMIT 5"}`)
	if err != nil {
		t.Fatalf("a permitted query was refused: %v", err)
	}

	var rows Rows
	if err := json.Unmarshal(res.StructuredContent, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows.Rows) != 5 {
		t.Fatalf("got %d rows, want 5", len(rows.Rows))
	}
	if len(rows.Columns) != 2 || rows.Columns[0] != "order_id" {
		t.Fatalf("columns = %v, want [order_id status]", rows.Columns)
	}
}

// TestOutOfScopeTableRejected is the point of the whole guard, and it exercises
// BOTH layers separately.
//
// warehouse.internal_notes is readable by broker_app but conferred by no demo
// scope, so the SCOPE ALLOWLIST is what refuses it — if the allowlist were
// broken, this row would pass. warehouse_restricted.payroll is not readable by
// broker_app at all, so POSTGRES refuses it first and the error is translated
// into the same actionable shape. A test that only covered the second case
// would report a working guard even with the allowlist deleted.
func TestOutOfScopeTableRejected(t *testing.T) {
	tool := newTool(t, &recordingMinter{}, QueryOptions{})

	cases := []struct {
		desc      string
		sql       string
		refusedBy string
		wantNamed string
	}{
		{
			desc:      "readable by the role, conferred by no scope",
			sql:       `{"sql":"SELECT note_id, body FROM warehouse.internal_notes"}`,
			refusedBy: "the scope allowlist",
			wantNamed: "warehouse.internal_notes",
		},
		{
			desc:      "not readable by the role at all",
			sql:       `{"sql":"SELECT full_name, annual_cents FROM warehouse_restricted.payroll"}`,
			refusedBy: "the database grant",
			wantNamed: "", // Postgres refused before the plan could name it.
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			_, err := callQuery(t, tool, analyst(), c.sql)
			if err == nil {
				t.Fatalf("a query refused by %s was permitted", c.refusedBy)
			}
			var denied *ErrRelationDenied
			if !errors.As(err, &denied) {
				t.Fatalf("err = %T (%v), want *ErrRelationDenied so the caller is told what "+
					"they COULD read", err, err)
			}
			if c.wantNamed != "" && denied.Relation != c.wantNamed {
				t.Fatalf("error names %q, want %q", denied.Relation, c.wantNamed)
			}
			if !contains(denied.Error(), "warehouse.orders") {
				t.Fatalf("error %q must list what is readable", denied.Error())
			}
		})
	}
}

// TestDeniedRelationHiddenInSubqueryIsStillRejected. This is what a real
// parser buys over string inspection, and what asking Postgres itself buys over
// a vendored parser: the denied table is not mentioned in a FROM clause the eye
// would scan first, and it still cannot get through.
func TestDeniedRelationHiddenInSubqueryIsStillRejected(t *testing.T) {
	tool := newTool(t, &recordingMinter{}, QueryOptions{})

	queries := []string{
		`{"sql":"SELECT o.order_id FROM warehouse.orders o WHERE o.total_cents > (SELECT max(annual_cents) FROM warehouse_restricted.payroll)"}`,
		`{"sql":"WITH leak AS (SELECT full_name FROM warehouse_restricted.payroll) SELECT * FROM leak"}`,
		`{"sql":"SELECT order_id FROM warehouse.orders UNION ALL SELECT employee_id FROM warehouse_restricted.payroll"}`,
	}
	for _, q := range queries {
		if _, err := callQuery(t, tool, analyst(), q); err == nil {
			t.Errorf("a denied relation reached through a subquery/CTE/union was permitted: %s", q)
		}
	}
}

// TestWritesAreRejectedByPostgresItself. Layer 1: the read-only transaction
// means DML never reaches the allowlist check at all.
func TestWritesAreRejectedByPostgresItself(t *testing.T) {
	tool := newTool(t, &recordingMinter{}, QueryOptions{})

	for _, q := range []string{
		`{"sql":"UPDATE warehouse.orders SET status = 'refunded'"}`,
		`{"sql":"DELETE FROM warehouse.orders"}`,
		`{"sql":"INSERT INTO warehouse.orders (order_id, customer_id, status, total_cents, placed_at) VALUES (999999, 1, 'x', 1, now())"}`,
		`{"sql":"DROP TABLE warehouse.orders"}`,
	} {
		if _, err := callQuery(t, tool, analyst(), q); err == nil {
			t.Errorf("a write was permitted: %s", q)
		}
	}
}

// TestUnqualifiedTableIsRejectedWithAnActionableError. The empty search_path
// removes the ambiguity; the error has to explain that, or it reads as "the
// table does not exist" when the table plainly does.
func TestUnqualifiedTableIsRejectedWithAnActionableError(t *testing.T) {
	tool := newTool(t, &recordingMinter{}, QueryOptions{})

	_, err := callQuery(t, tool, analyst(), `{"sql":"SELECT order_id FROM orders"}`)
	if err == nil {
		t.Fatal("an unqualified table name must be refused: the search path is empty")
	}
	if !contains(err.Error(), "schema-qualified") {
		t.Fatalf("error %q must explain the empty search path and show what would work", err)
	}
}

// TestStatementTimeoutCancelsServerSide.
func TestStatementTimeoutCancelsServerSide(t *testing.T) {
	tool := newTool(t, &recordingMinter{}, QueryOptions{StatementTimeout: 100 * time.Millisecond})

	// A self-join over 5,000 rows with no usable predicate takes far longer than
	// 100ms and is cancelled by Postgres, not by the Go context — which is the
	// point: the cap is enforced server-side, so a client that ignores its own
	// timeout still cannot pin a backend.
	_, err := callQuery(t, tool, analyst(),
		`{"sql":"SELECT count(*) FROM warehouse.orders a, warehouse.orders b, warehouse.orders c"}`)
	if err == nil {
		t.Fatal("a query exceeding the statement timeout must be cancelled")
	}
	if !contains(err.Error(), "timeout") && !contains(err.Error(), "cancel") {
		t.Fatalf("error %q should identify the timeout", err)
	}
}

// TestOverCapReturnsHandlePlusSummary. §8.4: exceeding the token cap does not
// truncate silently.
func TestOverCapReturnsHandlePlusSummary(t *testing.T) {
	minter := &recordingMinter{}
	tool := newTool(t, minter, QueryOptions{TokenCap: 200, RowCap: 500})

	res, err := callQuery(t, tool, analyst(),
		`{"sql":"SELECT order_id, customer_id, status, total_cents FROM warehouse.orders ORDER BY order_id"}`)
	if err != nil {
		t.Fatalf("the over-cap path must succeed with a handle, not fail: %v", err)
	}

	if minter.calls != 1 {
		t.Fatalf("minted %d handles, want exactly 1", minter.calls)
	}
	if minter.kind != HandleKindQueryResult {
		t.Fatalf("handle kind = %q, want %q", minter.kind, HandleKindQueryResult)
	}

	// The full result is what got stored, not the sample.
	var stored Rows
	if err := json.Unmarshal(minter.payload, &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored.Rows) != 500 {
		t.Fatalf("the handle holds %d rows, want the full capped result of 500", len(stored.Rows))
	}

	// The response inlines a sample and says so.
	var sample Rows
	if err := json.Unmarshal(res.StructuredContent, &sample); err != nil {
		t.Fatal(err)
	}
	if len(sample.Rows) != inlineSampleRows {
		t.Fatalf("inlined %d rows, want %d", len(sample.Rows), inlineSampleRows)
	}
	if len(res.Content) == 0 || !contains(res.Content[0].Text, "hnd_TESTHANDLE") {
		t.Fatalf("the response must name the handle: %+v", res.Content)
	}
	if !contains(res.Content[0].Text, "500") {
		t.Fatalf("the summary must state the full row count: %q", res.Content[0].Text)
	}
}

// TestRowCapIsEnforcedAndTruncationIsReported.
func TestRowCapIsEnforcedAndTruncationIsReported(t *testing.T) {
	minter := &recordingMinter{}
	tool := newTool(t, minter, QueryOptions{RowCap: 10, TokenCap: 1_000_000})

	res, err := callQuery(t, tool, analyst(),
		`{"sql":"SELECT order_id FROM warehouse.orders ORDER BY order_id"}`)
	if err != nil {
		t.Fatal(err)
	}
	// Truncation always takes the handle path, even under the token cap: a
	// caller must never receive a silently short answer.
	if minter.calls != 1 {
		t.Fatalf("a truncated result minted %d handles, want 1: truncation must never be silent",
			minter.calls)
	}
	var stored Rows
	if err := json.Unmarshal(minter.payload, &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored.Rows) != 10 {
		t.Fatalf("stored %d rows, want the row cap of 10", len(stored.Rows))
	}
	if len(res.Content) == 0 {
		t.Fatal("a truncated result must carry a summary")
	}
}

func TestDescribeListsOnlyPermittedTables(t *testing.T) {
	tool := NewDescribeTool(testPool(t))

	ctx := context.Background()
	res, err := tool.Call(ctx, analyst(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}

	var out describeResult
	if err := json.Unmarshal(res.StructuredContent, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Tables) != 2 {
		t.Fatalf("described %d tables, want 2 (customers, orders)", len(out.Tables))
	}
	for _, tbl := range out.Tables {
		if contains(tbl.Name, "payroll") {
			t.Fatalf("described a table outside the principal's scopes: %s", tbl.Name)
		}
		if len(tbl.Columns) == 0 {
			t.Errorf("%s was described with no columns", tbl.Name)
		}
	}
}

// TestDescribeRefusesAnUnpermittedTableTheSameWayAsAMissingOne. Distinguishing
// them would turn the schema endpoint into an enumeration oracle.
//
// The property is NOT that the two error strings are byte-identical: each echoes
// back the relation the CALLER asked for, and echoing a caller's own input
// reveals nothing they did not already know. The property is that the message
// TEMPLATE is identical — that nothing beyond the echoed name differs, so there
// is no signal to read.
func TestDescribeRefusesAnUnpermittedTableTheSameWayAsAMissingOne(t *testing.T) {
	tool := NewDescribeTool(testPool(t))
	ctx := context.Background()

	const denied = "warehouse.internal_notes" // exists, not conferred by any demo scope
	const missing = "warehouse.no_such_table" // does not exist at all

	_, existsButDenied := tool.Call(ctx, analyst(),
		json.RawMessage(`{"table":"`+denied+`"}`))
	_, doesNotExist := tool.Call(ctx, analyst(),
		json.RawMessage(`{"table":"`+missing+`"}`))

	if existsButDenied == nil || doesNotExist == nil {
		t.Fatal("both a denied table and a missing one must be refused")
	}

	// Strip each caller-supplied name and compare what remains.
	a := strings.Replace(existsButDenied.Error(), denied, "<relation>", 1)
	b := strings.Replace(doesNotExist.Error(), missing, "<relation>", 1)
	if a != b {
		t.Fatalf("beyond the echoed relation name, the two refusals differ, which tells the "+
			"caller whether the table exists:\n denied:  %s\n missing: %s", a, b)
	}

	// And both must be the same Go type, so a client switching on the error
	// cannot distinguish them either.
	var deniedErr, missingErr *ErrRelationDenied
	if !errors.As(existsButDenied, &deniedErr) {
		t.Fatalf("denied error is %T", existsButDenied)
	}
	if !errors.As(doesNotExist, &missingErr) {
		t.Fatalf("missing error is %T", doesNotExist)
	}
}

func TestDescribeAndQueryAgreeOnWhatIsReadable(t *testing.T) {
	pool := testPool(t)
	describe := NewDescribeTool(pool)
	query := NewQueryTool(pool, &recordingMinter{}, QueryOptions{RowCap: 1})
	ctx := context.Background()

	res, err := describe.Call(ctx, analyst(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	var out describeResult
	if err := json.Unmarshal(res.StructuredContent, &out); err != nil {
		t.Fatal(err)
	}

	// Everything describe advertises must actually be queryable. If the two
	// diverge, describe becomes a list of false promises.
	for _, tbl := range out.Tables {
		args := `{"sql":"SELECT * FROM ` + tbl.Name + ` LIMIT 1"}`
		if _, err := query.Call(ctx, analyst(), json.RawMessage(args)); err != nil {
			t.Errorf("describe advertised %s but query refused it: %v", tbl.Name, err)
		}
	}
}

var _ = envelope.ResultComplete // keep the envelope import meaningful across edits
