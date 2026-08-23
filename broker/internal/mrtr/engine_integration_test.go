//go:build integration

package mrtr

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/patsypppe/sentinel/broker/internal/envelope"
	"github.com/patsypppe/sentinel/broker/internal/registry"
	"github.com/patsypppe/sentinel/broker/internal/store"
)

// Every test in the §8.5 table lives here, by the name the spec gives it.

const (
	demoTenant = "00000000-0000-0000-0000-000000000001"
	analystID  = "00000000-0000-0000-0000-0000000000a1"
	operatorID = "00000000-0000-0000-0000-0000000000a2"
	toolName   = "ops.deployment_apply"
)

func operator() registry.Principal {
	return registry.Principal{TenantID: demoTenant, ID: operatorID, Scopes: []string{"ops:apply"}}
}

func analyst() registry.Principal {
	return registry.Principal{TenantID: demoTenant, ID: analystID, Scopes: []string{"warehouse:read"}}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	migrateURL := envOr("BROKER_MIGRATE_DATABASE_URL",
		"postgres://sentinel:sentinel_dev_only@localhost:5432/sentinel?sslmode=disable")
	appURL := envOr("BROKER_DATABASE_URL",
		"postgres://broker_app:broker_app_dev_only@localhost:5432/sentinel?sslmode=disable")

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

func testEngine(t *testing.T, opts Options) (*Engine, *pgxpool.Pool) {
	t.Helper()
	if opts.FlowTTL == 0 {
		opts.FlowTTL = 5 * time.Minute
	}
	if opts.ReplayWindow == 0 {
		opts.ReplayWindow = 24 * time.Hour
	}

	pool := testPool(t)
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(pool, sealer, opts)
	if err != nil {
		t.Fatal(err)
	}
	return e, pool
}

func inputRequests() []envelope.InputRequest {
	return []envelope.InputRequest{{
		Name:        "confirm",
		Kind:        "boolean",
		Prompt:      "Apply this deployment plan? This cannot be undone.",
		Destructive: true,
	}}
}

// deployEffect is the real shape of the side effect: it records an ATTEMPT
// first, unconditionally, then performs the deployment.
//
// The attempt row is what TestDuplicateRetryIsIdempotent counts. Counting rows
// in `deployments` instead would be measuring the UNIQUE(correlation_id)
// constraint, which would hold the count at 1 even with a completely broken
// engine — and the test would report success while the property it names had
// been lost.
func deployEffect(ctx context.Context, tx pgx.Tx, correlationID string, args json.RawMessage) (json.RawMessage, error) {
	if _, err := tx.Exec(ctx,
		`INSERT INTO deployment_attempts (correlation_id) VALUES ($1)`, correlationID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO deployments (deployment_id, tenant_id, principal_id, plan, correlation_id)
		 VALUES ($1, $2, $3, $4, $5)`,
		uuid.New(), demoTenant, operatorID, args, correlationID); err != nil {
		return nil, err
	}
	return json.RawMessage(`{"deployed":true,"correlationId":"` + correlationID + `"}`), nil
}

func countAttempts(t *testing.T, pool *pgxpool.Pool, correlationID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM deployment_attempts WHERE correlation_id = $1`,
		correlationID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func countDeployments(t *testing.T, pool *pgxpool.Pool, correlationID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM deployments WHERE correlation_id = $1`, correlationID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func correlationOf(t *testing.T, e *Engine, requestState string) string {
	t.Helper()
	id, _, err := e.sealer.Unseal(requestState, toolName)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

const applyArgs = `{"plan":"hnd_PLAN123","force":false}`

// --- the happy path -------------------------------------------------------

func TestBeginThenResumeExecutesOnce(t *testing.T) {
	e, pool := testEngine(t, Options{})
	ctx := context.Background()

	rs, err := e.Begin(ctx, operator(), toolName, json.RawMessage(applyArgs), inputRequests())
	if err != nil {
		t.Fatal(err)
	}
	corr := correlationOf(t, e, rs)

	if n := countAttempts(t, pool, corr); n != 0 {
		t.Fatalf("Begin performed %d effects; opening a flow must not do anything", n)
	}

	out, err := e.Resume(ctx, operator(), rs, toolName, json.RawMessage(applyArgs), deployEffect)
	if err != nil {
		t.Fatal(err)
	}
	if out.Replayed {
		t.Fatal("the first retry must execute, not replay")
	}
	if n := countAttempts(t, pool, corr); n != 1 {
		t.Fatalf("the effect ran %d times, want 1", n)
	}
}

// --- the seven properties of §8.5 ----------------------------------------

// TestCorrelationIgnoresRequestID.
//
// The engine is never given a JSON-RPC id: correlation is via the sealed
// requestState alone. This test proves the API makes the mistake impossible by
// showing that the same sealed state resolves the flow no matter what — there is
// no id parameter to get wrong. §14 gotcha 4.
func TestCorrelationIgnoresRequestID(t *testing.T) {
	e, pool := testEngine(t, Options{})
	ctx := context.Background()

	rs, err := e.Begin(ctx, operator(), toolName, json.RawMessage(applyArgs), inputRequests())
	if err != nil {
		t.Fatal(err)
	}
	corr := correlationOf(t, e, rs)

	// A real client sends a new JSON-RPC id on every retry. The engine's
	// signature has no id in it at all, so nothing downstream can correlate on
	// one. Three "requests" with notionally different ids resolve identically.
	for i := 0; i < 3; i++ {
		if _, err := e.Resume(ctx, operator(), rs, toolName, json.RawMessage(applyArgs), deployEffect); err != nil {
			t.Fatalf("retry %d: %v", i, err)
		}
	}
	if n := countAttempts(t, pool, corr); n != 1 {
		t.Fatalf("the effect ran %d times across three retries, want 1", n)
	}
}

// TestTamperedRequestStateRejected at the engine level. state_test.go covers
// the seal exhaustively; this proves the engine actually consults it before
// touching the database.
func TestTamperedRequestStateRejectedByEngine(t *testing.T) {
	e, pool := testEngine(t, Options{})
	ctx := context.Background()

	rs, err := e.Begin(ctx, operator(), toolName, json.RawMessage(applyArgs), inputRequests())
	if err != nil {
		t.Fatal(err)
	}
	corr := correlationOf(t, e, rs)

	tampered := rs[:len(rs)-2] + "AA"
	if _, err := e.Resume(ctx, operator(), tampered, toolName, json.RawMessage(applyArgs), deployEffect); !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("err = %v, want ErrStateInvalid", err)
	}
	if n := countAttempts(t, pool, corr); n != 0 {
		t.Fatalf("a tampered state caused %d effects", n)
	}
}

// TestMutatedArgumentsRejected. The user approved a specific action; honouring
// a retry that changed the target would make the approval a lie.
func TestMutatedArgumentsRejected(t *testing.T) {
	e, pool := testEngine(t, Options{})
	ctx := context.Background()

	rs, err := e.Begin(ctx, operator(), toolName, json.RawMessage(applyArgs), inputRequests())
	if err != nil {
		t.Fatal(err)
	}
	corr := correlationOf(t, e, rs)

	mutated := `{"plan":"hnd_SOMETHING_ELSE","force":true}`
	_, err = e.Resume(ctx, operator(), rs, toolName, json.RawMessage(mutated), deployEffect)
	if !errors.Is(err, ErrArgumentsMutated) {
		t.Fatalf("err = %v, want ErrArgumentsMutated", err)
	}
	if n := countAttempts(t, pool, corr); n != 0 {
		t.Fatalf("a mutated retry caused %d effects", n)
	}

	// The flow is still usable with the ORIGINAL arguments: a rejected mutation
	// must not burn the approval, or a mistyped retry costs the user their
	// confirmation.
	if _, err := e.Resume(ctx, operator(), rs, toolName, json.RawMessage(applyArgs), deployEffect); err != nil {
		t.Fatalf("the original arguments were refused after a mutated retry: %v", err)
	}
}

// TestArgumentsReserializedIsNotAMutation. The complement: an honest client
// that re-serialized its arguments must not be treated as an attacker.
func TestArgumentsReserializedIsNotAMutation(t *testing.T) {
	e, _ := testEngine(t, Options{})
	ctx := context.Background()

	rs, err := e.Begin(ctx, operator(), toolName, json.RawMessage(applyArgs), inputRequests())
	if err != nil {
		t.Fatal(err)
	}

	// Same value, different bytes: reordered keys and added whitespace.
	reserialized := "{\n  \"force\" : false,\n  \"plan\": \"hnd_PLAN123\"\n}"
	if _, err := e.Resume(ctx, operator(), rs, toolName, json.RawMessage(reserialized), deployEffect); err != nil {
		t.Fatalf("re-serialized arguments were rejected as a mutation: %v", err)
	}
}

// TestCrossPrincipalRetryRejected. Possession of the sealed state is total: the
// other principal has the exact string, in the same tenant, inside the window.
func TestCrossPrincipalRetryRejected(t *testing.T) {
	e, pool := testEngine(t, Options{})
	ctx := context.Background()

	rs, err := e.Begin(ctx, operator(), toolName, json.RawMessage(applyArgs), inputRequests())
	if err != nil {
		t.Fatal(err)
	}
	corr := correlationOf(t, e, rs)

	_, err = e.Resume(ctx, analyst(), rs, toolName, json.RawMessage(applyArgs), deployEffect)
	if !errors.Is(err, ErrFlowNotFound) {
		t.Fatalf("err = %v, want ErrFlowNotFound: a leaked requestState must not let another "+
			"principal complete the flow", err)
	}
	if n := countAttempts(t, pool, corr); n != 0 {
		t.Fatalf("a cross-principal retry caused %d effects", n)
	}

	// And the owner can still complete it. A refused impersonation must not
	// consume the approval.
	if _, err := e.Resume(ctx, operator(), rs, toolName, json.RawMessage(applyArgs), deployEffect); err != nil {
		t.Fatalf("the owner could not complete the flow afterwards: %v", err)
	}
}

// TestDuplicateRetryIsIdempotent — the single hardest correctness property in
// the project (§2 rule 2).
//
// It asserts on a SIDE-EFFECT COUNTER, never on the response body. §8.5 is
// explicit about why: "The response looking right while the effect happened
// twice is the exact failure this test exists to catch."
//
// The counter is `deployment_attempts`, which has no uniqueness constraint.
// Counting `deployments` would measure the UNIQUE(correlation_id) backstop
// instead of the engine, and would stay at 1 even if the engine re-executed
// every time.
func TestDuplicateRetryIsIdempotent(t *testing.T) {
	e, pool := testEngine(t, Options{})
	ctx := context.Background()

	rs, err := e.Begin(ctx, operator(), toolName, json.RawMessage(applyArgs), inputRequests())
	if err != nil {
		t.Fatal(err)
	}
	corr := correlationOf(t, e, rs)

	first, err := e.Resume(ctx, operator(), rs, toolName, json.RawMessage(applyArgs), deployEffect)
	if err != nil {
		t.Fatal(err)
	}
	if first.Replayed {
		t.Fatal("the first retry must execute")
	}

	// Ten identical duplicate retries, as a flaky client would send.
	for i := 0; i < 10; i++ {
		again, err := e.Resume(ctx, operator(), rs, toolName, json.RawMessage(applyArgs), deployEffect)
		if err != nil {
			t.Fatalf("duplicate retry %d failed: %v", i, err)
		}
		if !again.Replayed {
			t.Fatalf("duplicate retry %d executed instead of replaying", i)
		}
		if string(again.Result) != string(first.Result) {
			t.Fatalf("duplicate retry %d returned a different result:\n %s\n %s",
				i, first.Result, again.Result)
		}
	}

	// THE assertion.
	if n := countAttempts(t, pool, corr); n != 1 {
		t.Fatalf("the effect ran %d times across eleven retries, want exactly 1", n)
	}
	if n := countDeployments(t, pool, corr); n != 1 {
		t.Fatalf("%d deployments exist, want exactly 1", n)
	}
}

// TestConcurrentDuplicateRetriesExecuteOnce. Duplicates do not politely arrive
// in sequence. Without SELECT ... FOR UPDATE both would read
// status='awaiting_input', both would pass their checks, and both would execute.
func TestConcurrentDuplicateRetriesExecuteOnce(t *testing.T) {
	e, pool := testEngine(t, Options{})
	ctx := context.Background()

	rs, err := e.Begin(ctx, operator(), toolName, json.RawMessage(applyArgs), inputRequests())
	if err != nil {
		t.Fatal(err)
	}
	corr := correlationOf(t, e, rs)

	const concurrency = 8
	errs := make(chan error, concurrency)
	start := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		go func() {
			<-start
			_, err := e.Resume(ctx, operator(), rs, toolName, json.RawMessage(applyArgs), deployEffect)
			errs <- err
		}()
	}
	close(start)

	for i := 0; i < concurrency; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent retry failed: %v", err)
		}
	}

	if n := countAttempts(t, pool, corr); n != 1 {
		t.Fatalf("the effect ran %d times across %d concurrent retries, want exactly 1; "+
			"the row lock is not serializing them", n, concurrency)
	}
}

// TestExpiredFlowRejected. flow_ttl bounds how long a flow may sit AWAITING
// input.
func TestExpiredFlowRejected(t *testing.T) {
	e, pool := testEngine(t, Options{FlowTTL: time.Minute, ReplayWindow: time.Hour})
	ctx := context.Background()

	// Open the flow with the clock rolled back, so it is already stale.
	past := e.WithClock(func() time.Time { return time.Now().Add(-10 * time.Minute) })
	rs, err := past.Begin(ctx, operator(), toolName, json.RawMessage(applyArgs), inputRequests())
	if err != nil {
		t.Fatal(err)
	}
	corr := correlationOf(t, past, rs)

	_, err = e.Resume(ctx, operator(), rs, toolName, json.RawMessage(applyArgs), deployEffect)
	if !errors.Is(err, ErrStateExpired) && !errors.Is(err, ErrFlowExpired) {
		t.Fatalf("err = %v, want an expiry error", err)
	}
	if n := countAttempts(t, pool, corr); n != 0 {
		t.Fatalf("an expired flow caused %d effects", n)
	}

	// The wire error must tell the client to start again.
	wire := RPCError(err)
	if wire.Code != envelope.CodeMRTRFlowExpired {
		t.Fatalf("wire code = %d, want %d", wire.Code, envelope.CodeMRTRFlowExpired)
	}
}

// TestReplayWindowExpiry. Past the replay window, a duplicate retry gets a
// clear "no longer available" — NEVER a re-execution.
func TestReplayWindowExpiry(t *testing.T) {
	e, pool := testEngine(t, Options{FlowTTL: time.Minute, ReplayWindow: 2 * time.Minute})
	ctx := context.Background()

	// Consume the flow ten minutes ago, so both its TTL and its replay window
	// have passed by now.
	past := e.WithClock(func() time.Time { return time.Now().Add(-10 * time.Minute) })
	rs, err := past.Begin(ctx, operator(), toolName, json.RawMessage(applyArgs), inputRequests())
	if err != nil {
		t.Fatal(err)
	}
	corr := correlationOf(t, past, rs)

	if _, err := past.Resume(ctx, operator(), rs, toolName, json.RawMessage(applyArgs), deployEffect); err != nil {
		t.Fatal(err)
	}
	if n := countAttempts(t, pool, corr); n != 1 {
		t.Fatalf("setup: the effect ran %d times, want 1", n)
	}

	// Now, with the real clock. The sealed state's own expiry has passed too,
	// which is the honest case: a client retrying this late gets an expiry error
	// and, critically, no second deployment.
	_, err = e.Resume(ctx, operator(), rs, toolName, json.RawMessage(applyArgs), deployEffect)
	if err == nil {
		t.Fatal("a retry long after the replay window must be refused")
	}
	if n := countAttempts(t, pool, corr); n != 1 {
		t.Fatalf("a late retry caused a re-execution: the effect ran %d times, want 1", n)
	}
}

// TestReplayWindowClosedIsNotAReExecution isolates the window itself, with a
// sealed state that is still valid. This is the case ErrReplayWindowClosed
// exists for: the client's state is fine, the result has simply aged out.
func TestReplayWindowClosedIsNotAReExecution(t *testing.T) {
	e, pool := testEngine(t, Options{FlowTTL: time.Minute, ReplayWindow: time.Minute})
	ctx := context.Background()

	// The seal's expiry is left in the future so unsealing succeeds; only the
	// FLOW's replay window is forced closed below. That isolates the window
	// itself from state expiry, which TestReplayWindowExpiry already covers.
	rs, err := e.Begin(ctx, operator(), toolName, json.RawMessage(applyArgs), inputRequests())
	if err != nil {
		t.Fatal(err)
	}
	corr := correlationOf(t, e, rs)

	if _, err := e.Resume(ctx, operator(), rs, toolName, json.RawMessage(applyArgs), deployEffect); err != nil {
		t.Fatal(err)
	}

	// Force the recorded result past its window without moving the seal's clock.
	if _, err := pool.Exec(ctx,
		`UPDATE mrtr_flows SET replay_until = now() - interval '1 minute' WHERE correlation_id = $1`,
		corr); err != nil {
		t.Fatal(err)
	}

	_, err = e.Resume(ctx, operator(), rs, toolName, json.RawMessage(applyArgs), deployEffect)
	if !errors.Is(err, ErrReplayWindowClosed) {
		t.Fatalf("err = %v, want ErrReplayWindowClosed", err)
	}
	if n := countAttempts(t, pool, corr); n != 1 {
		t.Fatalf("a retry past the replay window re-executed: %d attempts, want 1", n)
	}

	// The wire message must make clear the action did NOT happen again.
	wire := RPCError(err)
	if wire.Code != envelope.CodeMRTRResultNoLongerAvailable {
		t.Fatalf("wire code = %d, want %d", wire.Code, envelope.CodeMRTRResultNoLongerAvailable)
	}
	if !contains(wire.Message, "NOT") {
		t.Fatalf("the message must say the action was not performed again: %q", wire.Message)
	}
}

// TestEffectFailureLeavesTheFlowRetryable. If the effect errors, the
// transaction rolls back, so the flow stays awaiting input and nothing was
// recorded — a transient failure must not burn the approval.
func TestEffectFailureLeavesTheFlowRetryable(t *testing.T) {
	e, pool := testEngine(t, Options{})
	ctx := context.Background()

	rs, err := e.Begin(ctx, operator(), toolName, json.RawMessage(applyArgs), inputRequests())
	if err != nil {
		t.Fatal(err)
	}
	corr := correlationOf(t, e, rs)

	failing := func(ctx context.Context, tx pgx.Tx, id string, args json.RawMessage) (json.RawMessage, error) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO deployment_attempts (correlation_id) VALUES ($1)`, id); err != nil {
			return nil, err
		}
		return nil, errors.New("the deployment target was unreachable")
	}

	if _, err := e.Resume(ctx, operator(), rs, toolName, json.RawMessage(applyArgs), failing); err == nil {
		t.Fatal("a failing effect must surface its error")
	}
	// The attempt row rolled back with everything else.
	if n := countAttempts(t, pool, corr); n != 0 {
		t.Fatalf("a failed effect left %d attempt rows behind; the transaction did not roll back", n)
	}

	// And the flow is still completable.
	out, err := e.Resume(ctx, operator(), rs, toolName, json.RawMessage(applyArgs), deployEffect)
	if err != nil {
		t.Fatalf("the flow was not retryable after a transient failure: %v", err)
	}
	if out.Replayed {
		t.Fatal("the retry replayed a result that was never recorded")
	}
	if n := countAttempts(t, pool, corr); n != 1 {
		t.Fatalf("the effect ran %d times, want 1", n)
	}
}

// TestEffectWithNoResultIsRefused. A consumed flow with no recorded result
// would re-execute on the next retry, so that state must be unreachable.
func TestEffectWithNoResultIsRefused(t *testing.T) {
	e, _ := testEngine(t, Options{})
	ctx := context.Background()

	rs, err := e.Begin(ctx, operator(), toolName, json.RawMessage(applyArgs), inputRequests())
	if err != nil {
		t.Fatal(err)
	}

	silent := func(context.Context, pgx.Tx, string, json.RawMessage) (json.RawMessage, error) {
		return nil, nil
	}
	if _, err := e.Resume(ctx, operator(), rs, toolName, json.RawMessage(applyArgs), silent); err == nil {
		t.Fatal("an effect that records no result must be refused")
	}
}

func TestBeginRequiresAnInputRequest(t *testing.T) {
	e, _ := testEngine(t, Options{})
	if _, err := e.Begin(context.Background(), operator(), toolName,
		json.RawMessage(applyArgs), nil); err == nil {
		t.Fatal("a flow with no input requests gives the client nothing to respond to")
	}
}

func TestEngineRefusesAReplayWindowShorterThanTheFlowTTL(t *testing.T) {
	pool := testPool(t)
	key, _ := NewKey()
	sealer, _ := NewSealer(key)

	_, err := NewEngine(pool, sealer, Options{FlowTTL: time.Hour, ReplayWindow: time.Minute})
	if err == nil {
		t.Fatal("a replay window shorter than the flow TTL re-opens the exactly-once hole " +
			"it exists to close and must be refused at construction")
	}
}

func TestSweepMarksAbandonedFlows(t *testing.T) {
	e, pool := testEngine(t, Options{FlowTTL: time.Minute, ReplayWindow: time.Hour})
	ctx := context.Background()

	past := e.WithClock(func() time.Time { return time.Now().Add(-time.Hour) })
	rs, err := past.Begin(ctx, operator(), toolName, json.RawMessage(applyArgs), inputRequests())
	if err != nil {
		t.Fatal(err)
	}
	corr := correlationOf(t, past, rs)

	if _, err := e.Sweep(ctx); err != nil {
		t.Fatal(err)
	}

	var status string
	if err := pool.QueryRow(ctx,
		`SELECT status FROM mrtr_flows WHERE correlation_id = $1`, corr).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != StatusExpired {
		t.Fatalf("status = %q after sweep, want %q", status, StatusExpired)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestRecordedResultIsReplayedVerbatim.
//
// §8.5 asks for the recorded result "verbatim", and that word rules out a
// storage type this table would otherwise reach for. `jsonb` is a parsed
// representation: it re-emits with its own spacing, sorts object keys and drops
// duplicates, so a replay returns the same VALUE with different BYTES. A client
// that hashes or signs a response, or simply diffs two retries, would see them
// disagree.
//
// The result used here is deliberately non-canonical — unsorted keys, irregular
// spacing — because a canonical one would pass under either column type and
// this test would prove nothing.
func TestRecordedResultIsReplayedVerbatim(t *testing.T) {
	e, _ := testEngine(t, Options{})
	ctx := context.Background()

	const awkward = `{"zebra":1,   "alpha":2,"nested":{"z":[3,   2, 1],"a":null}}`

	rs, err := e.Begin(ctx, operator(), toolName, json.RawMessage(applyArgs), inputRequests())
	if err != nil {
		t.Fatal(err)
	}

	effect := func(ctx context.Context, tx pgx.Tx, id string, _ json.RawMessage) (json.RawMessage, error) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO deployment_attempts (correlation_id) VALUES ($1)`, id); err != nil {
			return nil, err
		}
		return json.RawMessage(awkward), nil
	}

	first, err := e.Resume(ctx, operator(), rs, toolName, json.RawMessage(applyArgs), effect)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Result) != awkward {
		t.Fatalf("the freshly executed result was altered on the way out:\n got  %s\n want %s",
			first.Result, awkward)
	}

	replayed, err := e.Resume(ctx, operator(), rs, toolName, json.RawMessage(applyArgs), effect)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Replayed {
		t.Fatal("the second retry executed instead of replaying")
	}
	if string(replayed.Result) != awkward {
		t.Fatalf("the replay is not byte-identical to what was recorded — the storage type is "+
			"normalizing it (jsonb rather than json?):\n got  %s\n want %s",
			replayed.Result, awkward)
	}
}
