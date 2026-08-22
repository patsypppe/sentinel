//go:build integration

package handles

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

const (
	demoTenant = "00000000-0000-0000-0000-000000000001"
	analystID  = "00000000-0000-0000-0000-0000000000a1"
	operatorID = "00000000-0000-0000-0000-0000000000a2"
)

func analyst() registry.Principal {
	return registry.Principal{TenantID: demoTenant, ID: analystID, Scopes: []string{"warehouse:read"}}
}

// operator is a DIFFERENT principal in the SAME tenant. That combination is
// what makes the cross-principal tests meaningful: a different tenant would be
// refused by the tenant predicate alone, and the binding check would never be
// exercised.
func operator() registry.Principal {
	return registry.Principal{TenantID: demoTenant, ID: operatorID, Scopes: []string{"ops:apply"}}
}

func testStore(t *testing.T) *Store {
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
	return NewStore(s.Pool())
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func mintFor(t *testing.T, s *Store, p registry.Principal) string {
	t.Helper()
	id, err := s.Mint(context.Background(), p, KindQueryResult,
		json.RawMessage(`{"rows":[[1,2,3]]}`), 5*time.Minute)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return id
}

func TestMintedHandleResolvesForItsOwner(t *testing.T) {
	s := testStore(t)
	id := mintFor(t, s, analyst())

	payload, err := s.Resolve(context.Background(), analyst(), id)
	if err != nil {
		t.Fatalf("the minting principal could not resolve its own handle: %v", err)
	}
	if len(payload) == 0 {
		t.Fatal("resolution returned an empty payload")
	}
}

// TestCrossPrincipalHandleRefused — one of the nine negative tests of §11.
//
// Possession of the identifier is total here: the other principal has the exact
// string, in the same tenant, before it expires. It still does not resolve,
// because possession is not authentication.
func TestCrossPrincipalHandleRefused(t *testing.T) {
	s := testStore(t)
	leaked := mintFor(t, s, analyst())

	_, err := s.Resolve(context.Background(), operator(), leaked)
	if !errors.Is(err, ErrNotResolvable) {
		t.Fatalf("a leaked handle resolved for a different principal (err = %v); possession "+
			"of a handle is not authentication", err)
	}
}

// TestNonexistentAndUnauthorizedAreIndistinguishable — the enumeration-oracle
// defence, and the second of the nine.
//
// The property is exact: identical error VALUE and identical message. Anything
// that differs between the two branches — a code, a word, a latency class — is
// a bit an attacker can read, and reading one bit per guess is how a handle
// space gets mapped.
func TestNonexistentAndUnauthorizedAreIndistinguishable(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Exists, belongs to someone else.
	notYours := mintFor(t, s, analyst())
	_, unauthorized := s.Resolve(ctx, operator(), notYours)

	// Never existed. Same shape, so nothing about the STRING distinguishes it.
	neverExisted, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	_, nonexistent := s.Resolve(ctx, operator(), neverExisted)

	if unauthorized == nil || nonexistent == nil {
		t.Fatal("both cases must be refused")
	}
	if !errors.Is(unauthorized, ErrNotResolvable) || !errors.Is(nonexistent, ErrNotResolvable) {
		t.Fatalf("both must be ErrNotResolvable; got %v and %v", unauthorized, nonexistent)
	}
	if unauthorized.Error() != nonexistent.Error() {
		t.Fatalf("the two refusals differ, which confirms existence:\n not yours: %q\n no such:   %q",
			unauthorized.Error(), nonexistent.Error())
	}

	// And on the wire, where the client actually reads it. The rendered error
	// must be constant: same code, same message, and no data field at all,
	// because anything that varies between the two branches is a signal.
	wire := RPCError()
	if wire.Code != envelope.CodeHandleNotResolvable {
		t.Fatalf("wire code = %d, want %d", wire.Code, envelope.CodeHandleNotResolvable)
	}
	if wire.Data != nil {
		t.Fatalf("the wire error carries a data field (%v); anything in it is a signal", wire.Data)
	}
	if again := RPCError(); again.Message != wire.Message {
		t.Fatal("the wire message varies between calls")
	}
	for _, leak := range []string{"expired", "revoked", "not yours", "does not exist"} {
		if !strings.Contains(wire.Message, leak) {
			t.Fatalf("the message must list ALL the causes (%q missing) so that naming one "+
				"cannot single it out: %q", leak, wire.Message)
		}
	}
}

// TestExpiredHandleRefused. Expiry is evaluated by the DATABASE (expires_at >
// now()), so a skewed application clock cannot extend a handle's life.
func TestExpiredHandleRefused(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Mint with the clock rolled back so the row is already expired on arrival.
	past := s.WithClock(func() time.Time { return time.Now().Add(-2 * time.Hour) })
	id, err := past.Mint(ctx, analyst(), KindQueryResult, json.RawMessage(`{}`), time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.Resolve(ctx, analyst(), id); !errors.Is(err, ErrNotResolvable) {
		t.Fatalf("an expired handle resolved (err = %v)", err)
	}
}

func TestRevokedHandleRefusedImmediately(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	id := mintFor(t, s, analyst())
	if _, err := s.Resolve(ctx, analyst(), id); err != nil {
		t.Fatalf("precondition: the handle should resolve before revocation: %v", err)
	}

	if err := s.Revoke(ctx, analyst(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resolve(ctx, analyst(), id); !errors.Is(err, ErrNotResolvable) {
		t.Fatalf("a revoked handle still resolved (err = %v); revocation takes effect "+
			"immediately, not at expiry", err)
	}
}

// TestRevokeIsScopedToTheOwner. Revoking someone else's handle would be a
// denial-of-service primitive handed to anyone who saw an identifier.
func TestRevokeIsScopedToTheOwner(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	id := mintFor(t, s, analyst())

	if err := s.Revoke(ctx, operator(), id); err != nil {
		t.Fatalf("revoking another principal's handle must be a silent no-op, not an error "+
			"(an error would confirm the handle exists): %v", err)
	}
	if _, err := s.Resolve(ctx, analyst(), id); err != nil {
		t.Fatalf("another principal's revoke took effect: %v", err)
	}
}

// TestResolutionRechecksEveryTime. §5's pitfall: caching a resolved handle in
// memory and skipping the re-check on the second use.
//
// The shape of this test matters. It resolves successfully, revokes, then
// resolves again — a cache would return the payload from the first call and the
// test would fail. A test that resolved each handle only once could not see the
// difference.
func TestResolutionRechecksEveryTime(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	id := mintFor(t, s, analyst())
	for i := 0; i < 3; i++ {
		if _, err := s.Resolve(ctx, analyst(), id); err != nil {
			t.Fatalf("resolution %d failed: %v", i, err)
		}
	}

	if err := s.Revoke(ctx, analyst(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resolve(ctx, analyst(), id); !errors.Is(err, ErrNotResolvable) {
		t.Fatal("a handle resolved after revocation, which means a previous resolution was " +
			"cached and the principal check was skipped")
	}
}

// TestWrongKindIsIndistinguishable. A caller must not learn that a handle
// exists but is of another kind.
func TestWrongKindIsIndistinguishable(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	id := mintFor(t, s, analyst()) // KindQueryResult

	var into map[string]any
	wrongKind := s.ResolveTyped(ctx, analyst(), id, KindDeploymentPlan, &into)

	missing, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	noSuchHandle := s.ResolveTyped(ctx, analyst(), missing, KindDeploymentPlan, &into)

	if !errors.Is(wrongKind, ErrNotResolvable) || !errors.Is(noSuchHandle, ErrNotResolvable) {
		t.Fatalf("both must be ErrNotResolvable; got %v and %v", wrongKind, noSuchHandle)
	}
	if wrongKind.Error() != noSuchHandle.Error() {
		t.Fatalf("a wrong-kind handle is distinguishable from a missing one:\n %q\n %q",
			wrongKind.Error(), noSuchHandle.Error())
	}
}

func TestResolveTypedDecodesThePayload(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	type plan struct {
		Steps []string `json:"steps"`
	}
	id, err := s.Mint(ctx, analyst(), KindDeploymentPlan,
		json.RawMessage(`{"steps":["migrate","restart"]}`), time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	var got plan
	if err := s.ResolveTyped(ctx, analyst(), id, KindDeploymentPlan, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Steps) != 2 || got.Steps[0] != "migrate" {
		t.Fatalf("payload = %+v", got)
	}
}

// TestGCRemovesExpired, and — the part worth asserting — leaves live handles
// alone.
func TestGCRemovesExpired(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	live := mintFor(t, s, analyst())

	past := s.WithClock(func() time.Time { return time.Now().Add(-48 * time.Hour) })
	dead, err := past.Mint(ctx, analyst(), KindQueryResult, json.RawMessage(`{}`), time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.Collect(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}

	if exists(t, s.pool, dead) {
		t.Error("an expired handle survived collection")
	}
	if !exists(t, s.pool, live) {
		t.Error("collection deleted a live handle")
	}
}

// TestGCKeepsRecentlyExpiredHandlesForTheGracePeriod. Deleting the instant a
// handle expires destroys the row an audit investigation would want.
func TestGCKeepsRecentlyExpiredHandlesForTheGracePeriod(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	past := s.WithClock(func() time.Time { return time.Now().Add(-2 * time.Minute) })
	recentlyDead, err := past.Mint(ctx, analyst(), KindQueryResult, json.RawMessage(`{}`), time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	// Expired about a minute ago; the grace period is an hour.
	if _, err := s.Collect(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	if !exists(t, s.pool, recentlyDead) {
		t.Fatal("a handle that expired inside the grace period was collected; the row an " +
			"audit would want is gone")
	}

	// It must still be unresolvable, though. Retention is not revival.
	if _, err := s.Resolve(ctx, analyst(), recentlyDead); !errors.Is(err, ErrNotResolvable) {
		t.Fatal("a retained expired handle resolved")
	}
}

func exists(t *testing.T, pool *pgxpool.Pool, id string) bool {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM state_handles WHERE handle_id = $1`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// TestBindingConstraintIsEnforcedByTheDatabase. resolve.go's binding check is
// belt and braces behind this; if the CHECK ever stops firing, the Go-side
// check is all that remains and this test says so.
func TestBindingConstraintIsEnforcedByTheDatabase(t *testing.T) {
	s := testStore(t)

	_, err := s.pool.Exec(context.Background(), `
		INSERT INTO state_handles (handle_id, tenant_id, principal_id, binding, kind, payload, expires_at)
		VALUES ($1, $2, $3, $4, 'query_result', '{}'::jsonb, now() + interval '5 minutes')`,
		"hnd_FORGED", demoTenant, analystID, Binding(operatorID, "hnd_FORGED"))

	if err == nil {
		t.Fatal("the database accepted a handle whose binding names a different principal " +
			"than its own principal_id column")
	}
}
