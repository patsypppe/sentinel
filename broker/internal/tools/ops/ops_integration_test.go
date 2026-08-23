//go:build integration

package ops

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/patsypppe/sentinel/broker/internal/handles"
	"github.com/patsypppe/sentinel/broker/internal/mrtr"
	"github.com/patsypppe/sentinel/broker/internal/registry"
	"github.com/patsypppe/sentinel/broker/internal/store"
)

// The §10 (WP-6) definition of done, end to end through the real tools:
//
//	ops.deployment_apply → input_required → approve → retry completes →
//	replay the identical retry → identical response, ONE deployment.

const (
	demoTenant = "00000000-0000-0000-0000-000000000001"
	analystID  = "00000000-0000-0000-0000-0000000000a1"
	operatorID = "00000000-0000-0000-0000-0000000000a2"
)

func operator() registry.Principal {
	return registry.Principal{
		TenantID: demoTenant, ID: operatorID,
		Scopes: []string{"ops:plan", "ops:apply"},
	}
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

type harness struct {
	pool    *pgxpool.Pool
	plan    *PlanTool
	apply   *ApplyTool
	handles *handles.Store
}

func newHarness(t *testing.T) *harness {
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

	key, err := mrtr.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := mrtr.NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := mrtr.NewEngine(s.Pool(), sealer,
		mrtr.Options{FlowTTL: 5 * time.Minute, ReplayWindow: time.Hour})
	if err != nil {
		t.Fatal(err)
	}

	hs := handles.NewStore(s.Pool())
	return &harness{
		pool:    s.Pool(),
		plan:    NewPlanTool(hs, 15*time.Minute),
		apply:   NewApplyTool(engine, hs),
		handles: hs,
	}
}

func (h *harness) planHandle(t *testing.T, p registry.Principal) string {
	t.Helper()
	res, err := h.plan.Call(context.Background(), p,
		json.RawMessage(`{"service":"checkout","version":"1.4.2","replicas":3}`))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	var out struct {
		Handle string `json:"handle"`
	}
	if err := json.Unmarshal(res.StructuredContent, &out); err != nil {
		t.Fatal(err)
	}
	if out.Handle == "" {
		t.Fatal("plan returned no handle")
	}
	return out.Handle
}

func (h *harness) deploymentCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := h.pool.QueryRow(context.Background(), `SELECT count(*) FROM deployments`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (h *harness) attemptCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := h.pool.QueryRow(context.Background(), `SELECT count(*) FROM deployment_attempts`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestApplyIsIrreversibleByDeclaration. Everything else in this file follows
// from this one property, and it is checked through the registry's own rule
// rather than by reading the constant.
func TestApplyIsIrreversibleByDeclaration(t *testing.T) {
	h := newHarness(t)

	if h.apply.Reversibility() != registry.Irreversible {
		t.Fatalf("ops.deployment_apply declares %q, want irreversible", h.apply.Reversibility())
	}
	if !h.apply.Reversibility().RequiresConfirmation(false) {
		t.Fatal("an irreversible tool must require confirmation with no threshold and no exception")
	}
	if h.plan.Reversibility() != registry.Reversible {
		t.Fatalf("ops.deployment_plan declares %q; planning changes nothing", h.plan.Reversibility())
	}
}

// TestFullMRTRRoundTrip is the WP-6 definition of done.
func TestFullMRTRRoundTrip(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	before := h.deploymentCount(t)
	beforeAttempts := h.attemptCount(t)

	handle := h.planHandle(t, operator())

	// 1. The first call returns input_required and deploys nothing.
	args := json.RawMessage(`{"plan":"` + handle + `"}`)
	first, err := h.apply.Call(ctx, operator(), args)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.InputRequests) == 0 {
		t.Fatal("an irreversible tool's first call must return inputRequests")
	}
	if first.RequestState == "" {
		t.Fatal("an input_required result must carry a requestState")
	}
	if !first.InputRequests[0].Destructive {
		t.Error("a deployment confirmation should be flagged destructive")
	}
	if h.attemptCount(t) != beforeAttempts {
		t.Fatal("the first call deployed something; nothing may happen before confirmation")
	}

	// 2. The retry: a NEW request carrying inputResponses and the requestState.
	retry := json.RawMessage(`{"plan":"` + handle + `","requestState":"` + first.RequestState +
		`","inputResponses":{"confirm":true}}`)

	completed, err := h.apply.Call(ctx, operator(), retry)
	if err != nil {
		t.Fatalf("the retry failed: %v", err)
	}
	var out struct {
		Deployed     bool   `json:"deployed"`
		DeploymentID string `json:"deploymentId"`
	}
	if err := json.Unmarshal(completed.StructuredContent, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Deployed {
		t.Fatal("the confirmed retry did not deploy")
	}
	if h.deploymentCount(t) != before+1 {
		t.Fatalf("deployments went from %d to %d, want exactly one more", before, h.deploymentCount(t))
	}

	// 3. Replay the IDENTICAL retry. One deployment, two identical responses.
	replayed, err := h.apply.Call(ctx, operator(), retry)
	if err != nil {
		t.Fatalf("the replayed retry failed: %v", err)
	}
	if string(replayed.StructuredContent) != string(completed.StructuredContent) {
		t.Fatalf("the replay differs from the original:\n %s\n %s",
			completed.StructuredContent, replayed.StructuredContent)
	}
	if got := h.attemptCount(t); got != beforeAttempts+1 {
		t.Fatalf("the effect ran %d times, want exactly 1", got-beforeAttempts)
	}
	if h.deploymentCount(t) != before+1 {
		t.Fatalf("the replay deployed again: %d deployments, want %d", h.deploymentCount(t), before+1)
	}

	// The replayed response must SAY it is a replay, or an operator reading the
	// transcript cannot tell one deployment from two.
	if len(replayed.Content) == 0 || !contains(replayed.Content[0].Text, "already completed") {
		t.Fatalf("the replay must state that nothing happened again: %+v", replayed.Content)
	}
}

// TestDeclinedConfirmationDeploysNothing.
func TestDeclinedConfirmationDeploysNothing(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	before := h.attemptCount(t)
	handle := h.planHandle(t, operator())

	first, err := h.apply.Call(ctx, operator(), json.RawMessage(`{"plan":"`+handle+`"}`))
	if err != nil {
		t.Fatal(err)
	}

	declined := json.RawMessage(`{"plan":"` + handle + `","requestState":"` + first.RequestState +
		`","inputResponses":{"confirm":false}}`)
	res, err := h.apply.Call(ctx, operator(), declined)
	if err != nil {
		t.Fatalf("declining must not be an error: %v", err)
	}
	if h.attemptCount(t) != before {
		t.Fatal("declining deployed something")
	}
	if len(res.Content) == 0 || !contains(res.Content[0].Text, "declined") {
		t.Fatalf("the response must say the confirmation was declined: %+v", res.Content)
	}

	// The approval is not burned: the client may confirm afterwards.
	confirmed := json.RawMessage(`{"plan":"` + handle + `","requestState":"` + first.RequestState +
		`","inputResponses":{"confirm":true}}`)
	if _, err := h.apply.Call(ctx, operator(), confirmed); err != nil {
		t.Fatalf("confirming after a decline failed: %v", err)
	}
	if h.attemptCount(t) != before+1 {
		t.Fatal("confirming after a decline did not deploy")
	}
}

// TestRetryIsNotReadAsAMutation. The retry necessarily carries fields the first
// call did not — requestState and inputResponses. Hashing the whole argument
// object would make every legitimate retry look like a mutation.
func TestRetryIsNotReadAsAMutation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	handle := h.planHandle(t, operator())
	first, err := h.apply.Call(ctx, operator(), json.RawMessage(`{"plan":"`+handle+`"}`))
	if err != nil {
		t.Fatal(err)
	}

	retry := json.RawMessage(`{"plan":"` + handle + `","requestState":"` + first.RequestState +
		`","inputResponses":{"confirm":true}}`)
	if _, err := h.apply.Call(ctx, operator(), retry); err != nil {
		if errors.Is(err, mrtr.ErrArgumentsMutated) {
			t.Fatal("the retry's own extra fields were read as a mutation; the approved " +
				"argument set must exclude requestState and inputResponses")
		}
		t.Fatal(err)
	}
}

// TestChangingThePlanOnRetryIsRejected. The complement: what the approval
// actually covers must be inside the hash.
func TestChangingThePlanOnRetryIsRejected(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	approved := h.planHandle(t, operator())
	other := h.planHandle(t, operator())

	first, err := h.apply.Call(ctx, operator(), json.RawMessage(`{"plan":"`+approved+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	before := h.attemptCount(t)

	swapped := json.RawMessage(`{"plan":"` + other + `","requestState":"` + first.RequestState +
		`","inputResponses":{"confirm":true}}`)
	_, err = h.apply.Call(ctx, operator(), swapped)
	if !errors.Is(err, mrtr.ErrArgumentsMutated) {
		t.Fatalf("err = %v, want ErrArgumentsMutated: the user approved a specific plan", err)
	}
	if h.attemptCount(t) != before {
		t.Fatal("a swapped plan was deployed")
	}
}

// TestApplyRefusesAnotherPrincipalsPlanHandle. Possession is not
// authentication, and the handle is re-resolved on every call rather than
// trusted because it was checked once.
func TestApplyRefusesAnotherPrincipalsPlanHandle(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// The analyst has no ops scopes, so the plan is minted for the operator and
	// then presented BY the analyst — a leaked handle, in full.
	leaked := h.planHandle(t, operator())

	_, err := h.apply.Call(ctx, analyst(), json.RawMessage(`{"plan":"`+leaked+`"}`))
	if !errors.Is(err, handles.ErrNotResolvable) {
		t.Fatalf("err = %v, want ErrNotResolvable", err)
	}
}

// TestApplyRefusesAQueryResultHandle. A handle of the wrong kind is refused
// with the same error as a missing one.
func TestApplyRefusesAQueryResultHandle(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	wrongKind, err := h.handles.Mint(ctx, operator(), handles.KindQueryResult,
		json.RawMessage(`{"rows":[]}`), time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.apply.Call(ctx, operator(), json.RawMessage(`{"plan":"`+wrongKind+`"}`)); !errors.Is(err, handles.ErrNotResolvable) {
		t.Fatalf("err = %v, want ErrNotResolvable", err)
	}
}

func TestApplyRequiresAConfirmationOnRetry(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	handle := h.planHandle(t, operator())
	first, err := h.apply.Call(ctx, operator(), json.RawMessage(`{"plan":"`+handle+`"}`))
	if err != nil {
		t.Fatal(err)
	}

	noResponses := json.RawMessage(`{"plan":"` + handle + `","requestState":"` + first.RequestState + `"}`)
	_, err = h.apply.Call(ctx, operator(), noResponses)
	if err == nil {
		t.Fatal("a retry with no inputResponses must be refused")
	}
	if !contains(err.Error(), "inputResponses") || !contains(err.Error(), "try") {
		t.Fatalf("error %q must name the field and show what would work", err)
	}
}

func TestPlanValidatesItsArguments(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	for _, args := range []string{
		`{}`,
		`{"service":"checkout"}`,
		`{"service":"checkout","version":"1.4.2","replicas":0}`,
		`{"service":"checkout","version":"1.4.2","replicas":9999}`,
	} {
		_, err := h.plan.Call(ctx, operator(), json.RawMessage(args))
		if err == nil {
			t.Errorf("invalid plan arguments were accepted: %s", args)
			continue
		}
		if !contains(err.Error(), "try") {
			t.Errorf("error %q for %s should show what would work", err, args)
		}
	}
}

func TestPlanChangesNothing(t *testing.T) {
	h := newHarness(t)
	before := h.attemptCount(t)
	h.planHandle(t, operator())
	if h.attemptCount(t) != before {
		t.Fatal("planning performed a deployment")
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
