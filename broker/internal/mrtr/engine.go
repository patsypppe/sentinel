package mrtr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/patsypppe/sentinel/broker/internal/envelope"
	"github.com/patsypppe/sentinel/broker/internal/registry"
)

// The MRTR state machine, docs/HANDOFF.md §8.5.
//
//	                    tools/call (Irreversible tool)
//	                              │
//	                              ▼
//	                    ┌──────────────────┐
//	                    │ awaiting_input   │──── expires_at reached ──▶ expired
//	                    │ requestState     │
//	                    │ sealed → client  │──── never retried ───────▶ abandoned (GC)
//	                    └────────┬─────────┘
//	                             │ retry with inputResponses + requestState
//	                             ▼
//	                  ┌──────────────────────┐
//	                  │ verify seal          │  tampered → -32004
//	                  │ verify arguments_hash│  mutated  → -32003
//	                  │ verify principal     │  mismatch → -32000
//	                  └──────────┬───────────┘
//	                             │ first time
//	                             ▼
//	                    ┌──────────────────┐
//	                    │ execute effect   │  ← the ONLY place a side effect happens
//	                    │ record result    │
//	                    │ status=consumed  │
//	                    └────────┬─────────┘
//	                             │
//	      duplicate retry ───────┴──────▶ return RecordedResult verbatim, zero effects
//	      (within replay_window)
//
// The single most important line above is the box containing BOTH "execute
// effect" and "record result": they commit in ONE TRANSACTION. Executing before
// recording means a crash between the two re-executes on the next retry, which
// is the exact failure the whole mechanism exists to prevent (§14 gotcha 5).

// FlowStatus values.
const (
	StatusAwaitingInput = "awaiting_input"
	StatusConsumed      = "consumed"
	StatusExpired       = "expired"
	StatusAbandoned     = "abandoned"
)

var (
	// ErrFlowNotFound covers an unknown correlation id and one belonging to
	// another principal — indistinguishable, for the same reason handles are.
	ErrFlowNotFound = errors.New("mrtr: flow is not resolvable")
	// ErrFlowExpired: the flow sat awaiting input past flow_ttl.
	ErrFlowExpired = errors.New("mrtr: flow expired before it was completed")
	// ErrArgumentsMutated: the retry's arguments differ from the original.
	ErrArgumentsMutated = errors.New("mrtr: retry arguments differ from the approved call")
	// ErrReplayWindowClosed: consumed, and the recorded result has aged out.
	// Never a re-execution.
	ErrReplayWindowClosed = errors.New("mrtr: the recorded result is no longer available")
)

// Effect is the side effect a flow gates. It receives the transaction the flow
// is being consumed in, so the effect and the record commit together or not at
// all.
type Effect func(ctx context.Context, tx pgx.Tx, correlationID string, args json.RawMessage) (json.RawMessage, error)

// Engine drives the state machine.
type Engine struct {
	pool         *pgxpool.Pool
	sealer       *Sealer
	flowTTL      time.Duration
	replayWindow time.Duration
	now          func() time.Time
}

// Options configures the engine.
type Options struct {
	FlowTTL      time.Duration
	ReplayWindow time.Duration
}

func NewEngine(pool *pgxpool.Pool, sealer *Sealer, opts Options) (*Engine, error) {
	if opts.FlowTTL <= 0 {
		return nil, errors.New("mrtr: flow ttl must be positive")
	}
	if opts.ReplayWindow < opts.FlowTTL {
		// The same check config.Validate makes, enforced here too because the
		// engine can be constructed directly in tests: a replay window shorter
		// than the flow TTL re-opens the exactly-once hole it exists to close.
		return nil, fmt.Errorf("mrtr: replay window (%s) must not be shorter than flow ttl (%s)",
			opts.ReplayWindow, opts.FlowTTL)
	}
	return &Engine{
		pool:         pool,
		sealer:       sealer,
		flowTTL:      opts.FlowTTL,
		replayWindow: opts.ReplayWindow,
		now:          time.Now,
	}, nil
}

// WithClock replaces the clock, for tests.
func (e *Engine) WithClock(now func() time.Time) *Engine {
	return &Engine{
		pool: e.pool, sealer: e.sealer.WithClock(now),
		flowTTL: e.flowTTL, replayWindow: e.replayWindow, now: now,
	}
}

const beginSQL = `
INSERT INTO mrtr_flows (correlation_id, tenant_id, principal_id, tool_name,
                        arguments_hash, input_requests, status, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, 'awaiting_input', $7)`

// Begin opens a flow and returns the sealed requestState for the client.
//
// Nothing has happened yet. The effect runs only in Resume, and only once.
func (e *Engine) Begin(
	ctx context.Context,
	p registry.Principal,
	toolName string,
	args json.RawMessage,
	requests []envelope.InputRequest,
) (requestState string, err error) {
	if len(requests) == 0 {
		return "", errors.New("mrtr: a flow must carry at least one input request, " +
			"or the client has nothing to respond to")
	}

	argsHash, err := ArgumentsHash(args)
	if err != nil {
		return "", err
	}

	correlationID := "mrtr_" + uuid.NewString()
	expiry := e.now().Add(e.flowTTL)

	encodedRequests, err := json.Marshal(requests)
	if err != nil {
		return "", fmt.Errorf("mrtr: encode input requests: %w", err)
	}

	if _, err := e.pool.Exec(ctx, beginSQL,
		correlationID, p.TenantID, p.ID, toolName, argsHash, encodedRequests, expiry); err != nil {
		return "", fmt.Errorf("mrtr: begin flow: %w", err)
	}

	return e.sealer.Seal(correlationID, expiry, toolName)
}

// Outcome is what Resume produced.
type Outcome struct {
	// Result is the tool result, whether freshly executed or replayed.
	Result json.RawMessage
	// Replayed is true when this retry was a duplicate and no effect ran.
	Replayed bool
}

// selectForUpdate locks the flow row for the duration of the transaction.
//
// FOR UPDATE is what makes concurrent duplicate retries safe. Two retries
// arriving at once would otherwise both read status='awaiting_input', both pass
// their checks, and both execute. The lock serializes them: the second waits,
// then reads status='consumed' and replays.
const selectForUpdate = `
SELECT tool_name, arguments_hash, status, recorded_result, expires_at, replay_until
  FROM mrtr_flows
 WHERE correlation_id = $1
   AND tenant_id = $2
   AND principal_id = $3
   FOR UPDATE`

const consumeSQL = `
UPDATE mrtr_flows
   SET status = 'consumed', recorded_result = $2, consumed_at = now(), replay_until = $3
 WHERE correlation_id = $1`

// Resume verifies a retry and either executes the effect exactly once or
// replays the recorded result.
//
// The verification order is deliberate and every step is a listed pitfall:
//
//  1. Unseal — a tampered or forged requestState never reaches the database.
//  2. Look up BY CORRELATION ID and by principal — never by JSON-RPC id, which
//     is different on every retry (§14 gotcha 4).
//  3. Lock the row, so concurrent duplicates serialize.
//  4. If already consumed, replay verbatim. This is checked BEFORE the
//     arguments hash: a duplicate retry is the expected case and must succeed,
//     and a client that re-serialized its arguments should still get its result.
//  5. Check expiry, then the arguments hash.
//  6. Execute and record IN ONE TRANSACTION.
func (e *Engine) Resume(
	ctx context.Context,
	p registry.Principal,
	requestState string,
	toolName string,
	args json.RawMessage,
	effect Effect,
) (Outcome, error) {
	// 1.
	correlationID, _, err := e.sealer.Unseal(requestState, toolName)
	if err != nil {
		return Outcome{}, err
	}

	tx, err := e.pool.Begin(ctx)
	if err != nil {
		return Outcome{}, fmt.Errorf("mrtr: begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 2 and 3. The principal is part of the predicate, so a flow belonging to
	// someone else is simply not found — the same answer as one that never
	// existed.
	var (
		storedTool  string
		storedHash  string
		status      string
		recorded    []byte
		expiresAt   time.Time
		replayUntil *time.Time
	)
	err = tx.QueryRow(ctx, selectForUpdate, correlationID, p.TenantID, p.ID).
		Scan(&storedTool, &storedHash, &status, &recorded, &expiresAt, &replayUntil)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Outcome{}, ErrFlowNotFound
		}
		return Outcome{}, fmt.Errorf("mrtr: load flow: %w", err)
	}

	// The seal already bound the tool name as AAD, so this cannot normally
	// disagree. It is checked anyway: if it ever does, something has rewritten
	// a row, and executing the wrong tool's effect is not a failure worth
	// risking on the strength of one control.
	if storedTool != toolName {
		return Outcome{}, ErrFlowNotFound
	}

	// 4. Replay before anything else that could reject the retry.
	if status == StatusConsumed {
		if replayUntil != nil && e.now().After(*replayUntil) {
			// Past the replay window. A clear error, never a re-execution.
			return Outcome{}, ErrReplayWindowClosed
		}
		return Outcome{Result: recorded, Replayed: true}, nil
	}

	if status != StatusAwaitingInput {
		return Outcome{}, ErrFlowExpired
	}

	// 5.
	if e.now().After(expiresAt) {
		return Outcome{}, ErrFlowExpired
	}
	matches, err := ArgumentsMatch(storedHash, args)
	if err != nil {
		return Outcome{}, err
	}
	if !matches {
		return Outcome{}, ErrArgumentsMutated
	}

	// 6. The effect and the record commit together. A crash anywhere in here
	// rolls both back, so the next retry finds the flow still awaiting input and
	// executes exactly once — rather than finding it consumed with no result, or
	// executed with no record.
	result, err := effect(ctx, tx, correlationID, args)
	if err != nil {
		return Outcome{}, err
	}
	if len(result) == 0 {
		// A consumed flow with no recorded result would re-execute on the next
		// retry. The database CHECK constraint refuses that state too; this
		// catches it with a message that explains why.
		return Outcome{}, errors.New("mrtr: the effect returned no result to record; a " +
			"consumed flow with no recorded result would re-execute on the next retry")
	}

	if _, err := tx.Exec(ctx, consumeSQL,
		correlationID, result, e.now().Add(e.replayWindow)); err != nil {
		return Outcome{}, fmt.Errorf("mrtr: record result: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Outcome{}, fmt.Errorf("mrtr: commit: %w", err)
	}

	return Outcome{Result: result, Replayed: false}, nil
}

const sweepSQL = `
UPDATE mrtr_flows
   SET status = 'expired'
 WHERE status = 'awaiting_input'
   AND expires_at <= now()`

// Sweep marks flows that were never retried. A flow left awaiting input forever
// is not harmful, but it is also not informative; marking it makes "how many
// approvals were abandoned?" answerable.
func (e *Engine) Sweep(ctx context.Context) (int64, error) {
	tag, err := e.pool.Exec(ctx, sweepSQL)
	if err != nil {
		return 0, fmt.Errorf("mrtr: sweep: %w", err)
	}
	return tag.RowsAffected(), nil
}

// RPCError maps an engine error onto the wire.
func RPCError(err error) *envelope.RPCError {
	switch {
	case errors.Is(err, ErrStateInvalid):
		return envelope.New(envelope.CodeMRTRStateInvalid,
			"requestState is not valid: it was tampered with, forged, or issued for a different tool", nil)
	case errors.Is(err, ErrStateExpired), errors.Is(err, ErrFlowExpired):
		return envelope.New(envelope.CodeMRTRFlowExpired,
			"this approval expired before it was completed; start the request again", nil)
	case errors.Is(err, ErrArgumentsMutated):
		return envelope.New(envelope.CodeMRTRArgumentsMutated,
			"the retry's arguments differ from the call that was approved; "+
				"start the request again with the arguments you intend", nil)
	case errors.Is(err, ErrReplayWindowClosed):
		return envelope.New(envelope.CodeMRTRResultNoLongerAvailable,
			"this request already completed, but its recorded result is no longer available; "+
				"it was NOT performed again", nil)
	case errors.Is(err, ErrFlowNotFound):
		return envelope.New(envelope.CodeHandleNotResolvable,
			"no such in-progress request", nil)
	default:
		return envelope.ErrInternal("the request could not be completed")
	}
}
