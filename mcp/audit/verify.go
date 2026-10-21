package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Chain verification.
//
// `broker audit verify --from --to` walks the chain and reports the FIRST
// break. First, not all: after a rewritten row every subsequent link fails too,
// and printing a thousand breaks obscures the one that matters.

// Verifier walks a tenant's chain.
type Verifier struct {
	pool *pgxpool.Pool
}

func NewVerifier(pool *pgxpool.Pool) *Verifier { return &Verifier{pool: pool} }

const walkSQL = `
SELECT seq, occurred_at, tenant_id, principal_id, tool_name, scopes_exercised,
       arguments_redacted, protocol_version, trace_id, correlation_id,
       outcome, coalesce(error_code, 0), duration_ms, prev_hash, row_hash
  FROM tool_invocations
 WHERE tenant_id = $1
   AND occurred_at >= $2
   AND occurred_at < $3
 ORDER BY seq`

// Result reports what verification found.
type Result struct {
	TenantID string
	Rows     int
	From     time.Time
	To       time.Time
	// Break is nil when the chain verifies.
	Break *Break
	// StartedFromGenesis is false when the window begins mid-chain, in which
	// case the first row's prev_hash is taken on trust — it links to a row
	// outside the window.
	StartedFromGenesis bool
}

// OK reports whether the chain verified.
func (r Result) OK() bool { return r.Break == nil }

func (r Result) String() string {
	if r.Break != nil {
		return r.Break.String()
	}
	scope := "from genesis"
	if !r.StartedFromGenesis {
		scope = "from a mid-chain row, whose prev_hash links outside the window and is taken on trust"
	}
	return fmt.Sprintf("verified %d row(s) for tenant %s between %s and %s, %s: chain intact",
		r.Rows, r.TenantID,
		r.From.Format(time.RFC3339), r.To.Format(time.RFC3339), scope)
}

// Verify walks the chain and returns the first break, if any.
func (v *Verifier) Verify(ctx context.Context, tenantID string, from, to time.Time) (Result, error) {
	res := Result{TenantID: tenantID, From: from, To: to}

	rows, err := v.pool.Query(ctx, walkSQL, tenantID, from, to)
	if err != nil {
		return res, fmt.Errorf("audit: walk chain: %w", err)
	}
	defer rows.Close()

	expectedPrev := ""
	for rows.Next() {
		var (
			seq       int64
			r         Record
			errorCode int
			prevHash  string
			rowHash   string
			args      []byte
		)
		if err := rows.Scan(
			&seq, &r.OccurredAt, &r.TenantID, &r.PrincipalID, &r.ToolName, &r.ScopesExercised,
			&args, &r.ProtocolVersion, &r.TraceID, &r.CorrelationID,
			&r.Outcome, &errorCode, &r.DurationMs, &prevHash, &rowHash,
		); err != nil {
			return res, fmt.Errorf("audit: scan row: %w", err)
		}
		r.ArgumentsRedacted = json.RawMessage(args)
		r.ErrorCode = errorCode

		if res.Rows == 0 {
			res.StartedFromGenesis = prevHash == GenesisHash
			expectedPrev = prevHash
		}
		res.Rows++

		// 1. Does the row's prev_hash still link to the row before it?
		//
		// Checked first, because a removed or reordered row breaks the LINK
		// while every row's own contents remain internally consistent — and
		// reporting "contents rewritten" for a deletion would send an
		// investigator looking for the wrong thing.
		if prevHash != expectedPrev {
			res.Break = &Break{
				Seq: seq, OccurredAt: r.OccurredAt, TenantID: r.TenantID,
				Expected: expectedPrev, Stored: prevHash,
				Reason: ReasonLinkBroken,
			}
			return res, nil
		}

		// 2. Do the row's own contents still hash to its stored hash?
		recomputed, err := RowHash(prevHash, r)
		if err != nil {
			return res, fmt.Errorf("audit: recompute hash for seq %d: %w", seq, err)
		}
		if recomputed != rowHash {
			res.Break = &Break{
				Seq: seq, OccurredAt: r.OccurredAt, TenantID: r.TenantID,
				Expected: recomputed, Stored: rowHash,
				Reason: ReasonRowRewritten,
			}
			return res, nil
		}

		expectedPrev = rowHash
	}
	if err := rows.Err(); err != nil {
		return res, fmt.Errorf("audit: iterate chain: %w", err)
	}

	return res, nil
}

// Tenants lists the tenants that have audit rows in a window, so `verify` with
// no tenant can walk all of them.
func (v *Verifier) Tenants(ctx context.Context, from, to time.Time) ([]string, error) {
	rows, err := v.pool.Query(ctx,
		`SELECT DISTINCT tenant_id::text FROM tool_invocations
		  WHERE occurred_at >= $1 AND occurred_at < $2 ORDER BY 1`, from, to)
	if err != nil {
		return nil, fmt.Errorf("audit: list tenants: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, fmt.Errorf("audit: scan tenant: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
