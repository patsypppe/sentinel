package handles

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/patsypppe/sentinel/broker/internal/envelope"
	"github.com/patsypppe/sentinel/broker/internal/registry"
)

// This file is the ONLY place a handle becomes usable (docs/HANDOFF.md §5).
//
// It is short on purpose. A reviewer auditing whether possession of a handle
// can ever substitute for authentication should be able to answer the question
// by reading it end to end.

// ErrNotResolvable is returned for EVERY failed resolution, whatever the cause:
// the handle does not exist, it belongs to another principal, it belongs to
// another tenant, it expired, or it was revoked.
//
// Distinguishing those cases turns the handle space into an enumeration oracle:
// "not yours" confirms existence, and an attacker holding a leaked identifier
// learns whether it is live. One error, one message, always.
var ErrNotResolvable = errors.New("handle is not resolvable")

// resolveSQL is the exact query from §7.4. It is a single statement, and every
// clause is load-bearing:
//
//	handle_id      what was asked for
//	tenant_id      the tenant from the VALIDATED TOKEN, not from the handle
//	principal_id   likewise — this is the binding check
//	revoked_at     revocation takes effect immediately, not at expiry
//	expires_at     evaluated by the database, so a skewed app clock cannot
//	               extend a handle's life
//
// There is no variant of this query anywhere in the repository. A second
// resolution path is how the check gets skipped.
const resolveSQL = `
SELECT payload, binding
  FROM state_handles
 WHERE handle_id = $1
   AND tenant_id = $2
   AND principal_id = $3
   AND revoked_at IS NULL
   AND expires_at > now()`

// resolveTypedSQL is resolveSQL with one extra predicate. It is written out in
// full rather than concatenated so that both queries can be read as SQL, which
// is the whole reason this file has no ORM behind it.
const resolveTypedSQL = `
SELECT payload, binding
  FROM state_handles
 WHERE handle_id = $1
   AND tenant_id = $2
   AND principal_id = $3
   AND revoked_at IS NULL
   AND expires_at > now()
   AND kind = $4`

// Resolve returns a handle's payload, or ErrNotResolvable.
//
// The principal is re-verified here on EVERY call. There is deliberately no
// cache: a resolved handle held in memory and reused without the check is the
// exact shape of the bug this design exists to prevent, and it would not show
// up in a test that resolves each handle once.
func (s *Store) Resolve(ctx context.Context, p registry.Principal, id string) (json.RawMessage, error) {
	var payload json.RawMessage
	var binding string

	err := s.pool.QueryRow(ctx, resolveSQL, id, p.TenantID, p.ID).Scan(&payload, &binding)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotResolvable
		}
		return nil, fmt.Errorf("handles: resolve: %w", err)
	}

	// Belt and braces. The database CHECK constraint already guarantees the
	// binding matches its own columns, and the WHERE clause already matched on
	// principal_id — so this can only fire if the row was written by something
	// that bypassed both. It costs one string comparison, and the failure it
	// catches is one where every other control has already been defeated.
	if binding != Binding(p.ID, id) {
		return nil, ErrNotResolvable
	}

	return payload, nil
}

// ResolveTyped resolves and decodes in one step, checking the kind.
//
// The kind check is not decoration: a deployment_plan handle presented where a
// query_result is expected is either a confused client or a probe, and both
// should stop here rather than at whatever tries to use the payload.
func (s *Store) ResolveTyped(
	ctx context.Context, p registry.Principal, id, wantKind string, into any,
) error {
	var payload json.RawMessage
	var binding string

	err := s.pool.QueryRow(ctx, resolveTypedSQL, id, p.TenantID, p.ID, wantKind).
		Scan(&payload, &binding)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Same error as every other failure. A caller must not be able to
			// learn that a handle exists but is of the wrong kind.
			return ErrNotResolvable
		}
		return fmt.Errorf("handles: resolve typed: %w", err)
	}
	if binding != Binding(p.ID, id) {
		return ErrNotResolvable
	}
	return json.Unmarshal(payload, into)
}

// RPCError renders a resolution failure for the wire.
//
// One code, one message, no data field. Everything a caller can act on is in
// the message, and everything else would be a signal.
func RPCError() *envelope.RPCError {
	return envelope.New(envelope.CodeHandleNotResolvable,
		"handle is not resolvable: it does not exist, is not yours, has expired, or was revoked",
		nil)
}
