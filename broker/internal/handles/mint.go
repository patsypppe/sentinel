// Package handles implements server-minted state handles.
//
// Rule 1 of docs/HANDOFF.md §2: stateless, and handles are data, never
// credentials. There is no session and nothing keyed by connection. Cross-call
// state exists only as a handle passed as an ordinary tool argument, and
// POSSESSION OF A HANDLE IS NOT AUTHENTICATION — every resolution re-verifies
// principal and tenant against the validated token.
//
// resolve.go is the only place a handle becomes usable. That is a layout rule
// (§5) rather than a convention: a reviewer should be able to audit this
// property by reading one short file.
package handles

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/patsypppe/sentinel/broker/internal/registry"
)

// Prefix makes a handle self-describing in a log or an error message.
const Prefix = "hnd_"

// entropyBytes is 128 bits, per §7.4. A handle is not a credential, but it is
// also not a row number: a guessable handle would let an attacker probe the
// space, and the indistinguishable-error rule below only removes the ORACLE,
// not the guessing.
const entropyBytes = 16

// Handle kinds.
const (
	KindQueryResult    = "query_result"
	KindDeploymentPlan = "deployment_plan"
	KindUpload         = "upload"
)

// encoding is unpadded base32 without a separator: case-insensitive, safe in a
// URL and in a log line, and it survives being copied out of a terminal.
var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Store mints, resolves and collects handles.
type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// NewStore builds a handle store. now is injectable so expiry can be tested
// without sleeping.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool, now: time.Now}
}

// WithClock replaces the clock, for tests.
func (s *Store) WithClock(now func() time.Time) *Store {
	return &Store{pool: s.pool, now: now}
}

// NewID returns a fresh handle identifier: "hnd_" + base32 of 128 CSPRNG bits.
func NewID() (string, error) {
	buf := make([]byte, entropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("handles: read entropy: %w", err)
	}
	return Prefix + encoding.EncodeToString(buf), nil
}

// Binding is the value stored alongside every handle and verified on every use.
func Binding(principalID, handleID string) string {
	return principalID + ":" + handleID
}

const insertSQL = `
INSERT INTO state_handles (handle_id, tenant_id, principal_id, binding, kind, payload, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)`

// Mint stores a payload and returns its handle.
//
// The handle is bound to the minting principal at creation. Nothing later can
// widen that: resolution matches on principal_id, so a handle minted for one
// principal is not resolvable by another even with the identifier in hand.
func (s *Store) Mint(
	ctx context.Context,
	p registry.Principal,
	kind string,
	payload json.RawMessage,
	ttl time.Duration,
) (string, error) {
	if kind == "" {
		return "", fmt.Errorf("handles: a handle must declare its kind")
	}
	if ttl <= 0 {
		return "", fmt.Errorf("handles: ttl must be positive, got %s", ttl)
	}

	id, err := NewID()
	if err != nil {
		return "", err
	}

	_, err = s.pool.Exec(ctx, insertSQL,
		id, p.TenantID, p.ID, Binding(p.ID, id), kind, payload, s.now().Add(ttl))
	if err != nil {
		return "", fmt.Errorf("handles: mint: %w", err)
	}
	return id, nil
}
