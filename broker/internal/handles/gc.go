package handles

import (
	"context"
	"fmt"
	"time"

	"github.com/patsypppe/sentinel/broker/internal/registry"
)

// Handle lifecycle beyond resolution: revocation and collection.

const revokeSQL = `
UPDATE state_handles
   SET revoked_at = now()
 WHERE handle_id = $1
   AND tenant_id = $2
   AND principal_id = $3
   AND revoked_at IS NULL`

// Revoke retires a handle immediately.
//
// It is scoped to the owning principal exactly as resolution is: revoking
// someone else's handle would be a denial-of-service primitive handed out to
// anyone who saw an identifier. A no-op returns nil rather than an error, for
// the same reason resolution has one error — reporting "there was nothing to
// revoke" tells the caller whether the handle existed.
func (s *Store) Revoke(ctx context.Context, p registry.Principal, id string) error {
	if _, err := s.pool.Exec(ctx, revokeSQL, id, p.TenantID, p.ID); err != nil {
		return fmt.Errorf("handles: revoke: %w", err)
	}
	return nil
}

const collectSQL = `
DELETE FROM state_handles
 WHERE expires_at <= now() - $1::interval
    OR (revoked_at IS NOT NULL AND revoked_at <= now() - $1::interval)`

// Collect deletes handles that expired or were revoked longer ago than grace.
//
// The grace period matters. Deleting the instant a handle expires makes an
// expired handle indistinguishable from one that never existed — which is fine,
// since resolution returns the same error either way — but it also destroys the
// row an audit investigation would want. Keeping expired rows briefly costs
// nothing and answers "was this handle ever real?" after the fact.
func (s *Store) Collect(ctx context.Context, grace time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, collectSQL, grace.String())
	if err != nil {
		return 0, fmt.Errorf("handles: collect: %w", err)
	}
	return tag.RowsAffected(), nil
}

// RunCollector sweeps on an interval until ctx is cancelled.
func (s *Store) RunCollector(ctx context.Context, every, grace time.Duration, onSweep func(int64, error)) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := s.Collect(ctx, grace)
			if onSweep != nil {
				onSweep(n, err)
			}
		}
	}
}
