package postgres

import (
	"context"
	"encoding/binary"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// Scope locks precede timestamp/sequence allocation and all attempt/epoch row
// locks. Writers retain a shared transaction lock through commit/rollback;
// recovery takes the same exclusive lock, draining every overlapping writer.
// This is an acquisition boundary, not a persistent lease or replay watermark:
// new evidence may arrive later and the replay owner must account for it.
func (s *velocityJournal) scopeLock(ctx context.Context, tx pgx.Tx, tenant string, shared bool) error {
	digest := velocityMAC(s.key, "identity-risk-velocity-recovery-lock-v1", string(s.namespace), tenant)
	// All 64 bits deliberately identify PostgreSQL's signed advisory-lock key.
	key := int64(binary.BigEndian.Uint64(digest[:8]))
	query := `SELECT pg_advisory_xact_lock($1)`
	if shared {
		query = `SELECT pg_advisory_xact_lock_shared($1)`
	}
	if _, err := tx.Exec(ctx, query, key); err != nil {
		return identity.UnavailableError{}
	}
	return nil
}
