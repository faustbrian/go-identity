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

// Called under the shared scope lock before new history is written. A durable
// closed cut fences writers without holding a SQL transaction across native IO.
// Expiry cannot grant health; it only allows evidence to accumulate for recovery.
func (s *velocityJournal) writerOpen(ctx context.Context, tx pgx.Tx, tenant string) error {
	var closed bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+s.schema+`.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND state='replaying' AND replay_through>replay_from AND lease_expires_at>clock_timestamp())`, tenant, s.namespace).Scan(&closed); err != nil || closed {
		return identity.UnavailableError{}
	}
	return nil
}
