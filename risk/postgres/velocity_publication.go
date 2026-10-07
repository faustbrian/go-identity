package postgres

import (
	"context"
	"crypto/hmac"
	"errors"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	"github.com/jackc/pgx/v5"
)

type velocityPublicationCheck struct {
	cut     *velocityRecoveryClosure
	id      [32]byte
	persist bool
}

// ConfirmPublication durably records the configured native owner's exact
// publication in the existing primary epoch. Install
// VelocityPublicationMigrationSource. Original lease, cut, coverage and expiry
// remain unchanged; matching retries retain the original confirmation time.
// Unknown commit acknowledgement returns unavailable, never success or native
// resend permission. Retry the same custody to reconcile primary truth.
// This keeps the replay writer fence closed and does not publish healthy state,
// confirm present native continuity or authorize traffic. SQL locks never span
// native IO. Cancellation is preserved; other failures are redacted.
func (r VelocityRecovery) ConfirmPublication(ctx context.Context, lease VelocityRecoveryLease, owned risk.VelocityLease, cut VelocityRecoveryClosure, exported risk.VelocityClosure, publication risk.VelocityPublication) error {
	return r.publication(ctx, lease, owned, cut, exported, publication, true)
}

// CheckPublication rechecks the same recorded confirmation and original live
// custody without writing, renewing time or reopening journal admission. A
// missing, foreign, altered, expired or superseded confirmation denies. This is
// primary confirmation only, not evidence that the native projection is intact.
func (r VelocityRecovery) CheckPublication(ctx context.Context, lease VelocityRecoveryLease, owned risk.VelocityLease, cut VelocityRecoveryClosure, exported risk.VelocityClosure, publication risk.VelocityPublication) error {
	return r.publication(ctx, lease, owned, cut, exported, publication, false)
}

func (r VelocityRecovery) publication(ctx context.Context, lease VelocityRecoveryLease, owned risk.VelocityLease, cut VelocityRecoveryClosure, exported risk.VelocityClosure, publication risk.VelocityPublication, persist bool) error {
	if r.state == nil || r.state.journalIssuer == (risk.VelocityJournalIssuer{}) || lease.state == nil || lease.state.owner != r.state || cut.state == nil || cut.state.lease != lease.state || cut.state.started.IsZero() {
		return identity.InvalidInputError{Field: "velocity_publication"}
	}
	s, l := r.state, lease.state
	bounded, cancel, err := s.bounded(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	lb, err := s.journalReader.Lease(owned)
	if err != nil || lb.Tenant != l.tenant || !hmac.Equal(lb.Namespace[:], s.journal.namespace) || lb.Epoch != l.epoch || lb.Owner != l.token || lb.Generation != l.generation || !lb.ExpiresAt.Equal(l.expires) {
		return identity.InvalidInputError{Field: "velocity_publication"}
	}
	b, err := s.nativeVerifier.Publication(bounded, owned, exported, publication)
	if err != nil {
		return velocityPublicationError(bounded, err)
	}
	if b != s.closureBinding(l, cut.state) {
		return identity.InvalidInputError{Field: "velocity_publication"}
	}
	_, err = r.primaryPublicationClosure(bounded, lease, false, true, &velocityPublicationCheck{cut: cut.state, id: b.ID, persist: persist})
	return velocityPublicationError(bounded, err)
}

func velocityPublicationError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return identity.UnavailableError{}
}

// Called only under the exclusive scope fence, after applied/coverage checks.
// The persisted identity is the existing primary's keyed exact cut, not a
// separate journal, caller-supplied health assertion or replacement lease.
func (s *velocityRecovery) confirmPublication(ctx context.Context, tx pgx.Tx, l *velocityRecoveryLease, current *velocityRecoveryClosure, check *velocityPublicationCheck, now time.Time) error {
	if current.position != check.cut.position || !current.from.Equal(check.cut.from) || !current.through.Equal(check.cut.through) || !current.started.Equal(check.cut.started) || check.id != s.closureBinding(l, current).ID {
		return identity.UnavailableError{}
	}
	var id []byte
	var confirmed *time.Time
	if err := tx.QueryRow(ctx, `SELECT publication_id,publication_confirmed_at FROM `+s.journal.schema+`.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.tenant, s.journal.namespace, l.epoch[:]).Scan(&id, &confirmed); err != nil {
		return identity.UnavailableError{}
	}
	if confirmed != nil || len(id) != 0 {
		if confirmed == nil || !hmac.Equal(id, check.id[:]) || confirmed.Before(current.through) || !confirmed.Before(l.expires) || confirmed.After(now) {
			return identity.UnavailableError{}
		}
		return nil
	}
	if !check.persist {
		return identity.UnavailableError{}
	}
	_, err := tx.Exec(ctx, `UPDATE `+s.journal.schema+`.velocity_epochs SET publication_id=$4,publication_confirmed_at=$5 WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.tenant, s.journal.namespace, l.epoch[:], check.id[:], now)
	if err != nil {
		return identity.UnavailableError{}
	}
	return nil
}

// Lease/page-only deployments may predate optional publication metadata.
// Renewal/takeover clears it when installed, while retaining old-schema APIs.
func (s *velocityRecovery) clearPublication(ctx context.Context, tx pgx.Tx, tenant string, epoch [16]byte) error {
	var installed bool
	if err := tx.QueryRow(ctx, `SELECT to_jsonb(e) ? 'publication_id' FROM `+s.journal.schema+`.velocity_epochs e WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, tenant, s.journal.namespace, epoch[:]).Scan(&installed); err != nil {
		return identity.UnavailableError{}
	}
	if installed {
		if _, err := tx.Exec(ctx, `UPDATE `+s.journal.schema+`.velocity_epochs SET publication_id=NULL,publication_confirmed_at=NULL WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, tenant, s.journal.namespace, epoch[:]); err != nil {
			return identity.UnavailableError{}
		}
	}
	return nil
}
