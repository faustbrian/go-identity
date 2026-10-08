package postgres

import (
	"context"
	"crypto/hmac"
	"fmt"
	"io"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	"github.com/jackc/pgx/v5"
)

// VelocityHealthy retains exact-instance custody of one acknowledged primary
// activation, not a cached health assertion or permission for external effects.
// CheckHealthy must recheck current primary state before use; the concrete
// native owner must separately verify its exact marker and continuity at every
// effect boundary. Original expiry is never renewed. Zero is invalid; copies
// are immutable/concurrent-safe, redacted and nonserializable.
type VelocityHealthy struct{ state *velocityHealthy }
type velocityHealthy struct {
	owner     *velocityRecovery
	lease     *velocityRecoveryLease
	cut       *velocityRecoveryClosure
	activated time.Time
}

func (VelocityHealthy) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.VelocityHealthy(redacted)")
}
func (VelocityHealthy) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (VelocityHealthy) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }

// Activate atomically records primary eligibility for the exact covered,
// durably confirmed and native-confirmed cut, then reopens journal writers.
// Install VelocityActivationMigrationSource. It drains writers and independently
// authenticates original lease, applied progress, complete history, coverage and
// persisted confirmation under primary locks. No SQL lock spans native IO.
// The native acknowledgement is historical, not a substitute for those checks.
// Healthy retries reconcile the original activation without replay callbacks,
// writes or refreshed times; expired/superseded/invalidated state denies.
// Ambiguous commits return no receipt. Retry the same custody to reconcile.
// Cancellation is preserved; authority/IO failures are redacted unavailable.
// Success records primary state only: public traffic additionally needs current
// native continuity, exact-marker enforcement and owned intent/result execution.
func (r VelocityRecovery) Activate(ctx context.Context, lease VelocityRecoveryLease, owned risk.VelocityLease, cut VelocityRecoveryClosure, exported risk.VelocityClosure, publication risk.VelocityPublication, confirmation risk.VelocityConfirmation, native risk.VelocityNativeConfirmation) (VelocityHealthy, error) {
	if r.state == nil || lease.state == nil || lease.state.owner != r.state || cut.state == nil || cut.state.lease != lease.state || cut.state.started.IsZero() {
		return VelocityHealthy{}, identity.InvalidInputError{Field: "velocity_activation"}
	}
	s, l := r.state, lease.state
	bounded, cancel, err := s.bounded(ctx)
	if err != nil {
		return VelocityHealthy{}, err
	}
	defer cancel()
	lb, err := s.journalReader.Lease(owned)
	if err != nil || lb.Tenant != l.tenant || !hmac.Equal(lb.Namespace[:], s.journal.namespace) || lb.Epoch != l.epoch || lb.Owner != l.token || lb.Generation != l.generation || !lb.ExpiresAt.Equal(l.expires) {
		return VelocityHealthy{}, identity.InvalidInputError{Field: "velocity_activation"}
	}
	b, err := s.nativeVerifier.NativeConfirmation(owned, exported, publication, confirmation, native)
	if err != nil || b != s.closureBinding(l, cut.state) {
		return VelocityHealthy{}, identity.InvalidInputError{Field: "velocity_activation"}
	}
	candidate := &velocityHealthy{owner: s, lease: l, cut: cut.state}
	h, healthy, err := r.readHealthy(bounded, candidate, velocityHealthReconcile)
	if err != nil {
		return VelocityHealthy{}, velocityPublicationError(bounded, err)
	}
	if healthy {
		return h, nil
	}
	// Replay-only callbacks are used only before the transition. The final
	// primary transaction independently repeats all mutable checks under locks.
	if _, err := s.nativeVerifier.Confirmation(bounded, owned, exported, publication, confirmation); err != nil {
		return VelocityHealthy{}, velocityPublicationError(bounded, err)
	}
	activated, err := r.primaryPublicationClosure(bounded, lease, false, true, &velocityPublicationCheck{cut: cut.state, id: b.ID, activate: true})
	if err != nil {
		return VelocityHealthy{}, velocityPublicationError(bounded, err)
	}
	return VelocityHealthy{state: &velocityHealthy{owner: s, lease: l, cut: cut.state, activated: activated.state.activated}}, nil
}

// CheckHealthy rechecks exact generation/owner, original cut, sealed applied
// progress, recorded confirmation/activation and exclusive expiry by primary
// time. It never invokes replaying-only callbacks, renews metadata, inspects
// native state or treats subsequent journal history as restored replay progress.
// Unavailable primary/expired or altered state denies; no stale fallback exists.
func (r VelocityRecovery) CheckHealthy(ctx context.Context, healthy VelocityHealthy) error {
	if r.state == nil || healthy.state == nil || healthy.state.owner != r.state || healthy.state.activated.IsZero() {
		return identity.InvalidInputError{Field: "velocity_health"}
	}
	bounded, cancel, err := r.state.bounded(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	_, _, err = r.readHealthy(bounded, healthy.state, velocityHealthCurrent)
	return velocityPublicationError(bounded, err)
}

// InvalidateHealthy makes the exact activation unavailable without clearing
// counters, history, lockouts or original lease expiry. Retained metadata permits
// idempotent reconciliation of an ambiguous invalidation. Only the unchanged
// original generation/owner may invalidate, even after expiry; superseded custody
// cannot affect a successor. New recovery still requires authoritative lease
// expiry. This denial operation performs no native IO and cannot resurrect health.
func (r VelocityRecovery) InvalidateHealthy(ctx context.Context, healthy VelocityHealthy) error {
	if r.state == nil || healthy.state == nil || healthy.state.owner != r.state || healthy.state.activated.IsZero() {
		return identity.InvalidInputError{Field: "velocity_health"}
	}
	s, h := r.state, healthy.state
	bounded, cancel, err := s.bounded(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	tx, err := s.journal.pool.Raw().BeginTx(bounded, pgx.TxOptions{})
	if err != nil {
		return velocityPublicationError(bounded, identity.UnavailableError{})
	}
	defer velocityRollback(tx)
	if err := s.lock(bounded, tx, h.lease.tenant); err != nil {
		return velocityPublicationError(bounded, err)
	}
	if _, _, err := r.healthyRecord(bounded, tx, h, velocityHealthInvalidate); err != nil {
		return velocityPublicationError(bounded, err)
	}
	if _, err := tx.Exec(bounded, `UPDATE `+s.journal.schema+`.velocity_epochs SET state='unavailable',healthy_at=NULL WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, h.lease.tenant, s.journal.namespace, h.lease.epoch[:]); err != nil {
		return velocityPublicationError(bounded, identity.UnavailableError{})
	}
	return velocityPublicationError(bounded, tx.Commit(bounded))
}

type velocityHealthReadMode uint8

const (
	velocityHealthCurrent velocityHealthReadMode = iota
	velocityHealthReconcile
	velocityHealthInvalidate
)

func (r VelocityRecovery) readHealthy(ctx context.Context, h *velocityHealthy, mode velocityHealthReadMode) (VelocityHealthy, bool, error) {
	s := r.state
	tx, err := s.journal.pool.Raw().BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return VelocityHealthy{}, false, identity.UnavailableError{}
	}
	defer velocityRollback(tx)
	if err := s.journal.scopeLock(ctx, tx, h.lease.tenant, true); err != nil {
		return VelocityHealthy{}, false, err
	}
	result, healthy, err := r.healthyRecord(ctx, tx, h, mode)
	if err != nil {
		return VelocityHealthy{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return VelocityHealthy{}, false, identity.UnavailableError{}
	}
	return result, healthy, nil
}

// Called only inside a bounded transaction with the scoped advisory lock.
func (r VelocityRecovery) healthyRecord(ctx context.Context, tx pgx.Tx, h *velocityHealthy, mode velocityHealthReadMode) (VelocityHealthy, bool, error) {
	s, l, c := r.state, h.lease, h.cut
	var state, generation string
	var window, position int64
	var token, id, seal []byte
	var appliedGeneration *string
	var expires, from, through, started, snapshot, activated, confirmed *time.Time
	err := tx.QueryRow(ctx, `SELECT state,generation::text,lease_owner,lease_expires_at,maximum_window_us,replay_from,replay_through,journal_started_at,healthy_at,activated_at,publication_id,publication_confirmed_at,applied_generation::text,applied_position,applied_seal FROM `+s.journal.schema+`.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3 FOR SHARE`, l.tenant, s.journal.namespace, l.epoch[:]).Scan(&state, &generation, &token, &expires, &window, &from, &through, &started, &snapshot, &activated, &id, &confirmed, &appliedGeneration, &position, &seal)
	if err != nil {
		return VelocityHealthy{}, false, identity.UnavailableError{}
	}
	if state == "replaying" && mode == velocityHealthReconcile {
		return VelocityHealthy{}, false, nil
	}
	if state != "healthy" && (mode != velocityHealthInvalidate || state != "unavailable") {
		return VelocityHealthy{}, false, identity.UnavailableError{}
	}
	b := s.closureBinding(l, c)
	if generation != strconv.FormatUint(l.generation, 10) || !hmac.Equal(token, l.token[:]) || expires == nil || !expires.Equal(l.expires) || window != s.maximumWindow.Microseconds() || from == nil || !from.Equal(c.from) || through == nil || !through.Equal(c.through) || started == nil || !started.Equal(c.started) || activated == nil || confirmed == nil || !hmac.Equal(id, b.ID[:]) || confirmed.Before(c.through) || activated.Before(*confirmed) || !activated.Before(l.expires) || !h.activated.IsZero() && !activated.Equal(h.activated) || position != c.position || state == "healthy" && (snapshot == nil || !snapshot.Equal(c.through)) || state == "unavailable" && snapshot != nil {
		return VelocityHealthy{}, false, identity.UnavailableError{}
	}
	if appliedGeneration == nil {
		if position != 0 || len(seal) != 0 {
			return VelocityHealthy{}, false, identity.UnavailableError{}
		}
	} else if *appliedGeneration != generation || position <= 0 || !hmac.Equal(seal, s.appliedSeal(l, position)) {
		return VelocityHealthy{}, false, identity.UnavailableError{}
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil || activated.After(now) || mode != velocityHealthInvalidate && !now.Before(l.expires) {
		return VelocityHealthy{}, false, identity.UnavailableError{}
	}
	return VelocityHealthy{state: &velocityHealthy{owner: s, lease: l, cut: c, activated: *activated}}, state == "healthy", nil
}
