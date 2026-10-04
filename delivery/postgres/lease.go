package postgres

import (
	"context"
	"crypto/hmac"
	"errors"
	"time"

	"github.com/faustbrian/go-identity/delivery"
	"github.com/jackc/pgx/v5"
)

// leaseFence is private worker ownership, not user authorization or a public
// Queue extension. The full owned Queue must authenticate worker composition.
type leaseFence struct {
	TenantID   delivery.TenantID
	IntentID   delivery.IntentID
	WorkerID   string
	Generation uint32
}

func (f leaseFence) completion() delivery.CompleteRequest {
	return delivery.CompleteRequest{TenantID: f.TenantID, IntentID: f.IntentID, WorkerID: f.WorkerID, Generation: f.Generation}
}

// Renew extends only live ownership; it cannot reset the original attempt's
// one-minute maximum lifetime, credential expiry, generation or retry policy.
// Database row locks serialize heartbeat, completion and lost-lease sweeps.
// The returned deadline is authoritative only after acknowledged commit. No
// automatic goroutine or provider invocation is created by this method.
func (s *attemptStore) Renew(ctx context.Context, f leaseFence) (time.Time, error) {
	if f.completion().Validate() != nil {
		return time.Time{}, delivery.ErrInvalidInput
	}
	w, stop, err := s.bounded(ctx)
	if err != nil {
		return time.Time{}, err
	}
	defer stop()
	tx, err := s.pool.Begin(w)
	if err != nil {
		return time.Time{}, attemptFailure(w, err)
	}
	defer rollbackAttempt(tx)
	var state string
	var expiry time.Time
	err = tx.QueryRow(w, `SELECT state,expires_at FROM identity.delivery_intents WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 FOR UPDATE`, s.deployment, string(f.TenantID), string(f.IntentID)).Scan(&state, &expiry)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && state != "submitted" {
		return time.Time{}, delivery.ErrConflict
	}
	if err != nil {
		return time.Time{}, attemptFailure(w, err)
	}
	var lease, now time.Time
	var digest []byte
	err = tx.QueryRow(w, `SELECT lease_until,clock_timestamp(),policy_digest FROM identity.delivery_processing WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND generation=$4 AND lease_owner=$5 AND NOT cancel_requested FOR UPDATE`, s.deployment, string(f.TenantID), string(f.IntentID), int64(f.Generation), f.WorkerID).Scan(&lease, &now, &digest)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (!lease.After(now) || !expiry.After(now) || !hmac.Equal(digest, s.policyDigest[:])) {
		return time.Time{}, delivery.ErrConflict
	}
	if err != nil {
		return time.Time{}, attemptFailure(w, err)
	}
	var started time.Time
	err = tx.QueryRow(w, `SELECT started_at FROM identity.delivery_attempt_history WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND generation=$4 AND worker=$5 AND outcome IS NULL FOR UPDATE`, s.deployment, string(f.TenantID), string(f.IntentID), int64(f.Generation), f.WorkerID).Scan(&started)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, delivery.ErrConflict
	}
	if err != nil {
		return time.Time{}, attemptFailure(w, err)
	}
	cap := minTime(expiry, started.Add(time.Minute))
	if !cap.After(now) || lease.After(cap) {
		return time.Time{}, delivery.ErrConflict
	}
	until := minTime(now.Add(s.leaseDuration), cap).Truncate(time.Microsecond)
	if until.Before(lease) {
		until = lease
	}
	// Recheck wall-clock validity at the actual write after all lock waits.
	// A stale heartbeat must not resurrect a lease even within one transaction.
	tag, err := tx.Exec(w, `UPDATE identity.delivery_processing SET lease_until=$6 WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND generation=$4 AND lease_owner=$5 AND lease_until>clock_timestamp() AND $6::timestamptz>clock_timestamp() AND NOT cancel_requested`, s.deployment, string(f.TenantID), string(f.IntentID), int64(f.Generation), f.WorkerID, until)
	if err != nil {
		return time.Time{}, attemptFailure(w, err)
	}
	if tag.RowsAffected() != 1 {
		return time.Time{}, delivery.ErrConflict
	}
	if _, err := tx.Exec(w, `UPDATE identity.delivery_attempt_history SET lease_until=$6 WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND generation=$4 AND worker=$5 AND outcome IS NULL`, s.deployment, string(f.TenantID), string(f.IntentID), int64(f.Generation), f.WorkerID, until); err != nil {
		return time.Time{}, attemptFailure(w, err)
	}
	if err := tx.Commit(w); err != nil {
		return time.Time{}, delivery.ErrOutcomeUnknown
	}
	return until.UTC(), nil
}

// Release relinquishes a possibly invoked attempt conservatively as unknown,
// never as transient failure or retry authority. If the worker can prove it
// never invoked Send, it must instead use Complete with Invoked=false. Exact
// repeated releases recover the recorded result without a new provider call.
// The original database start supplies stable evidence identity on replay,
// not a caller-controlled clock or fresh observation of a provider outcome.
func (s *attemptStore) Release(ctx context.Context, f leaseFence) (delivery.CompleteResult, error) {
	q := f.completion()
	if q.Validate() != nil {
		return delivery.CompleteResult{}, delivery.ErrInvalidInput
	}
	w, stop, err := s.bounded(ctx)
	if err != nil {
		return delivery.CompleteResult{}, err
	}
	defer stop()
	var started time.Time
	err = s.pool.QueryRow(w, `SELECT started_at FROM identity.delivery_attempt_history WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND generation=$4 AND worker=$5`, s.deployment, string(f.TenantID), string(f.IntentID), int64(f.Generation), f.WorkerID).Scan(&started)
	if errors.Is(err, pgx.ErrNoRows) {
		return delivery.CompleteResult{}, delivery.ErrConflict
	}
	if err != nil {
		return delivery.CompleteResult{}, attemptFailure(w, err)
	}
	q.Invoked = true
	q.Result = delivery.DeliveryResult{State: delivery.StateOutcomeUnknown, ObservedAt: started.UTC()}
	return s.Complete(w, q)
}
