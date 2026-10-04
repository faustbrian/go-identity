package postgres

import (
	"context"
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"unicode/utf8"

	"github.com/faustbrian/go-identity/delivery"
	"github.com/jackc/pgx/v5"
)

// cancel is a private delivery-effect primitive, not an authenticated Queue
// command. Public composition must own current policy, protected audit and
// original command replay before exposing it. The reason is shape-checked but
// never persisted here: the original command audit owns operator metadata.
// All writers lock intent before processing. Cancellation keeps a live worker's
// fence so attributable in-flight completion can still settle the outcome;
// it cannot renew that fence or authorize another invocation.
func (s *attemptStore) cancel(ctx context.Context, q delivery.CancelRequest, subject string) (delivery.CancelResult, error) {
	return s.cancelMode(ctx, q, subject, false)
}

// The selected forward profile preserves a no-op's exact local-stop result.
// Public policy/audit/original-command composition remains the caller's owner;
// neither private variant is an authenticated endpoint or full Queue.Cancel.
func (s *attemptStore) cancelTracked(ctx context.Context, q delivery.CancelRequest, subject string) (delivery.CancelResult, error) {
	return s.cancelMode(ctx, q, subject, true)
}

func (s *attemptStore) cancelMode(ctx context.Context, q delivery.CancelRequest, subject string, tracked bool) (delivery.CancelResult, error) {
	if !safeID(string(q.TenantID), false) || !safeID(subject, false) || len(q.IntentID) != 64 || len(q.Reason) < 1 || len(q.Reason) > 256 || !utf8.ValidString(q.Reason) {
		return delivery.CancelResult{}, delivery.ErrInvalidInput
	}
	intent, err := hex.DecodeString(string(q.IntentID))
	if err != nil || hex.EncodeToString(intent) != string(q.IntentID) {
		return delivery.CancelResult{}, delivery.ErrInvalidInput
	}
	w, stop, err := s.bounded(ctx)
	if err != nil {
		return delivery.CancelResult{}, err
	}
	defer stop()
	tx, err := s.pool.Begin(w)
	if err != nil {
		return delivery.CancelResult{}, attemptFailure(w, err)
	}
	defer rollbackAttempt(tx)
	var snapshot deliveryStatus
	var aad []byte
	stopColumn := "NULL::text"
	if tracked {
		stopColumn = "local_stop_state"
	}
	err = tx.QueryRow(w, `SELECT state,no_op,expires_at<=clock_timestamp(),binding_aad,`+stopColumn+` FROM identity.delivery_intents WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND subject_id=$4 FOR UPDATE`, s.deployment, string(q.TenantID), string(q.IntentID), subject).Scan(&snapshot.state, &snapshot.noop, &snapshot.expired, &aad, &snapshot.localStop)
	if errors.Is(err, pgx.ErrNoRows) {
		return delivery.CancelResult{}, delivery.ErrNotFound
	}
	if err != nil {
		return delivery.CancelResult{}, attemptFailure(w, err)
	}
	b, err := decodeBinding(aad)
	if err != nil {
		return delivery.CancelResult{}, err
	}
	if s.retainedVersion != 0 && b.PolicyVersion != s.retainedVersion {
		return delivery.CancelResult{}, delivery.ErrConflict
	}
	var policy []byte
	err = tx.QueryRow(w, `SELECT generation,policy_digest FROM identity.delivery_processing WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 FOR UPDATE`, s.deployment, string(q.TenantID), string(q.IntentID)).Scan(&snapshot.generation, &policy)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return delivery.CancelResult{}, attemptFailure(w, err)
	}
	if snapshot.generation != int64(q.ExpectedGeneration) || snapshot.generation > 0 && !hmac.Equal(policy, s.policyDigest[:]) {
		return delivery.CancelResult{}, delivery.ErrConflict
	}
	if snapshot.generation > 0 {
		err = tx.QueryRow(w, `SELECT outcome,provider_reference_digest IS NOT NULL FROM identity.delivery_attempt_history WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND generation=$4`, s.deployment, string(q.TenantID), string(q.IntentID), snapshot.generation).Scan(&snapshot.outcome, &snapshot.reference)
		if errors.Is(err, pgx.ErrNoRows) {
			return delivery.CancelResult{}, delivery.ErrConflict
		}
		if err != nil {
			return delivery.CancelResult{}, attemptFailure(w, err)
		}
	}
	// Submitted may have a still-live invocation or acknowledged acceptance;
	// either requires provider reconciliation, never local remote-success claims.
	var out delivery.CancelResult
	state := snapshot.state
	erase := false
	switch state {
	case "planned", "retry-wait":
		observed, err := snapshot.result()
		if err != nil {
			return delivery.CancelResult{}, err
		}
		state, erase = "cancelled", true
		out = delivery.CancelResult{State: delivery.StateCancelled, LocalCancelled: true}
		if observed.State == delivery.StateExpired {
			state = "expired"
			out = delivery.CancelResult{State: delivery.StateExpired}
		}
	case "submitted", "outcome-unknown":
		if snapshot.generation == 0 {
			return delivery.CancelResult{}, delivery.ErrConflict
		}
		state = "outcome-unknown"
		out = delivery.CancelResult{State: delivery.StateOutcomeUnknown, LocalCancelled: true}
	case "cancelled":
		// No-op physical cancellation is private; expiry has the same effective
		// result as a never-submitted sendable intent.
		out = delivery.CancelResult{State: delivery.StateCancelled, LocalCancelled: true}
		if snapshot.noop && snapshot.expired {
			out = delivery.CancelResult{State: delivery.StateExpired}
		}
		if snapshot.localStop != nil {
			observed, err := snapshot.result()
			if err != nil {
				return delivery.CancelResult{}, err
			}
			out = delivery.CancelResult{State: observed.State, LocalCancelled: observed.State == delivery.StateCancelled}
		}
	default:
		observed, err := snapshot.result()
		if err != nil || !observed.Terminal {
			return delivery.CancelResult{}, delivery.ErrUnavailable
		}
		out.State = observed.State
	}
	if state != snapshot.state || erase {
		if _, err := tx.Exec(w, `UPDATE identity.delivery_intents SET state=$4,ciphertext=CASE WHEN $5 THEN NULL ELSE ciphertext END,envelope_key_id=CASE WHEN $5 THEN NULL ELSE envelope_key_id END,payload_erased_at=CASE WHEN $5 THEN COALESCE(payload_erased_at,clock_timestamp()) ELSE payload_erased_at END WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`, s.deployment, string(q.TenantID), string(q.IntentID), state, erase); err != nil {
			return delivery.CancelResult{}, attemptFailure(w, err)
		}
	}
	if snapshot.generation > 0 && (out.LocalCancelled || erase) {
		if _, err := tx.Exec(w, `UPDATE identity.delivery_processing SET cancel_requested=true,next_attempt_at=NULL WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND generation=$4`, s.deployment, string(q.TenantID), string(q.IntentID), snapshot.generation); err != nil {
			return delivery.CancelResult{}, attemptFailure(w, err)
		}
	}
	if tracked && snapshot.noop && snapshot.localStop == nil {
		checkpoint := "cancelled"
		if out.State == delivery.StateExpired {
			checkpoint = "expired"
		}
		if _, err := tx.Exec(w, `UPDATE identity.delivery_intents SET local_stop_state=$4,local_stop_at=clock_timestamp() WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`, s.deployment, string(q.TenantID), string(q.IntentID), checkpoint); err != nil {
			return delivery.CancelResult{}, attemptFailure(w, err)
		}
	}
	if err := tx.Commit(w); err != nil {
		return delivery.CancelResult{}, delivery.ErrOutcomeUnknown
	}
	return out, nil
}
