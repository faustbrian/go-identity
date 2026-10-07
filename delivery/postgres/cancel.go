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
	if err := validateCancellation(q, subject); err != nil {
		return delivery.CancelResult{}, err
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
	out, err := s.cancelIn(w, cancellationSQL{
		scan: func(ctx context.Context, sql string, args []any, dest ...any) error {
			return tx.QueryRow(ctx, sql, args...).Scan(dest...)
		},
		exec: func(ctx context.Context, sql string, args ...any) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		},
	}, q, subject, tracked)
	if err != nil {
		return delivery.CancelResult{}, err
	}
	if err := tx.Commit(w); err != nil {
		return delivery.CancelResult{}, delivery.ErrOutcomeUnknown
	}
	return out, nil
}

func validateCancellation(q delivery.CancelRequest, subject string) error {
	if !safeID(string(q.TenantID), false) || !safeID(subject, false) || len(q.IntentID) != 64 || len(q.Reason) < 1 || len(q.Reason) > 256 || !utf8.ValidString(q.Reason) {
		return delivery.ErrInvalidInput
	}
	intent, err := hex.DecodeString(string(q.IntentID))
	if err != nil || hex.EncodeToString(intent) != string(q.IntentID) {
		return delivery.ErrInvalidInput
	}
	return nil
}

// cancellationSQL borrows serial SQL access from the effect's transaction owner.
// It deliberately has no Begin, Commit or Rollback operation. The original Work
// adapter can provide bounded cursor access without exposing a raw driver.
type cancellationSQL struct {
	scan func(context.Context, string, []any, ...any) error
	exec func(context.Context, string, ...any) error
}

// cancelIn stages delivery effects only. Its result is provisional until the
// caller commits all protected policy/audit/lifecycle effects. No transaction,
// callback to a provider, independent deadline or retry is created here.
func (s *attemptStore) cancelIn(w context.Context, sql cancellationSQL, q delivery.CancelRequest, subject string, tracked bool) (delivery.CancelResult, error) {
	if s == nil || !safeID(s.deployment, false) || w == nil || sql.scan == nil || sql.exec == nil || validateCancellation(q, subject) != nil {
		return delivery.CancelResult{}, delivery.ErrInvalidInput
	}
	if err := w.Err(); err != nil {
		return delivery.CancelResult{}, err
	}
	var snapshot deliveryStatus
	var aad []byte
	stopColumn := "NULL::text"
	if tracked {
		stopColumn = "local_stop_state"
	}
	err := sql.scan(w, `SELECT state,no_op,expires_at<=clock_timestamp(),binding_aad,`+stopColumn+` FROM identity.delivery_intents WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND subject_id=$4 FOR UPDATE`, []any{s.deployment, string(q.TenantID), string(q.IntentID), subject}, &snapshot.state, &snapshot.noop, &snapshot.expired, &aad, &snapshot.localStop)
	if errors.Is(err, pgx.ErrNoRows) {
		return delivery.CancelResult{}, delivery.ErrNotFound
	}
	if err != nil {
		return delivery.CancelResult{}, attemptFailure(w, err)
	}
	b, err := decodeUserBinding(aad, s.deployment, string(q.TenantID), string(q.IntentID), subject)
	if err != nil {
		return delivery.CancelResult{}, err
	}
	if s.retainedVersion != 0 && b.PolicyVersion != s.retainedVersion {
		return delivery.CancelResult{}, delivery.ErrConflict
	}
	var policy []byte
	err = sql.scan(w, `SELECT generation,policy_digest FROM identity.delivery_processing WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 FOR UPDATE`, []any{s.deployment, string(q.TenantID), string(q.IntentID)}, &snapshot.generation, &policy)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return delivery.CancelResult{}, attemptFailure(w, err)
	}
	if snapshot.generation != int64(q.ExpectedGeneration) || snapshot.generation > 0 && !hmac.Equal(policy, s.policyDigest[:]) {
		return delivery.CancelResult{}, delivery.ErrConflict
	}
	if snapshot.generation > 0 {
		// Borrowed Work has a closed nullable-int64 scan profile, not nullable
		// int16. Preserve null outcome and bound conversion before classification.
		var outcome *int64
		err = sql.scan(w, `SELECT outcome::bigint,provider_reference_digest IS NOT NULL FROM identity.delivery_attempt_history WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND generation=$4`, []any{s.deployment, string(q.TenantID), string(q.IntentID), snapshot.generation}, &outcome, &snapshot.reference)
		if errors.Is(err, pgx.ErrNoRows) {
			return delivery.CancelResult{}, delivery.ErrConflict
		}
		if err != nil {
			return delivery.CancelResult{}, attemptFailure(w, err)
		}
		if outcome != nil {
			if *outcome < 1 || *outcome > 12 {
				return delivery.CancelResult{}, delivery.ErrUnavailable
			}
			bounded := int16(*outcome)
			snapshot.outcome = &bounded
		}
		if s.receiptTracking {
			if _, err := loadReceiptProjection(w, sql, s.deployment, q.TenantID, q.IntentID, &snapshot); err != nil {
				return delivery.CancelResult{}, err
			}
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
		if err := sql.exec(w, `UPDATE identity.delivery_intents SET state=$4,ciphertext=CASE WHEN $5 THEN NULL ELSE ciphertext END,envelope_key_id=CASE WHEN $5 THEN NULL ELSE envelope_key_id END,payload_erased_at=CASE WHEN $5 THEN COALESCE(payload_erased_at,clock_timestamp()) ELSE payload_erased_at END WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`, s.deployment, string(q.TenantID), string(q.IntentID), state, erase); err != nil {
			return delivery.CancelResult{}, attemptFailure(w, err)
		}
	}
	if snapshot.generation > 0 && (out.LocalCancelled || erase) {
		if err := sql.exec(w, `UPDATE identity.delivery_processing SET cancel_requested=true,next_attempt_at=NULL WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND generation=$4`, s.deployment, string(q.TenantID), string(q.IntentID), snapshot.generation); err != nil {
			return delivery.CancelResult{}, attemptFailure(w, err)
		}
	}
	if tracked && snapshot.noop && snapshot.localStop == nil {
		checkpoint := "cancelled"
		if out.State == delivery.StateExpired {
			checkpoint = "expired"
		}
		if err := sql.exec(w, `UPDATE identity.delivery_intents SET local_stop_state=$4,local_stop_at=clock_timestamp() WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`, s.deployment, string(q.TenantID), string(q.IntentID), checkpoint); err != nil {
			return delivery.CancelResult{}, attemptFailure(w, err)
		}
	}
	return out, nil
}
