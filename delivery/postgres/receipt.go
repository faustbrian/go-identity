package postgres

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/faustbrian/go-identity/delivery"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Private borrowed effect phase only. The public composition must authenticate
// callback evidence before this call, authorize current exact scope, enlist
// audit/lifecycle under the existing kernel coordinator and recover its original
// command. NamespaceKey must be that deployment's immutable admission key.
// This primitive has no pool, deadline, provider, command journal or transaction
// closure; results remain provisional until its caller commits.
type receiptStore struct {
	deployment   string
	namespaceKey [32]byte
}

func (s *receiptStore) digests(q delivery.ReceiptRecordRequest) ([32]byte, [32]byte) {
	eventWire, _ := json.Marshal([]string{string(q.TenantID), q.Provider, q.ProviderEventID})
	defer clear(eventWire)
	event := custodyMAC(s.namespaceKey, "identity-delivery-provider-event-v1", []byte(s.deployment), eventWire)
	evidenceWire, _ := json.Marshal([]string{string(q.IntentID), strconv.FormatUint(uint64(q.Generation), 10), strconv.FormatUint(uint64(q.Status), 10), q.ObservedAt.UTC().Format(time.RFC3339Nano)})
	defer clear(evidenceWire)
	evidence := custodyMAC(s.namespaceKey, "identity-delivery-provider-evidence-v1", event[:], evidenceWire)
	// Command idempotency is owned by the kernel; the same authenticated event
	// may arrive under a new command without becoming a second provider effect.
	return event, evidence
}

func (s *receiptStore) recordIn(ctx context.Context, sql cancellationSQL, q delivery.ReceiptRecordRequest, subject string) (delivery.ReceiptRecordResult, error) {
	if ctx == nil || s == nil || !safeID(s.deployment, false) || s.namespaceKey == ([32]byte{}) || sql.scan == nil || sql.exec == nil || q.Validate() != nil || validateCancellation(delivery.CancelRequest{TenantID: q.TenantID, IntentID: q.IntentID, Reason: "provider-receipt"}, subject) != nil {
		return delivery.ReceiptRecordResult{}, delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return delivery.ReceiptRecordResult{}, err
	}
	var current deliveryStatus
	var provider string
	err := sql.scan(ctx, `SELECT state,provider,no_op FROM identity.delivery_intents WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND subject_id=$4 FOR UPDATE`, []any{s.deployment, string(q.TenantID), string(q.IntentID), subject}, &current.state, &provider, &current.noop)
	if errors.Is(err, pgx.ErrNoRows) {
		return delivery.ReceiptRecordResult{}, delivery.ErrNotFound
	}
	if err != nil {
		return delivery.ReceiptRecordResult{}, attemptFailure(ctx, err)
	}
	if provider != q.Provider || current.noop {
		return delivery.ReceiptRecordResult{}, delivery.ErrForbidden
	}
	event, evidence := s.digests(q)
	var prior []byte
	var recordedState int64
	err = sql.scan(ctx, `SELECT evidence_digest,result_state::bigint FROM identity.delivery_receipts WHERE deployment=$1 AND tenant_id=$2 AND provider=$3 AND event_digest=$4`, []any{s.deployment, string(q.TenantID), q.Provider, event[:]}, &prior, &recordedState)
	if err == nil {
		if !hmac.Equal(prior, evidence[:]) {
			return delivery.ReceiptRecordResult{}, delivery.ErrConflict
		}
		if recordedState < 2 || recordedState > 12 {
			return delivery.ReceiptRecordResult{}, delivery.ErrUnavailable
		}
		return delivery.ReceiptRecordResult{Deduplicated: true, State: delivery.DeliveryState(recordedState)}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return delivery.ReceiptRecordResult{}, attemptFailure(ctx, err)
	}
	// Serialize against all worker/cancellation writers in the same intent->
	// processing lock order. Replay above never re-applies an old generation.
	err = sql.scan(ctx, `SELECT generation,lease_owner IS NOT NULL AND lease_until>clock_timestamp() FROM identity.delivery_processing WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 FOR UPDATE`, []any{s.deployment, string(q.TenantID), string(q.IntentID)}, &current.generation, &current.live)
	if errors.Is(err, pgx.ErrNoRows) {
		return delivery.ReceiptRecordResult{}, delivery.ErrConflict
	}
	if err != nil {
		return delivery.ReceiptRecordResult{}, attemptFailure(ctx, err)
	}
	if current.generation != int64(q.Generation) {
		return delivery.ReceiptRecordResult{}, delivery.ErrConflict
	}
	var outcome *int64
	err = sql.scan(ctx, `SELECT outcome::bigint,provider_reference_digest IS NOT NULL FROM identity.delivery_attempt_history WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND generation=$4`, []any{s.deployment, string(q.TenantID), string(q.IntentID), current.generation}, &outcome, &current.reference)
	if errors.Is(err, pgx.ErrNoRows) {
		return delivery.ReceiptRecordResult{}, delivery.ErrConflict
	}
	if err != nil {
		return delivery.ReceiptRecordResult{}, attemptFailure(ctx, err)
	}
	if outcome != nil {
		if *outcome < 1 || *outcome > 12 {
			return delivery.ReceiptRecordResult{}, delivery.ErrUnavailable
		}
		value := int16(*outcome)
		current.outcome = &value
	}
	status, err := current.result()
	if err != nil {
		return delivery.ReceiptRecordResult{}, err
	}
	snapshot := delivery.ReceiptSnapshot{State: status.State, Generation: q.Generation}
	var observed *time.Time
	var receiptState int64
	err = sql.scan(ctx, `SELECT result_state::bigint,observed_at FROM identity.delivery_receipts WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND generation=$4 ORDER BY observed_at DESC NULLS LAST,event_digest LIMIT 1`, []any{s.deployment, string(q.TenantID), string(q.IntentID), current.generation}, &receiptState, &observed)
	if err == nil {
		if receiptState < 2 || receiptState > 12 {
			return delivery.ReceiptRecordResult{}, delivery.ErrUnavailable
		}
		if observed != nil {
			snapshot.ObservedAt = observed.UTC()
		}
		// Do not overwrite a worker's newer terminal state or cancellation's
		// unknown checkpoint with an earlier accepted receipt projection.
		if current.state == "submitted" && receiptState == int64(delivery.StateAccepted) || current.state == "rejected" && receiptState == int64(delivery.StateBounced) {
			snapshot.State = delivery.DeliveryState(receiptState)
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return delivery.ReceiptRecordResult{}, attemptFailure(ctx, err)
	}
	// PostgreSQL's microsecond timestamp profile must own comparison precision,
	// not accidentally round two provider observations into a different order.
	// Keep the exact authenticated time in the fingerprint, but fail closed on
	// conflicting states that normalize to the same stored instant.
	normalized := q
	normalized.ObservedAt = q.ObservedAt.UTC().Truncate(time.Microsecond)
	decision, err := delivery.DecideReceipt(snapshot, normalized)
	if err != nil {
		return delivery.ReceiptRecordResult{}, err
	}
	if decision.Advanced || decision.ErasePayload {
		state := current.state
		if decision.Advanced {
			state = durableCompletionState(decision.State)
		}
		if state == "" {
			return delivery.ReceiptRecordResult{}, delivery.ErrUnavailable
		}
		if err := sql.exec(ctx, `UPDATE identity.delivery_intents SET state=$4,ciphertext=CASE WHEN $5 THEN NULL ELSE ciphertext END,envelope_key_id=CASE WHEN $5 THEN NULL ELSE envelope_key_id END,payload_erased_at=CASE WHEN $5 THEN COALESCE(payload_erased_at,clock_timestamp()) ELSE payload_erased_at END WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`, s.deployment, string(q.TenantID), string(q.IntentID), state, decision.ErasePayload); err != nil {
			return delivery.ReceiptRecordResult{}, attemptFailure(ctx, err)
		}
		// Definitive provider evidence fences competing worker completion and
		// future retries. Unknown evidence keeps an original live worker fence;
		// neither path renews the lease or performs any external invocation.
		definitive := decision.State == delivery.StateAccepted || decision.ErasePayload
		if err := sql.exec(ctx, `UPDATE identity.delivery_processing SET next_attempt_at=NULL,lease_owner=CASE WHEN $5 THEN NULL ELSE lease_owner END,lease_until=CASE WHEN $5 THEN NULL ELSE lease_until END WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND generation=$4`, s.deployment, string(q.TenantID), string(q.IntentID), current.generation, definitive); err != nil {
			return delivery.ReceiptRecordResult{}, attemptFailure(ctx, err)
		}
	}
	var watermark any
	if !decision.ObservedAt.IsZero() {
		watermark = decision.ObservedAt
	}
	if err := sql.exec(ctx, `INSERT INTO identity.delivery_receipts(deployment,tenant_id,provider,event_digest,evidence_digest,effect_id,generation,result_state,advanced,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, s.deployment, string(q.TenantID), q.Provider, event[:], evidence[:], string(q.IntentID), current.generation, int16(decision.State), decision.Advanced, watermark); err != nil {
		var collision *pgconn.PgError
		if errors.As(err, &collision) && collision.Code == "23505" {
			return delivery.ReceiptRecordResult{}, delivery.ErrConflict
		}
		return delivery.ReceiptRecordResult{}, attemptFailure(ctx, err)
	}
	return delivery.ReceiptRecordResult{Advanced: decision.Advanced, State: decision.State}, nil
}
