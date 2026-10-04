package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// attemptStore is an owned delivery-domain processing seam, not the public
// Queue or application-supplied orchestration. Its pool is borrowed primary
// authority; it never closes the pool or invokes a provider. All mutable state
// is owned by PostgreSQL row locks, not this concurrently readable holder.
type attemptStore struct {
	receiptTracking                bool
	pool                           *pgxpool.Pool
	deployment                     string
	codec                          *payloadCodec
	policy                         delivery.CompletionPolicy
	maximumDuration, leaseDuration time.Duration
	attempts                       uint8
	policyDigest                   [32]byte
	retainedVersion                uint64
	providerVersion                uint64
}

func (attemptStore) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("delivery.postgres(redacted)"))
}
func (attemptStore) LogValue() slog.Value { return slog.StringValue("delivery.postgres(redacted)") }

func newAttemptStore(pool *pgxpool.Pool, deployment string, codec *payloadCodec, config delivery.Config, timeout time.Duration) (*attemptStore, error) {
	if pool == nil || !safeID(deployment, false) || codec == nil || codec.service == nil || len(codec.keys) == 0 || timeout < time.Second || timeout > 30*time.Second {
		return nil, delivery.ErrInvalidInput
	}
	policy, err := delivery.NewCompletionPolicy(config)
	if err != nil {
		return nil, err
	}
	return &attemptStore{pool: pool, deployment: deployment, codec: codec, policy: policy, maximumDuration: timeout, leaseDuration: config.SenderTimeout + timeout, attempts: config.Attempts, policyDigest: attemptPolicyDigest(config, timeout)}, nil
}

// Record policy identity at first invocation so a restart cannot reinterpret
// an existing attempt using different retry or lease settings. These bounded
// fields are non-secret; the digest is configuration identity, not authority.
func attemptPolicyDigest(c delivery.Config, timeout time.Duration) [32]byte {
	wire := append([]byte("identity-delivery-attempt-policy-v1"), c.Attempts, c.SenderConcurrency, byte(len(c.BackoffCeilings)))
	if c.Production {
		wire = append(wire, 1)
	} else {
		wire = append(wire, 0)
	}
	for _, v := range append([]time.Duration{c.SenderTimeout, c.DedupeTTL, timeout}, c.BackoffCeilings...) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(v))
		wire = append(wire, size[:]...)
	}
	return sha256.Sum256(wire)
}

func (s *attemptStore) bounded(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil || s == nil || s.pool == nil || s.codec == nil || s.maximumDuration <= 0 {
		return nil, nil, delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	w, stop := context.WithTimeout(ctx, s.maximumDuration)
	return w, stop, nil
}

func attemptFailure(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return delivery.ErrUnavailable
}

func rollbackAttempt(tx pgx.Tx) {
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	_ = tx.Rollback(ctx)
}

// Expiry erases bearer custody without asserting a provider outcome. Only
// never-submitted/authoritatively retryable effects become locally expired.
func (s *attemptStore) sweepExpired(ctx context.Context, tx pgx.Tx, tenant delivery.TenantID) error {
	rows, err := tx.Query(ctx, `WITH due AS (SELECT effect_id FROM identity.delivery_intents WHERE deployment=$1 AND tenant_id=$2 AND ciphertext IS NOT NULL AND expires_at<=clock_timestamp() AND state IN ('planned','retry-wait','submitted','outcome-unknown') ORDER BY expires_at,effect_id LIMIT 100 FOR UPDATE SKIP LOCKED) UPDATE identity.delivery_intents i SET state=CASE WHEN i.state IN ('planned','retry-wait') THEN 'expired' ELSE i.state END,ciphertext=NULL,envelope_key_id=NULL,payload_erased_at=clock_timestamp() FROM due WHERE i.deployment=$1 AND i.tenant_id=$2 AND i.effect_id=due.effect_id RETURNING i.effect_id`, s.deployment, string(tenant))
	if err != nil {
		return err
	}
	ids := make([]string, 0, 100)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := tx.Exec(ctx, `UPDATE identity.delivery_processing SET next_attempt_at=NULL WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`, s.deployment, string(tenant), id); err != nil {
			return err
		}
	}
	return nil
}

// sweepLost marks a bounded set of expired invocation leases ambiguous, not
// failed. It never returns them to retry admission. Lock intent before its
// processing row, the same order used by Claim and Complete.
func (s *attemptStore) sweepLost(ctx context.Context, tx pgx.Tx, tenant delivery.TenantID) error {
	rows, err := tx.Query(ctx, `SELECT i.effect_id,p.generation FROM identity.delivery_intents i JOIN identity.delivery_processing p USING(deployment,tenant_id,effect_id) WHERE i.deployment=$1 AND i.tenant_id=$2 AND i.state='submitted' AND p.lease_until<=clock_timestamp() ORDER BY p.lease_until,i.effect_id LIMIT 100 FOR UPDATE OF i SKIP LOCKED`, s.deployment, string(tenant))
	if err != nil {
		return err
	}
	type fence struct {
		id         string
		generation int64
	}
	batch := make([]fence, 0, 100)
	for rows.Next() {
		var f fence
		if err := rows.Scan(&f.id, &f.generation); err != nil {
			rows.Close()
			return err
		}
		batch = append(batch, f)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, f := range batch {
		// The join's processing snapshot may predate the intent lock (for
		// example an acceptance just cleared its lease). Re-read the exact
		// processing fence after acquiring the intent; never retire stale
		// joined lease evidence or a renewed/replaced generation.
		var current int64
		err := tx.QueryRow(ctx, `SELECT generation FROM identity.delivery_processing WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND generation=$4 AND lease_owner IS NOT NULL AND lease_until<=clock_timestamp() FOR UPDATE`, s.deployment, string(tenant), f.id, f.generation).Scan(&current)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE identity.delivery_intents SET state='outcome-unknown' WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`, s.deployment, string(tenant), f.id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE identity.delivery_processing SET lease_owner=NULL,lease_until=NULL WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`, s.deployment, string(tenant), f.id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE identity.delivery_attempt_history SET outcome=$5,completed_at=clock_timestamp() WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND generation=$4 AND outcome IS NULL`, s.deployment, string(tenant), f.id, f.generation, int16(delivery.StateOutcomeUnknown)); err != nil {
			return err
		}
	}
	return nil
}

// Claim commits the invocation fence before opening sensitive custody. Any
// decrypt/cancellation failure records this worker's no-invocation evidence
// under the same generation. A lost claim acknowledgement never permits Send.
func (s *attemptStore) Claim(ctx context.Context, q delivery.ClaimRequest) (delivery.ClaimResult, error) {
	if q.Validate() != nil {
		return delivery.ClaimResult{}, delivery.ErrInvalidInput
	}
	w, stop, err := s.bounded(ctx)
	if err != nil {
		return delivery.ClaimResult{}, err
	}
	defer stop()
	tx, err := s.pool.Begin(w)
	if err != nil {
		return delivery.ClaimResult{}, attemptFailure(w, err)
	}
	defer rollbackAttempt(tx)
	if err := s.sweepExpired(w, tx, q.TenantID); err != nil {
		return delivery.ClaimResult{}, attemptFailure(w, err)
	}
	if err := s.sweepLost(w, tx, q.TenantID); err != nil {
		return delivery.ClaimResult{}, attemptFailure(w, err)
	}
	var aad []byte
	var envelope identitypostgres.DeliveryEnvelope
	var generation int64
	var attempt int16
	var retainedPolicy []byte
	err = tx.QueryRow(w, `SELECT i.binding_aad,i.effect_index,i.envelope_key_id,i.ciphertext,COALESCE(p.generation,0),COALESCE(p.attempt_number,0),p.policy_digest FROM identity.delivery_intents i LEFT JOIN identity.delivery_processing p USING(deployment,tenant_id,effect_id) WHERE i.deployment=$1 AND i.tenant_id=$2 AND ($3::numeric=0 OR i.policy_version=$3::numeric) AND ($4::numeric=0 OR i.provider_version=$4::numeric) AND NOT i.no_op AND i.expires_at>clock_timestamp() AND ((i.state='planned' AND p.generation IS NULL) OR (i.state='retry-wait' AND p.next_attempt_at<=clock_timestamp() AND p.lease_owner IS NULL)) ORDER BY i.created_at,i.effect_id LIMIT 1 FOR UPDATE OF i SKIP LOCKED`, s.deployment, string(q.TenantID), strconv.FormatUint(s.retainedVersion, 10), strconv.FormatUint(s.providerVersion, 10)).Scan(&aad, &envelope.EffectIndex, &envelope.KeyID, &envelope.Ciphertext, &generation, &attempt, &retainedPolicy)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := tx.Commit(w); err != nil {
			return delivery.ClaimResult{}, delivery.ErrOutcomeUnknown
		}
		return delivery.ClaimResult{}, nil
	}
	if err != nil {
		return delivery.ClaimResult{}, attemptFailure(w, err)
	}
	defer clear(envelope.Ciphertext)
	b, err := s.codec.restore(aad, envelope)
	if err != nil {
		return delivery.ClaimResult{}, err
	}
	if b.Deployment != s.deployment || string(b.Command.TenantID) != string(q.TenantID) || generation >= 4294967295 || attempt >= int16(s.attempts) || generation > 0 && !hmac.Equal(retainedPolicy, s.policyDigest[:]) {
		return delivery.ClaimResult{}, delivery.ErrConflict
	}
	if s.retainedVersion != 0 && b.PolicyVersion != s.retainedVersion {
		return delivery.ClaimResult{}, delivery.ErrConflict
	}
	if s.providerVersion != 0 && b.Intent.ProviderConfigVersion != s.providerVersion {
		return delivery.ClaimResult{}, delivery.ErrConflict
	}
	var now time.Time
	if err := tx.QueryRow(w, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return delivery.ClaimResult{}, attemptFailure(w, err)
	}
	now = now.UTC()
	lease := minTime(now.Add(s.leaseDuration), b.Intent.ExpiresAt)
	if !lease.After(now) {
		return delivery.ClaimResult{}, delivery.ErrExpired
	}
	generation++
	attempt++
	if _, err := tx.Exec(w, `INSERT INTO identity.delivery_processing(deployment,tenant_id,effect_id,generation,attempt_number,lease_owner,lease_until,policy_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(deployment,tenant_id,effect_id) DO UPDATE SET generation=EXCLUDED.generation,attempt_number=EXCLUDED.attempt_number,lease_owner=EXCLUDED.lease_owner,lease_until=EXCLUDED.lease_until,next_attempt_at=NULL`, s.deployment, string(q.TenantID), b.Intent.EffectID, generation, attempt, q.WorkerID, lease, s.policyDigest[:]); err != nil {
		return delivery.ClaimResult{}, attemptFailure(w, err)
	}
	if _, err := tx.Exec(w, `INSERT INTO identity.delivery_attempt_history(deployment,tenant_id,effect_id,generation,attempt_number,worker,started_at,lease_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, s.deployment, string(q.TenantID), b.Intent.EffectID, generation, attempt, q.WorkerID, now, lease); err != nil {
		return delivery.ClaimResult{}, attemptFailure(w, err)
	}
	tag, err := tx.Exec(w, `UPDATE identity.delivery_intents SET state='submitted' WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND expires_at>clock_timestamp()`, s.deployment, string(q.TenantID), b.Intent.EffectID)
	if err != nil {
		return delivery.ClaimResult{}, attemptFailure(w, err)
	}
	if tag.RowsAffected() != 1 {
		return delivery.ClaimResult{}, delivery.ErrExpired
	}
	if err := tx.Commit(w); err != nil {
		return delivery.ClaimResult{}, delivery.ErrOutcomeUnknown
	}
	p, err := s.codec.open(w, b, envelope)
	if err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.maximumDuration)
		defer cancel()
		_, _ = s.Complete(cleanup, delivery.CompleteRequest{TenantID: q.TenantID, IntentID: delivery.IntentID(b.Intent.EffectID), WorkerID: q.WorkerID, Generation: uint32(generation)})
		return delivery.ClaimResult{}, err
	}
	var live bool
	err = s.pool.QueryRow(w, `SELECT EXISTS(SELECT 1 FROM identity.delivery_processing WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND generation=$4 AND lease_owner=$5 AND lease_until>clock_timestamp() AND NOT cancel_requested)`, s.deployment, string(q.TenantID), b.Intent.EffectID, generation, q.WorkerID).Scan(&live)
	if err != nil {
		return delivery.ClaimResult{}, attemptFailure(w, err)
	}
	if !live {
		return delivery.ClaimResult{}, delivery.ErrConflict
	}
	result := delivery.ClaimResult{Claimed: true, LeaseUntil: lease, Attempt: delivery.Attempt{TenantID: q.TenantID, IntentID: delivery.IntentID(b.Intent.EffectID), Generation: uint32(generation), Channel: p.Recipient.Channel, Recipient: p.Recipient.Address, Subject: p.Rendered.Subject, Body: p.Rendered.Body, ContentType: p.Rendered.ContentType, IdempotencyKey: b.Intent.EffectID, ValidUntil: b.Intent.ExpiresAt}}
	if result.Validate(q) != nil {
		return delivery.ClaimResult{}, delivery.ErrUnavailable
	}
	return result, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// completionMAC stores confidential evidence identity, never a raw provider
// reference. Explicit framing covers exact invocation and result semantics.
func completionMAC(key [32]byte, q delivery.CompleteRequest) [32]byte {
	var wire []byte
	for _, v := range []string{string(q.TenantID), string(q.IntentID), q.WorkerID, q.Result.ProviderReference, q.Result.ObservedAt.Format(time.RFC3339Nano)} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(v)))
		wire = append(wire, size[:]...)
		wire = append(wire, v...)
	}
	defer clear(wire)
	var fixed [14]byte
	binary.BigEndian.PutUint32(fixed[:4], q.Generation)
	if q.Invoked {
		fixed[4] = 1
	}
	fixed[5] = byte(q.Result.State)
	binary.BigEndian.PutUint64(fixed[6:], uint64(q.Result.RetryAfter))
	return custodyMAC(key, "identity-delivery-completion-v1", fixed[:], wire)
}

func durableCompletionState(s delivery.DeliveryState) string {
	switch s {
	case delivery.StateAccepted:
		return "submitted"
	case delivery.StateDelivered:
		return "confirmed"
	case delivery.StateRejected, delivery.StateBounced:
		return "rejected"
	case delivery.StateOutcomeUnknown:
		return "outcome-unknown"
	case delivery.StateRetryWait:
		return "retry-wait"
	case delivery.StateCancelled:
		return "cancelled"
	case delivery.StateExpired:
		return "expired"
	case delivery.StateExhausted:
		return "exhausted"
	}
	return ""
}

func (s *attemptStore) Complete(ctx context.Context, q delivery.CompleteRequest) (delivery.CompleteResult, error) {
	if q.Validate() != nil {
		return delivery.CompleteResult{}, delivery.ErrInvalidInput
	}
	w, stop, err := s.bounded(ctx)
	if err != nil {
		return delivery.CompleteResult{}, err
	}
	defer stop()
	tx, err := s.pool.Begin(w)
	if err != nil {
		return delivery.CompleteResult{}, attemptFailure(w, err)
	}
	defer rollbackAttempt(tx)
	var aad []byte
	var state string
	err = tx.QueryRow(w, `SELECT binding_aad,state FROM identity.delivery_intents WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 FOR UPDATE`, s.deployment, string(q.TenantID), string(q.IntentID)).Scan(&aad, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return delivery.CompleteResult{}, delivery.ErrConflict
	}
	if err != nil {
		return delivery.CompleteResult{}, attemptFailure(w, err)
	}
	b, err := decodeBinding(aad)
	if err != nil {
		return delivery.CompleteResult{}, err
	}
	if s.retainedVersion != 0 && b.PolicyVersion != s.retainedVersion {
		return delivery.CompleteResult{}, delivery.ErrConflict
	}
	if s.providerVersion != 0 && b.Intent.ProviderConfigVersion != s.providerVersion {
		return delivery.CompleteResult{}, delivery.ErrConflict
	}
	key, ok := s.codec.keys[b.DigestKeyVersion]
	if !ok {
		return delivery.CompleteResult{}, delivery.ErrUnavailable
	}
	digest := completionMAC(key, q)
	var owner string
	var completed []byte
	var outcome *int16
	err = tx.QueryRow(w, `SELECT worker,completion_digest,outcome FROM identity.delivery_attempt_history WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND generation=$4`, s.deployment, string(q.TenantID), string(q.IntentID), int64(q.Generation)).Scan(&owner, &completed, &outcome)
	if errors.Is(err, pgx.ErrNoRows) {
		return delivery.CompleteResult{}, delivery.ErrConflict
	}
	if err != nil {
		return delivery.CompleteResult{}, attemptFailure(w, err)
	}
	if owner != q.WorkerID {
		return delivery.CompleteResult{}, delivery.ErrConflict
	}
	if len(completed) != 0 {
		if !hmac.Equal(completed, digest[:]) || outcome == nil {
			return delivery.CompleteResult{}, delivery.ErrConflict
		}
		result := delivery.CompleteResult{State: delivery.DeliveryState(*outcome), Commit: delivery.CommitCommitted}
		if result.Validate() != nil {
			return delivery.CompleteResult{}, delivery.ErrUnavailable
		}
		return result, nil
	}
	var generation int64
	var attempts int16
	var worker *string
	var lease *time.Time
	var cancelRequested bool
	var now time.Time
	var retainedPolicy []byte
	err = tx.QueryRow(w, `SELECT generation,attempt_number,lease_owner,lease_until,cancel_requested,clock_timestamp(),policy_digest FROM identity.delivery_processing WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 FOR UPDATE`, s.deployment, string(q.TenantID), string(q.IntentID)).Scan(&generation, &attempts, &worker, &lease, &cancelRequested, &now, &retainedPolicy)
	if errors.Is(err, pgx.ErrNoRows) {
		return delivery.CompleteResult{}, delivery.ErrConflict
	}
	if err != nil {
		return delivery.CompleteResult{}, attemptFailure(w, err)
	}
	now = now.UTC()
	// Cancellation or an unknown receipt marks uncertainty without discarding
	// evidence from the original live invocation. The unchanged generation,
	// owner, deadline and uncompleted history below forbid takeover/renewal.
	canComplete := state == "submitted" || state == "outcome-unknown" && outcome == nil
	if !canComplete || generation != int64(q.Generation) || worker == nil || *worker != q.WorkerID || lease == nil || !lease.After(now) || !hmac.Equal(retainedPolicy, s.policyDigest[:]) {
		return delivery.CompleteResult{}, delivery.ErrConflict
	}
	evidence := q.Result
	if !q.Invoked {
		evidence = delivery.DeliveryResult{State: delivery.StateTransientFailure, ObservedAt: now}
	}
	decision, err := s.policy.Decide(w, delivery.CompletionSnapshot{State: delivery.StateAttempting, Generation: q.Generation, ExpectedGeneration: uint32(generation), AttemptNumber: uint8(attempts), CancelRequested: cancelRequested, Now: now, ValidUntil: b.Intent.ExpiresAt}, evidence)
	if err != nil {
		return delivery.CompleteResult{}, err
	}
	var next any
	if decision.State == delivery.StateRetryWait {
		rounded := decision.NextAttemptAt.Truncate(time.Microsecond)
		if rounded.Before(decision.NextAttemptAt) {
			rounded = rounded.Add(time.Microsecond)
		}
		if !rounded.Before(b.Intent.ExpiresAt) {
			decision.State = delivery.StateExpired
			decision.ErasePayload = true
		} else {
			next = rounded
		}
	}
	tag, err := tx.Exec(w, `UPDATE identity.delivery_processing SET lease_owner=NULL,lease_until=NULL,next_attempt_at=$6 WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND generation=$4 AND lease_owner=$5 AND lease_until>clock_timestamp()`, s.deployment, string(q.TenantID), string(q.IntentID), int64(q.Generation), q.WorkerID, next)
	if err != nil {
		return delivery.CompleteResult{}, attemptFailure(w, err)
	}
	if tag.RowsAffected() != 1 {
		return delivery.CompleteResult{}, delivery.ErrConflict
	}
	if _, err := tx.Exec(w, `UPDATE identity.delivery_intents SET state=$4,ciphertext=CASE WHEN $5 THEN NULL ELSE ciphertext END,envelope_key_id=CASE WHEN $5 THEN NULL ELSE envelope_key_id END,payload_erased_at=CASE WHEN $5 THEN COALESCE(payload_erased_at,clock_timestamp()) ELSE payload_erased_at END WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`, s.deployment, string(q.TenantID), string(q.IntentID), durableCompletionState(decision.State), decision.ErasePayload); err != nil {
		return delivery.CompleteResult{}, attemptFailure(w, err)
	}
	var reference any
	if q.Result.ProviderReference != "" {
		v := custodyMAC(key, "identity-delivery-provider-reference-v1", []byte(s.deployment), []byte(q.Result.ProviderReference))
		reference = v[:]
	}
	if _, err := tx.Exec(w, `UPDATE identity.delivery_attempt_history SET outcome=$5,completed_at=clock_timestamp(),completion_digest=$6,provider_reference_digest=$7 WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND generation=$4`, s.deployment, string(q.TenantID), string(q.IntentID), int64(q.Generation), int16(decision.State), digest[:], reference); err != nil {
		return delivery.CompleteResult{}, attemptFailure(w, err)
	}
	result := delivery.CompleteResult{State: decision.State, Commit: delivery.CommitCommitted}
	if err := tx.Commit(w); err != nil {
		result.Commit = delivery.CommitUnknown
		return result, delivery.ErrOutcomeUnknown
	}
	return result, nil
}
