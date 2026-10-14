package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

var _ identitypostgres.CaptchaUseReservationContributor = (*Repository)(nil)

// ReserveCaptchaEvidence locks an already committed original CAPTCHA row and
// binds its one consuming command/fingerprint/generation in the coordinator's
// existing reservation transaction. Complete signed native input and selected
// current configuration are authenticated; primary expiry is checked after
// locking and again at CAS. No provider, caller callback or private transaction
// runs. Failure requires coordinator rollback. The serial-use handle and rows
// are not retained. This reserves ownership only, not protected-use permission.
// Install CaptchaUseMigrationSource before selecting consuming plans.
func (r *Repository) ReserveCaptchaEvidence(ctx context.Context, w identitypostgres.CaptchaUseReservationWork) error {
	return r.reserveCaptchaEvidence(ctx, w, false)
}

// RebindCaptchaEvidence transfers only the exact reserved predecessor to its
// positive successor under the same command/fingerprint and signed original.
// The coordinator transfers every declared participant atomically. Original
// expiry/reservation time and terminal ownership are never renewed or released.
// It has the same callback/transaction/lifetime constraints as first reservation.
func (r *Repository) RebindCaptchaEvidence(ctx context.Context, w identitypostgres.CaptchaUseReservationWork) error {
	return r.reserveCaptchaEvidence(ctx, w, true)
}

func (r *Repository) reserveCaptchaEvidence(ctx context.Context, w identitypostgres.CaptchaUseReservationWork, rebind bool) error {
	if ctx == nil || r == nil || r.schema == "" {
		return risk.ErrInvalidEvidenceExecution
	}
	owner, err := w.Binding(r)
	if err != nil {
		return err
	}
	command, err := w.NativeCommand(r)
	if err != nil {
		return err
	}
	spec, ok := command.Feature()
	if !ok || spec.Binding != owner.Command || owner.Generation == 0 || owner.Fingerprint == ([32]byte{}) ||
		!rebind && owner.PreviousGeneration != 0 || rebind && (owner.PreviousGeneration == 0 || owner.PreviousGeneration == ^uint64(0) || owner.Generation != owner.PreviousGeneration+1) || r.ValidateCaptchaUseCommand(command, owner.Plan) != nil {
		return identity.ConflictError{}
	}
	claim, err := restoreCaptchaUseCommand(command, r.keys, r.policy)
	if err != nil {
		return identity.ConflictError{}
	}
	p := claim.Prepared()
	originalID, err := base64.RawURLEncoding.Strict().DecodeString(p.Original.Binding.CommandID)
	if err != nil || len(originalID) != 16 {
		return identity.ConflictError{}
	}
	consumerID, err := base64.RawURLEncoding.Strict().DecodeString(p.ConsumerCommandID)
	if err != nil || len(consumerID) != 16 {
		return identity.ConflictError{}
	}
	b := owner.Command
	// The exact indexed keyed digest is the lookup key; a signed projection alone
	// cannot turn an absent/foundation/uncommitted source into issuance authority.
	rows, err := w.Query(ctx, `SELECT e.command_id,e.user_id,e.anonymous_flow_id,e.intent_digest,e.proof_digest,e.hostname,e.issued_at,e.expires_at,e.state,
 e.consumer_command_id,e.consumer_purpose,e.consumer_fingerprint,e.consumer_generation::text,e.consumer_binding_digest,e.consumer_signature,e.reserved_at,e.terminal_at
 FROM `+r.schema+`.captcha_issued_evidence e WHERE e.tenant_id=$1 AND e.key_version=$2 AND e.evidence_digest=$3
 AND EXISTS(SELECT 1 FROM identity.commands c WHERE c.command_id=e.command_id AND c.tenant_id=e.tenant_id AND c.purpose=e.command_purpose AND c.state='committed' AND c.terminal_class='committed') FOR UPDATE OF e`, string(b.TenantID), int64(p.Original.Binding.KeyVersion), p.EvidenceDigest[:])
	if err != nil {
		return err
	}
	var issuance, intent, proof, consumer, fingerprint, binding, signature []byte
	var subject, flow, hostname, state string
	var purpose, generation *string
	var issuedAt, expiresAt time.Time
	var reservedAt, terminalAt *time.Time
	matched := rows.Next() && rows.Scan(&issuance, &subject, &flow, &intent, &proof, &hostname, &issuedAt, &expiresAt, &state, &consumer, &purpose, &fingerprint, &generation, &binding, &signature, &reservedAt, &terminalAt) == nil
	if rows.Next() || rows.Err() != nil {
		matched = false
	}
	rows.Close()
	if !matched || !bytes.Equal(issuance, originalID) || subject != string(b.UserID) || flow != b.AnonymousFlowID || !issuedAt.Equal(p.IssuedAt) || !expiresAt.Equal(p.ExpiresAt) {
		return identity.ConflictError{}
	}
	// Materialize at the unchanged original database issuance time to compare
	// signed native facts, never at the new reservation time or consumer binding.
	original, err := r.restoreCaptchaOriginal(p.Original)
	if err != nil {
		return identity.ConflictError{}
	}
	record, err := original.Materialize(issuedAt.UTC())
	if err != nil || !bytes.Equal(intent, record.IntentDigest[:]) || !bytes.Equal(proof, record.ProofDigest[:]) || hostname != record.Hostname || record.EvidenceDigest != p.EvidenceDigest {
		return identity.ConflictError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	current := false
	for _, custody := range r.captcha {
		if _, err := custody.RecheckUse(p.Original, p, now); err == nil {
			current = true
			break
		}
	}
	if !current {
		return identity.ConflictError{}
	}
	link := bindingDigest(b)
	var count int64
	if rebind {
		if state != "reserved" || !bytes.Equal(consumer, consumerID) || purpose == nil || *purpose != b.OperationID || !bytes.Equal(fingerprint, owner.Fingerprint[:]) || generation == nil || *generation != strconv.FormatUint(owner.PreviousGeneration, 10) || !bytes.Equal(binding, link[:]) || !bytes.Equal(signature, p.Signature[:]) || reservedAt == nil || now.Before(*reservedAt) || terminalAt != nil {
			return identity.ConflictError{}
		}
		count, err = w.Exec(ctx, `UPDATE `+r.schema+`.captcha_issued_evidence SET consumer_generation=$4::numeric
 WHERE tenant_id=$1 AND key_version=$2 AND evidence_digest=$3 AND state='reserved' AND consumer_command_id=$5 AND consumer_fingerprint=$6 AND consumer_generation=$7::numeric
 AND consumer_binding_digest=$8 AND consumer_signature=$9 AND expires_at>clock_timestamp() AND reserved_at<=clock_timestamp()`, string(b.TenantID), int64(p.Original.Binding.KeyVersion), p.EvidenceDigest[:], strconv.FormatUint(owner.Generation, 10), consumerID, owner.Fingerprint[:], strconv.FormatUint(owner.PreviousGeneration, 10), link[:], p.Signature[:])
	} else {
		if state != "issued" || consumer != nil || purpose != nil || fingerprint != nil || generation != nil || binding != nil || signature != nil || reservedAt != nil || terminalAt != nil {
			return identity.ConflictError{}
		}
		count, err = w.Exec(ctx, `UPDATE `+r.schema+`.captcha_issued_evidence SET state='reserved',consumer_command_id=$4,consumer_purpose=$5,consumer_fingerprint=$6,consumer_generation=$7::numeric,consumer_binding_digest=$8,consumer_signature=$9,reserved_at=$10
 WHERE tenant_id=$1 AND key_version=$2 AND evidence_digest=$3 AND state='issued' AND expires_at>clock_timestamp() AND issued_at<=clock_timestamp()`, string(b.TenantID), int64(p.Original.Binding.KeyVersion), p.EvidenceDigest[:], consumerID, b.OperationID, owner.Fingerprint[:], strconv.FormatUint(owner.Generation, 10), link[:], p.Signature[:], now)
	}
	if err != nil {
		return err
	}
	if count != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (r *Repository) restoreCaptchaOriginal(p risk.PreparedCaptchaEvidence) (risk.CaptchaEvidenceIssue, error) {
	for _, custody := range r.captcha {
		if issue, err := custody.RestoreCaptchaIssue(p); err == nil {
			return issue, nil
		}
	}
	return risk.CaptchaEvidenceIssue{}, risk.ErrInvalidEvidenceExecution
}
