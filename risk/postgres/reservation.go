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

var _ identitypostgres.RiskReservationContributor = (*Repository)(nil)

// ReserveRiskEvidence authenticates the frozen initiation use and locks its
// existing primary issued row through the sole coordinator's reservation Work.
// Exactly one command obtains ownership. No bearer, response or domain authority
// is returned. Missing, expired, terminal or mismatched evidence yields the same
// redacted conflict. It never inserts evidence, renews expiry, runs callbacks or
// opens a private transaction. The reservation migration must already be applied.
func (r *Repository) ReserveRiskEvidence(ctx context.Context, w identitypostgres.RiskReservationWork) error {
	return r.reserveEvidence(ctx, w, false)
}

// RebindRiskEvidence transfers only the same command/fingerprint's exact prior
// generation in the coordinator's atomic owner takeover. Original reservation
// time, issuance custody and expiry remain unchanged. Terminal, expired, missing
// or partial ownership fails closed; lease expiry never releases evidence.
func (r *Repository) RebindRiskEvidence(ctx context.Context, w identitypostgres.RiskReservationWork) error {
	return r.reserveEvidence(ctx, w, true)
}

func (r *Repository) reserveEvidence(ctx context.Context, w identitypostgres.RiskReservationWork, rebind bool) error {
	if ctx == nil || r == nil || r.schema == "" {
		return identity.InvalidInputError{Field: "risk_reservation"}
	}
	b, err := w.Binding(r)
	if err != nil {
		return err
	}
	p := b.Plan
	claim, err := r.restoreUse(b)
	if err != nil || b.Generation == 0 || !rebind && b.PreviousGeneration != 0 || rebind && (b.PreviousGeneration == 0 || b.PreviousGeneration == ^uint64(0) || b.Generation != b.PreviousGeneration+1) {
		return identity.ConflictError{}
	}
	issuedID, _ := base64.RawURLEncoding.DecodeString(p.IssuanceCommandID)
	consumerID, _ := base64.RawURLEncoding.DecodeString(p.ConsumerCommandID)
	// Foundation/unknown histories may retain positive native linkage without
	// a proved successful command. Never turn that evidence into new authority.
	// Terminal issuance metadata cannot be retired while this journal's FK lives.
	rows, err := w.Query(ctx, `SELECT e.command_id,e.user_id,e.policy_version::text,e.intent_digest,e.proof_digest,e.issued_at,e.expires_at,e.state,e.reservation_command_id,e.reservation_purpose,e.reservation_fingerprint,e.reservation_generation::text
 FROM `+r.schema+`.issued_evidence e WHERE e.tenant_id=$1 AND e.purpose=$2 AND e.key_version=$3 AND e.evidence_digest=$4
 AND EXISTS(SELECT 1 FROM identity.commands c WHERE c.command_id=e.command_id AND c.tenant_id=e.tenant_id AND c.purpose=e.command_purpose AND c.state='committed' AND c.terminal_class='committed') FOR UPDATE OF e`, p.Tenant, p.Purpose, int64(p.KeyVersion), p.EvidenceDigest[:])
	if err != nil {
		return err
	}
	var issuance, intent, proof, owner, fingerprint []byte
	var subject, policy, state string
	var purpose, generation *string
	var issuedAt, expiresAt time.Time
	matched := rows.Next() && rows.Scan(&issuance, &subject, &policy, &intent, &proof, &issuedAt, &expiresAt, &state, &owner, &purpose, &fingerprint, &generation) == nil
	if rows.Next() || rows.Err() != nil {
		matched = false
	}
	rows.Close()
	if !matched || !bytes.Equal(issuance, issuedID) || subject != p.Subject || policy != strconv.FormatUint(p.PolicyVersion, 10) || !bytes.Equal(intent, p.IntentDigest[:]) || !bytes.Equal(proof, p.ProofDigest[:]) || !issuedAt.Equal(p.IssuedAt) || !expiresAt.Equal(p.ExpiresAt) {
		return identity.ConflictError{}
	}
	// Sample primary time after the row lock: waiting cannot preserve an earlier
	// positive validity observation. The final CAS also checks clock_timestamp.
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if claim.Validate(now) != nil {
		return identity.ConflictError{}
	}
	var count int64
	if rebind {
		if state != "reserved" || !bytes.Equal(owner, consumerID) || purpose == nil || *purpose != b.Command.OperationID || !bytes.Equal(fingerprint, b.Fingerprint[:]) || generation == nil || *generation != strconv.FormatUint(b.PreviousGeneration, 10) {
			return identity.ConflictError{}
		}
		count, err = w.Exec(ctx, `UPDATE `+r.schema+`.issued_evidence SET reservation_generation=$5::numeric WHERE tenant_id=$1 AND purpose=$2 AND key_version=$3 AND evidence_digest=$4 AND state='reserved' AND reservation_command_id=$6 AND reservation_fingerprint=$7 AND reservation_generation=$8::numeric AND expires_at>clock_timestamp()`, p.Tenant, p.Purpose, int64(p.KeyVersion), p.EvidenceDigest[:], strconv.FormatUint(b.Generation, 10), consumerID, b.Fingerprint[:], strconv.FormatUint(b.PreviousGeneration, 10))
	} else {
		if state != "issued" || owner != nil || purpose != nil || fingerprint != nil || generation != nil {
			return identity.ConflictError{}
		}
		count, err = w.Exec(ctx, `UPDATE `+r.schema+`.issued_evidence SET state='reserved',reservation_command_id=$5,reservation_purpose=$6,reservation_fingerprint=$7,reservation_generation=$8::numeric,reserved_at=$9 WHERE tenant_id=$1 AND purpose=$2 AND key_version=$3 AND evidence_digest=$4 AND state='issued' AND expires_at>clock_timestamp()`, p.Tenant, p.Purpose, int64(p.KeyVersion), p.EvidenceDigest[:], consumerID, b.Command.OperationID, b.Fingerprint[:], strconv.FormatUint(b.Generation, 10), now)
	}
	if err != nil {
		return err
	}
	if count != 1 {
		return identity.ConflictError{}
	}
	return nil
}

// This authenticates only the signed native projection and supported consuming
// scope/current risk policy. Raw recovery equality was established by core
// PrecheckUse; apply still owns rechecking native scope, counters and policy.
func (r *Repository) restoreUse(b identitypostgres.RiskReservationBinding) (risk.EvidenceUseClaim, error) {
	p := b.Plan
	c := b.Command
	if r == nil || p.PolicyVersion != r.policy || p.PolicyVersion == 0 || p.Tenant != string(c.TenantID) || p.Subject != string(c.UserID) || p.ConsumerCommandID != string(c.CommandID) || p.ConsumerActor != string(c.ActorID) || p.RecoveryOperation != c.OperationID || c.OperationID != "identity.phone.password-reset-request" || c.SchemaID != "identity.phone.password-reset-request.native-v1" || c.SchemaVersion != 1 || p.Phase != string(risk.PhoneResetInitiation) || p.Purpose != "phone-password-reset-initiate" {
		return risk.EvidenceUseClaim{}, identity.ConflictError{}
	}
	prepared := risk.PreparedEvidenceUse{Binding: risk.EvidenceIntentBinding{CommandID: p.IssuanceCommandID, Tenant: p.Tenant, Subject: p.Subject, Actor: p.IssuerActor, Purpose: p.Purpose, Phase: risk.IssuancePhase(p.Phase), RecoveryOperation: risk.Action(p.RecoveryOperation), PolicyVersion: p.PolicyVersion, KeyVersion: p.KeyVersion, IntentDigest: p.IntentDigest}, ConsumerCommandID: p.ConsumerCommandID, ConsumerActor: p.ConsumerActor, EvidenceDigest: p.EvidenceDigest, ProofDigest: p.ProofDigest, Signature: p.Signature, IssuedAt: p.IssuedAt, CheckedAt: p.CheckedAt, ExpiresAt: p.ExpiresAt}
	for _, key := range r.keys {
		if claim, err := key.RestoreUse(prepared); err == nil {
			return claim, nil
		}
	}
	return risk.EvidenceUseClaim{}, identity.ConflictError{}
}
