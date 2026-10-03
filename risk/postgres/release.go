package postgres

import (
	"context"
	"encoding/base64"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

var _ identitypostgres.RiskReleaseContributor = (*Repository)(nil)

// ReleaseRiskEvidence terminally releases exact reserved initiation custody
// only through the sole coordinator's unanimous-noncommit release invocation.
// It preserves original issuance, expiry and reservation time, recording only
// the recovery generation. No expiry check grants rollback proof or reusability.
// Foreign, missing, terminal or mismatched custody fails closed. No callbacks,
// bearer reads, new evidence or private transaction are permitted.
func (r *Repository) ReleaseRiskEvidence(ctx context.Context, w identitypostgres.RiskReleaseWork) error {
	if ctx == nil || r == nil || r.schema == "" {
		return identity.InvalidInputError{Field: "risk_release"}
	}
	b, err := w.Binding(r)
	if err != nil {
		return err
	}
	if _, err = r.restoreHistoricalUse(b); err != nil {
		return identity.ConflictError{}
	}
	args := reservedEvidenceArgs(b)
	args = append(args, strconv.FormatUint(b.Generation, 10))
	n, err := w.Exec(ctx, `UPDATE `+r.schema+`.issued_evidence e SET state='released',reservation_generation=$16::numeric WHERE `+reservedEvidencePredicate, args...)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

// The coordinator excludes all prior domain writers before invoking recovery.
// An exact reserved row is negative evidence for this participant's finalization
// only; the phone, kernel, audit and outbox must independently prove noncommit.
// Missing and terminal rows are unknown, never absence-based rollback proof.
func (r *Repository) recoverRiskEvidence(ctx context.Context, w identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	unknown := func() (identitypostgres.RecoveryStatus, error) {
		return identitypostgres.RecoveryUnknown, identity.UnavailableError{}
	}
	b, err := w.RiskBinding(r)
	if err != nil {
		return unknown()
	}
	if _, err = r.restoreHistoricalUse(b); err != nil {
		return unknown()
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM `+r.schema+`.issued_evidence e WHERE `+reservedEvidencePredicate+`)`, reservedEvidenceArgs(b)...)
	if err != nil {
		return unknown()
	}
	defer rows.Close()
	var exact bool
	if !rows.Next() || rows.Scan(&exact) != nil || rows.Next() || rows.Err() != nil || !exact {
		return unknown()
	}
	return identitypostgres.RecoveryNotCommitted, nil
}

// One immutable predicate is used for evidence reads and the terminal CAS.
// Retained command metadata is authoritative; neither expiry nor the current
// configured policy can turn an old reservation into a reusable issued row.
const reservedEvidencePredicate = `e.tenant_id=$1 AND e.purpose=$2 AND e.key_version=$3 AND e.evidence_digest=$4
 AND e.command_id=$5 AND e.user_id=$6 AND e.policy_version=$7::numeric AND e.intent_digest=$8 AND e.proof_digest=$9
 AND e.issued_at=$10 AND e.expires_at=$11 AND e.state='reserved'
 AND e.reservation_command_id=$12 AND e.reservation_purpose=$13 AND e.reservation_fingerprint=$14 AND e.reservation_generation=$15::numeric
 AND EXISTS(SELECT 1 FROM identity.commands c WHERE c.command_id=e.command_id AND c.tenant_id=e.tenant_id AND c.purpose=e.command_purpose AND c.state='committed' AND c.terminal_class='committed')`

func reservedEvidenceArgs(b identitypostgres.RiskReservationBinding) []any {
	p := b.Plan
	issuance, _ := base64.RawURLEncoding.DecodeString(p.IssuanceCommandID)
	consumer, _ := base64.RawURLEncoding.DecodeString(p.ConsumerCommandID)
	return []any{p.Tenant, p.Purpose, int64(p.KeyVersion), p.EvidenceDigest[:], issuance, p.Subject, strconv.FormatUint(p.PolicyVersion, 10), p.IntentDigest[:], p.ProofDigest[:], p.IssuedAt, p.ExpiresAt, consumer, b.Command.OperationID, b.Fingerprint[:], strconv.FormatUint(b.PreviousGeneration, 10)}
}
