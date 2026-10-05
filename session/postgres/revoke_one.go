package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"strconv"
	"strings"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func nativeRevokeOne(command identity.Command) (session.SessionCommand, error) {
	b, record, err := nativeSessionRecord(command, session.RevokeOneOperation())
	if err != nil {
		return session.SessionCommand{}, err
	}
	return session.NewRevokeOneCommand(b, record)
}

func (r *Repository) validateRevokeOnePlan(command identity.Command, p kernel.CommandPlan) error {
	if r == nil || r.issueAdmission == nil {
		return session.ErrInvalidSessionCommand
	}
	native, err := nativeRevokeOne(command)
	if err != nil {
		return err
	}
	one, _ := native.RevokeOne()
	spec, _ := one.Session.Bindings()
	if _, _, _, err = sessionAdmissionBindings(IdentifierAdmissionConfig(*r.issueAdmission), one.Session, one.Binding, spec.SessionID, spec.Version); err != nil {
		return err
	}
	if p.Feature == nil || p.Feature.Contributor != r.Descriptor() || p.Feature.Operation != session.RevokeOneOperation() || p.SubjectType != "session" || p.Capability != nil || p.Lifecycle == nil || p.Lifecycle.EventType != "session.revoked.v1" || p.Lifecycle.BeforeVersion != spec.Version || p.Lifecycle.AfterVersion != spec.Version+1 || len(p.Audits) != 1 {
		return session.ErrInvalidSessionCommand
	}
	a := p.Audits[0]
	if a.EventType != "identity.session.revoke" || a.SchemaVersion != 1 || !a.Required || a.RequiredRecordCount != 1 || a.RetentionClass != "standard" && a.RetentionClass != "protected" {
		return session.ErrInvalidSessionCommand
	}
	return nil
}

// The native mutation is not caller authentication. The owned service must
// supply opaque current caller custody and policy Allow before reservation.
// Here every original target owner is checked on the coordinator's primary
// transaction, with locks retained until its terminal commit/abort. Supported
// single-factor targets cannot omit another applicable authority dimension.
func (r *Repository) applyRevokeOne(ctx context.Context, w kernel.Work, one session.RevokeOneCommandSpec) (identity.FeatureReceipt, error) {
	if r.issueAdmission == nil || r.maximumDuration <= 0 {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	spec, err := one.Session.Bindings()
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, feature, transition, err := w.FeatureScope(r)
	if err != nil || b != one.Binding || feature.Operation != session.RevokeOneOperation() || transition.BeforeVersion != spec.Version || transition.AfterVersion != spec.Version+1 {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	directory, credential, policy, err := sessionAdmissionBindings(IdentifierAdmissionConfig(*r.issueAdmission), one.Session, b, spec.SessionID, spec.Version)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = w.RequireActiveDirectoryAuthority(bounded, r, directory); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, err = w.RequireActiveCredential(bounded, r, credential); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = w.RequireActiveUserAuthorization(bounded, r, policy); err != nil {
		return identity.FeatureReceipt{}, err
	}
	// Acquire the mutation lock before the shared record admission, so two
	// revokers cannot both hold SHARE then deadlock upgrading the same target.
	rows, err := w.Query(bounded, `SELECT record::text FROM `+r.schema+`.sessions WHERE tenant_id=$1 AND user_id=$2 AND session_id=$3 AND version=$4::numeric AND state='active' FOR UPDATE`, string(b.TenantID), string(b.UserID), b.RecordID, strconv.FormatUint(spec.Version, 10))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	var locked []byte
	err = readSessionAdmission(rows, &locked)
	rows.Close()
	if err != nil {
		return identity.FeatureReceipt{}, admissionError(bounded, err)
	}
	// This remains the exact original active record, not a refreshed vector.
	// Family share locks prevent concurrent family revocation from crossing the
	// transition; no family or sibling version is advanced by this operation.
	if err = RequireSession(bounded, w, Config{Schema: strings.Trim(r.schema, "\""), MaximumDuration: r.maximumDuration}, one.Session); err != nil {
		return identity.FeatureReceipt{}, err
	}
	payload, _, err := encodeRecord(one.Session)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	n, err := w.Exec(bounded, `UPDATE `+r.schema+`.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id=$2 AND session_id=$3 AND version=$4::numeric AND state='active' AND record=$5::jsonb`, string(b.TenantID), string(b.UserID), b.RecordID, strconv.FormatUint(spec.Version, 10), string(payload))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	id, digest := revocationEvidence(b, transition)
	recordDigest := sha256.Sum256(payload)
	// The original record/version remains immutable. The terminal successor is
	// retained independently of payload cleanup, never used to resurrect a row.
	n, err = w.Exec(bounded, `INSERT INTO `+r.schema+`.session_revocations(tenant_id,command_id,purpose,user_id,session_id,before_version,after_version,binding_digest,record_digest) VALUES($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8,$9)`, string(b.TenantID), id, b.OperationID, string(b.UserID), b.RecordID, strconv.FormatUint(transition.BeforeVersion, 10), strconv.FormatUint(transition.AfterVersion, 10), digest[:], recordDigest[:])
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	return identity.FeatureReceipt{Operation: feature.Operation, BeforeVersion: transition.BeforeVersion, AfterVersion: transition.AfterVersion}, nil
}

func (r *Repository) recoverRevokeOne(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, feature, transition, err := w.FeatureScope(r)
	if err != nil || feature.Operation != session.RevokeOneOperation() || transition.BeforeVersion == 0 || transition.BeforeVersion == ^uint64(0) || transition.AfterVersion != transition.BeforeVersion+1 {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	id, digest := revocationEvidence(b, transition)
	rows, err := w.Query(ctx, `SELECT purpose,user_id,session_id,before_version::text,after_version::text,binding_digest,record_digest FROM `+r.schema+`.session_revocations WHERE tenant_id=$1 AND command_id=$2`, string(b.TenantID), id)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err = rows.Err(); err != nil {
			return kernel.RecoveryUnknown, err
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var purpose, user, target, before, after string
	var stored, record []byte
	if err = rows.Scan(&purpose, &user, &target, &before, &after, &stored, &record); err != nil {
		return kernel.RecoveryUnknown, err
	}
	if rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if purpose != b.OperationID || user != string(b.UserID) || target != b.RecordID || before != strconv.FormatUint(transition.BeforeVersion, 10) || after != strconv.FormatUint(transition.AfterVersion, 10) || subtle.ConstantTimeCompare(stored, digest[:]) != 1 || len(record) != sha256.Size {
		return kernel.RecoveryUnknown, nil
	}
	return kernel.RecoveryCommitted, nil
}
