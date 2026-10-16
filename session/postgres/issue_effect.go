package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"strconv"
)

func (r *Repository) validateIssuePlan(command identity.Command, p kernel.CommandPlan) error {
	if r == nil || r.issueAdmission == nil {
		return session.ErrInvalidSessionCommand
	}
	native, err := nativeIssue(command)
	if err != nil {
		return err
	}
	issue, _ := native.Issue()
	s, _ := issue.Session.Bindings()
	proof := s.Authentication
	if err = r.ValidateAuthenticatedFeature(command, authentication.AuthenticatedProofSpec{Proof: proof.Proof, ProofVersion: proof.ProofVersion, CredentialID: proof.CredentialID, CredentialVersion: proof.CredentialVersion}); err != nil {
		return err
	}
	if p.Feature == nil || p.Feature.Contributor != r.Descriptor() || p.Feature.Operation != session.IssueOperation() || p.SubjectType != "session" || p.Lifecycle == nil || p.Lifecycle.EventType != "session.created.v1" || p.Lifecycle.BeforeVersion != 0 || p.Lifecycle.AfterVersion != 1 || len(p.Audits) != 1 {
		return session.ErrInvalidSessionCommand
	}
	a := p.Audits[0]
	if a.EventType != "identity.session.create" || a.SchemaVersion != 1 || !a.Required || a.RequiredRecordCount != 1 || a.RetentionClass != "standard" && a.RetentionClass != "protected" {
		return session.ErrInvalidSessionCommand
	}
	return nil
}

func (r *Repository) applyIssue(ctx context.Context, w kernel.Work, issue session.IssueCommandSpec) (identity.FeatureReceipt, error) {
	if ctx == nil || r == nil || r.issueAdmission == nil {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	b, feature, transition, err := w.FeatureScope(r)
	if err != nil || b != issue.Binding || feature.Operation != session.IssueOperation() || transition.BeforeVersion != 0 || transition.AfterVersion != 1 {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	s, err := issue.Session.Bindings()
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := r.writeIssuedSession(ctx, w, b, transition, issue.Session, s); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: feature.Operation, AfterVersion: 1}, nil
}

// Both authentication owners persist the same immutable session projection and
// retained evidence. The enclosing owner supplies its exact original transition;
// anonymous command scope must never replace the selected session user.
func (r *Repository) writeIssuedSession(ctx context.Context, w kernel.Work, b identity.CommandBinding, transition kernel.LifecyclePlan, record session.Session, s session.SessionSpec) error {
	payload, expiry, err := encodeRecord(record)
	if err != nil {
		return err
	}
	// Conflicting family creation cannot revive or overwrite retained authority.
	// The exact family is checked again after uniqueness waits, under this Work.
	if s.FamilyVersion == 1 {
		if _, err = w.Exec(ctx, `INSERT INTO `+r.schema+`.families(tenant_id,family_id,user_id,version,state,issued_at) VALUES($1,$2,$3,1,'active',$4) ON CONFLICT DO NOTHING`, string(s.TenantID), s.FamilyID, string(s.UserID), s.IssuedAt.UTC().Format(storedTimeLayout)); err != nil {
			return err
		}
	}
	if err = r.requireIssueFamily(ctx, w, s, true); err != nil {
		return err
	}
	n, err := w.Exec(ctx, `INSERT INTO `+r.schema+`.sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record) VALUES($1,$2,$3,$4,1,$5::numeric,'active',$6,$7,$8,$9::jsonb) ON CONFLICT DO NOTHING`, string(s.TenantID), s.SessionID, string(s.UserID), s.FamilyID, strconv.FormatUint(s.FamilyVersion, 10), int64(s.Lookup.KeyVersion), s.Lookup.Sum[:], expiry, string(payload))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	id, digest := revocationEvidence(b, transition)
	recordDigest := sha256.Sum256(payload)
	if b.OperationID == "identity.otp.signin" {
		digest = otpIssuanceDigest(digest, string(s.UserID), s.SessionID, s.FamilyID, recordDigest[:])
	} else if b.OperationID == "identity.password.signin" {
		digest = passwordIssuanceDigest(digest, string(s.UserID), s.SessionID, s.FamilyID, recordDigest[:])
	} else if b.OperationID == "identity.password.signup" {
		digest = passwordSignupIssuanceDigest(digest, string(s.UserID), s.SessionID, s.FamilyID, recordDigest[:])
	} else if b.OperationID == "identity.magic-link.consume" {
		digest = magicLinkIssuanceDigest(digest, string(s.UserID), s.SessionID, s.FamilyID, recordDigest[:])
	} else if b.OperationID == "identity.mfa.totp-verify" {
		digest = mfaTOTPIssuanceDigest(digest, string(s.UserID), s.SessionID, s.FamilyID, recordDigest[:])
	} else if b.OperationID == "identity.mfa.otp-verify" {
		digest = mfaOTPIssuanceDigest(digest, string(s.UserID), s.SessionID, s.FamilyID, recordDigest[:])
	} else if b.OperationID == "identity.mfa.recovery-use" {
		digest = mfaRecoveryIssuanceDigest(digest, string(s.UserID), s.SessionID, s.FamilyID, recordDigest[:])
	} else if b.OperationID == "identity.email.verification-signin" {
		digest = verificationIssuanceDigest(digest, string(s.UserID), s.SessionID, s.FamilyID, recordDigest[:])
	}
	if b.OperationID == "identity.email.verification-signin" {
		if _, err := identity.ParseCommandID(b.RecordID); err != nil {
			return session.ErrInvalidSessionCommand
		}
		parent, err := base64.RawURLEncoding.Strict().DecodeString(b.RecordID)
		if err != nil || len(parent) != 16 {
			return session.ErrInvalidSessionCommand
		}
		// Only this selected forward profile needs the parent column. Legacy
		// writes retain their SQL and work before its migration is installed.
		n, err = w.Exec(ctx, `INSERT INTO `+r.schema+`.session_issuances(tenant_id,command_id,purpose,user_id,session_id,family_id,binding_digest,record_digest,verification_command_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, string(b.TenantID), id, b.OperationID, string(s.UserID), s.SessionID, s.FamilyID, digest[:], recordDigest[:], parent)
	} else {
		n, err = w.Exec(ctx, `INSERT INTO `+r.schema+`.session_issuances(tenant_id,command_id,purpose,user_id,session_id,family_id,binding_digest,record_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, string(b.TenantID), id, b.OperationID, string(s.UserID), s.SessionID, s.FamilyID, digest[:], recordDigest[:])
	}
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

// This retained evidence complements the keyed journal; it never reconstructs
// a bearer or renews authority from a current session row. Cleanup may delete
// session payloads but must retain issuance bindings for command reconciliation.
func (r *Repository) recoverIssue(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, feature, transition, err := w.FeatureScope(r)
	if err != nil || feature.Operation != session.IssueOperation() || transition.BeforeVersion != 0 || transition.AfterVersion != 1 {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	id, digest := revocationEvidence(b, transition)
	rows, err := w.Query(ctx, `SELECT purpose,user_id,session_id,family_id,binding_digest,record_digest FROM `+r.schema+`.session_issuances WHERE tenant_id=$1 AND command_id=$2`, string(b.TenantID), id)
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
	var purpose, user, sessionID, family string
	var stored, record []byte
	if err = rows.Scan(&purpose, &user, &sessionID, &family, &stored, &record); err != nil {
		return kernel.RecoveryUnknown, err
	}
	if rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if purpose != b.OperationID || user != string(b.UserID) || sessionID != b.RecordID || !scopeID(family) || subtle.ConstantTimeCompare(stored, digest[:]) != 1 || len(record) != sha256.Size {
		return kernel.RecoveryUnknown, nil
	}
	return kernel.RecoveryCommitted, nil
}
