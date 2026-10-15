package passwordpostgres

import (
	"context"
	"encoding/base64"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
)

var _ mfapg.TOTPEnrollmentPrimarySource = (*MFAEnablePrimarySource)(nil)
var _ mfapg.TOTPEnrollmentPrimary = MFAEnableAdmission{}

// PrepareEnrollment implements MFA's consumer-owned primary port using the
// existing password source and sole upstream signed-proof validator. It compares
// the submitted PrimaryProof with the original session rather than treating the
// protected-action reauthentication proof as another primary login. It performs
// no factor generation or proof consumption; native risk/CSRF still apply.
func (s *MFAEnablePrimarySource) PrepareEnrollment(ctx context.Context, r mfa.EnableRequest, command identity.CommandID, factor mfa.FactorID) (mfapg.TOTPEnrollmentPrimary, error) {
	if r.Validate() != nil {
		return nil, identity.InvalidInputError{Field: "mfa_enable"}
	}
	a, err := s.Prepare(ctx, enrollmentPrimaryRequest(r, command, factor))
	if err != nil {
		return nil, err
	}
	return matchEnrollmentPrimary(r, a)
}

// RestoreEnrollment accepts only authenticated original encrypted preparation
// from the native MFA owner. It compares the original primary projection and
// bearer commitment without SQL, freshness renewal or authority grants. Current
// primary SQL and exact proof one-use remain mandatory in protected Consume.
func (s *MFAEnablePrimarySource) RestoreEnrollment(ctx context.Context, r mfa.EnableRequest, command identity.CommandID, factor mfa.FactorID, wire []byte) (mfapg.TOTPEnrollmentPrimary, error) {
	if r.Validate() != nil {
		return nil, identity.InvalidInputError{Field: "mfa_enable"}
	}
	a, err := s.Restore(ctx, enrollmentPrimaryRequest(r, command, factor), wire)
	if err != nil {
		return nil, err
	}
	return matchEnrollmentPrimary(r, a)
}

func enrollmentPrimaryRequest(r mfa.EnableRequest, command identity.CommandID, factor mfa.FactorID) MFAEnablePrimaryRequest {
	return MFAEnablePrimaryRequest{TenantID: r.TenantID, CommandID: command, FactorID: string(factor), Session: r.Session, Proof: r.Reauthentication, Caller: r.Caller, CSRFToken: r.CSRFToken}
}

func matchEnrollmentPrimary(r mfa.EnableRequest, a MFAEnableAdmission) (mfapg.TOTPEnrollmentPrimary, error) {
	original, err := a.Original()
	if err != nil {
		return nil, err
	}
	b, err := original.Bindings()
	if err != nil || b.Authentication.Proof != r.PrimaryProof {
		return nil, identity.ForbiddenError{}
	}
	return a, nil
}

// RecoverEnrollment reconciles only the password owner's original enrollment
// proof-use marker under an exact registered MFA recovery invocation. No proof,
// bearer, current authority, material, freshness or standalone transaction is
// returned. The native owner must combine this with every factor/recovery/risk/
// audit/lifecycle participant. Historical key retirement grants no new authority.
func (s *MFAEnablePrimarySource) RecoverEnrollment(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || s == nil || s.source == nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	b, f, life, err := w.FeatureScope(owner)
	if err != nil || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) || f.Operation != mfaEnableOperation() || life.EventType != "factor.enrollment-created.v1" || life.BeforeVersion != 0 || life.AfterVersion != 1 {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, `SELECT p.proof_id,p.user_id,CASE WHEN octet_length(p.record)<=$4 THEN p.record ELSE ''::bytea END
FROM identity_password.reauthentication_records p JOIN identity.commands c USING(tenant_id,purpose,command_id)
WHERE p.tenant_id=$1 AND p.consumed_purpose=$2 AND p.consumed_command_id=$3 AND c.state='committed'`, string(b.TenantID), b.OperationID, id, maximumReauthenticationRecordBytes)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return kernel.RecoveryUnknown, rows.Err()
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var proofID, user string
	var payload []byte
	if rows.Scan(&proofID, &user, &payload) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	defer clear(payload)
	record, err := decodeReauthenticationRecord(auth.ProofID(proofID), string(b.TenantID), string(b.UserID), payload)
	if err != nil || user != string(b.UserID) || record.Proof.Action != b.OperationID {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return kernel.RecoveryCommitted, nil
}
