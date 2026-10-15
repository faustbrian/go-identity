package mfapostgres

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// A factor and its first recovery set share the original random enrollment
// identity in disjoint owned namespaces. It is not a credential or a digest.
// The immutable set epoch stays one when pending activation advances row state.
func enrollmentRecoveryBinding(m PendingTOTPMetadata) ([]byte, error) {
	for _, id := range []string{string(m.TenantID), string(m.UserID)} {
		if _, err := identity.ParseIdentifierID(id); err != nil {
			return nil, invalidEnrollment()
		}
	}
	if _, err := identity.ParseCommandID(m.FactorID); err != nil {
		return nil, invalidEnrollment()
	}
	return json.Marshal(struct {
		Profile, Tenant, User, Factor, Set string
		Epoch                              uint64
	}{"mfa-recovery-code-v1", string(m.TenantID), string(m.UserID), m.FactorID, m.FactorID, 1})
}

func (p *totpEnrollmentPhase) persistRecovery(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p == nil || p.input == nil || p.output == nil {
		return invalidEnrollment()
	}
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return err
	}
	b, feature, life, err := w.FeatureScope(p)
	if err != nil || feature.Operation != enrollmentOperation() || life.EventType != "factor.enrollment-created.v1" || b != p.input.Binding || len(p.output.stored.Digests) != int(p.request().FactorPolicy.RecoveryCodes) {
		return invalidEnrollment()
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return invalidEnrollment()
	}
	count := len(p.output.stored.Digests)
	sql := `INSERT INTO identity_mfa.recovery_sets(tenant_id,user_id,set_id,factor_id,set_version,row_version,state,code_count,key_version,created_command_id,created_purpose,created_at)
SELECT tenant_id,user_id,factor_id,factor_id,1,1,1,$4,$5,$3,'identity.mfa.enable',created_at
FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$6 AND state=1 AND created_command_id=$3 AND created_purpose='identity.mfa.enable'`
	if p.state.method == "otp" {
		sql = `INSERT INTO identity_mfa.recovery_sets(tenant_id,user_id,set_id,factor_id,factor_method,set_version,row_version,state,code_count,key_version,created_command_id,created_purpose,created_at)
SELECT tenant_id,user_id,factor_id,factor_id,'otp',1,1,1,$4,$5,$3,'identity.mfa.enable',created_at
FROM identity_mfa.otp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$6 AND state=1 AND created_command_id=$3 AND created_purpose='identity.mfa.enable'`
	}
	n, err := w.Exec(ctx, sql, string(b.TenantID), string(b.UserID), id, count, int64(p.output.stored.RecoveryKeyVersion), b.RecordID)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	for index, digest := range p.output.stored.Digests {
		n, err := w.Exec(ctx, `INSERT INTO identity_mfa.recovery_codes(tenant_id,set_id,code_index,digest) VALUES($1,$2,$3,$4)`, string(b.TenantID), b.RecordID, index, digest[:])
		if err != nil {
			return err
		}
		if n != 1 {
			return identity.UnavailableError{}
		}
	}
	return nil
}

func (p *totpEnrollmentPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	if p == nil || p.state == nil {
		return kernel.RecoveryUnknown, invalidEnrollment()
	}
	b, f, life, err := w.FeatureScope(p)
	if err != nil || f.Contributor != p.Descriptor() || f.Operation != enrollmentOperation() || life.EventType != "factor.enrollment-created.v1" || life.BeforeVersion != 0 || life.AfterVersion != 1 {
		return kernel.RecoveryUnknown, invalidEnrollment()
	}
	primary, err := p.state.config.Primary.RecoverEnrollment(ctx, w, p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, invalidEnrollment()
	}
	sql := `SELECT f.user_id,f.factor_id,r.user_id,r.set_id,r.code_count,
(SELECT count(*) FROM identity_mfa.recovery_codes c WHERE c.tenant_id=r.tenant_id AND c.set_id=r.set_id)
FROM identity_mfa.totp_factors f LEFT JOIN identity_mfa.recovery_sets r ON r.tenant_id=f.tenant_id AND r.factor_id=f.factor_id
WHERE f.tenant_id=$1 AND f.created_purpose='identity.mfa.enable' AND f.created_command_id=$2`
	if p.state.method == "otp" {
		sql = `SELECT f.user_id,f.factor_id,r.user_id,r.set_id,r.code_count,
(SELECT count(*) FROM identity_mfa.recovery_codes c WHERE c.tenant_id=r.tenant_id AND c.set_id=r.set_id)
FROM identity_mfa.otp_factors f LEFT JOIN identity_mfa.recovery_sets r ON r.tenant_id=f.tenant_id AND r.factor_id=f.factor_id AND r.factor_method='otp'
WHERE f.tenant_id=$1 AND f.created_purpose='identity.mfa.enable' AND f.created_command_id=$2`
	}
	rows, err := w.Query(ctx, sql, string(b.TenantID), id)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return kernel.RecoveryUnknown, rows.Err()
		}
		if primary == kernel.RecoveryNotCommitted {
			return primary, nil
		}
		return kernel.RecoveryUnknown, nil
	}
	var user, factor string
	var recoveryUser, set *string
	var count *int16
	var actual int64
	if rows.Scan(&user, &factor, &recoveryUser, &set, &count, &actual) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if primary != kernel.RecoveryCommitted || user != string(b.UserID) || factor != b.RecordID || recoveryUser == nil || *recoveryUser != user || set == nil || *set != factor || count == nil || *count < 1 || *count > 64 || actual != int64(*count) {
		return kernel.RecoveryUnknown, nil
	}
	return kernel.RecoveryCommitted, nil
}

// RecoverEnable uses only the exact original non-secret command scope and the
// current result-access policy. It never asks for a password/code/bearer, restores
// expired authorization, generates material, reveals codes or repeats enrollment.
// All native proof/factor/recovery/counter/audit/lifecycle participants must agree
// before pending ambiguity can terminalize. Terminal receipts remain historical.
func (s *TOTPEnrollmentService) RecoverEnable(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out mfa.EnableResult, err error) {
	if ctx == nil || s == nil || s.state == nil || q.OperationID != enrollmentOperation().OperationID {
		return out, invalidEnrollment()
	}
	state := s.state()
	ctx, stop := context.WithTimeout(ctx, state.config.MaximumDuration)
	defer stop()
	p := &totpEnrollmentPhase{state: state}
	c, _, err := state.coordinator(p)
	if err != nil {
		return out, err
	}
	receipt, err := c.RecoverFeatureCommand(ctx, q, caller)
	if receipt.Binding.CommandID != "" {
		out.CommandID = receipt.Binding.CommandID
	}
	out.Outcome = receipt.Outcome
	return out, err
}
