package mfapostgres

import (
	"context"
	"encoding/base64"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func (p *totpURIPhase) admitOTPConfirmation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if err := p.checkOTPConfirmationState(ctx, w, false); err != nil {
		return err
	}
	if err := p.primary.Check(ctx, w, p, c); err != nil {
		return err
	}
	if p.output != nil {
		now, err := w.DatabaseTime(ctx)
		if err != nil {
			return err
		}
		return p.risk.CheckAt(ctx, now)
	}
	return nil
}

func (p *totpURIPhase) checkOTPConfirmationState(ctx context.Context, w kernel.Work, applied bool) error {
	if p == nil || p.pending == nil || p.pending.Input.OTP == nil || p.sendInput == nil || p.otpConfirmation == nil {
		return invalidEnrollment()
	}
	m := *p.pending.Input.OTP
	expectedAuthority, expectedActive := p.pending.AuthorityVersion, int32(0)
	if applied {
		expectedAuthority++
		expectedActive = 1
	}
	rows, err := w.Query(ctx, `SELECT version::text,active_factors FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE`, string(m.TenantID), string(m.UserID))
	if err != nil {
		return err
	}
	var authority string
	var active int32
	if !rows.Next() || rows.Scan(&authority, &active) != nil || rows.Next() || rows.Err() != nil {
		rows.Close()
		return identity.ForbiddenError{}
	}
	rows.Close()
	if authority != strconv.FormatUint(expectedAuthority, 10) || active != expectedActive {
		return identity.ForbiddenError{}
	}
	rows, err = w.Query(ctx, `SELECT state,row_version::text,created_command_id,last_send_command_id,identifier_id,identifier_version::text,verification_version::text,channel,enrollment_expires_at,activation_command_id,COALESCE(activation_before_version::text,''),COALESCE(activation_authority_before::text,'')
FROM identity_mfa.otp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 FOR UPDATE`, string(m.TenantID), string(m.UserID), m.FactorID)
	if err != nil {
		return err
	}
	var state int16
	var row, identifier, iv, vv, channel, before, authorityBefore string
	var parent, send, activation []byte
	var expires time.Time
	if !rows.Next() || rows.Scan(&state, &row, &parent, &send, &identifier, &iv, &vv, &channel, &expires, &activation, &before, &authorityBefore) != nil || rows.Next() || rows.Err() != nil {
		rows.Close()
		return identity.ForbiddenError{}
	}
	rows.Close()
	expectedRow, expectedState := p.pending.RowVersion, int16(1)
	if applied {
		expectedRow++
		expectedState = 2
	}
	if state != expectedState || row != strconv.FormatUint(expectedRow, 10) || base64.RawURLEncoding.EncodeToString(parent) != string(p.pending.binding().CommandID) || base64.RawURLEncoding.EncodeToString(send) != string(p.sendInput.Binding.CommandID) || identifier != string(m.IdentifierID) || iv != strconv.FormatUint(m.IdentifierVersion, 10) || vv != strconv.FormatUint(m.VerificationVersion, 10) || channel != otpChannelText(m.Channel) || !expires.Equal(m.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	if applied && (base64.RawURLEncoding.EncodeToString(activation) != string(p.request.CommandID) || before != strconv.FormatUint(p.pending.RowVersion, 10) || authorityBefore != strconv.FormatUint(p.pending.AuthorityVersion, 10)) || !applied && (len(activation) != 0 || before != "" || authorityBefore != "") {
		return identity.ForbiddenError{}
	}
	prepared, err := NewPreparedOTPEnrollment(m)
	if err != nil {
		return err
	}
	if err = prepared.checkRecipient(ctx, w); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if now.Before(p.sendInput.IssuedAt) || !now.Before(m.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *totpURIPhase) applyOTPConfirmation(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	bad := func(err error) (identity.FeatureReceipt, error) { return identity.FeatureReceipt{}, err }
	if p.otpPlan == nil || c != p.generatedOTP {
		return bad(invalidEnrollment())
	}
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return bad(err)
	}
	consumption, err := w.OTPConsumption(p)
	if err != nil || consumption.Plan != *p.otpPlan || consumption.Command.CommandID != p.request.CommandID || consumption.Plan.ChallengeID != string(p.sendInput.Binding.CommandID) {
		return bad(invalidEnrollment())
	}
	if err = p.AdmitFeaturePreparation(ctx, w, c); err != nil {
		return bad(err)
	}
	if err = p.CheckFeatureCommit(ctx, w, c); err != nil {
		return bad(err)
	}
	m := *p.pending.Input.OTP
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return bad(err)
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(p.request.CommandID))
	if err != nil {
		return bad(invalidEnrollment())
	}
	parent, err := base64.RawURLEncoding.Strict().DecodeString(string(p.pending.binding().CommandID))
	if err != nil {
		return bad(invalidEnrollment())
	}
	n, err := w.Exec(ctx, `UPDATE identity_mfa.otp_factors SET state=2,confirmed_at=$4,activation_command_id=$5,activation_before_version=row_version,activation_authority_before=$6::numeric,row_version=row_version+1
WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=1 AND row_version=$7::numeric AND activation_command_id IS NULL`, string(m.TenantID), string(m.UserID), m.FactorID, now, id, strconv.FormatUint(p.pending.AuthorityVersion, 10), strconv.FormatUint(p.pending.RowVersion, 10))
	if err != nil {
		return bad(err)
	}
	if n != 1 {
		return bad(identity.ForbiddenError{})
	}
	n, err = w.Exec(ctx, `UPDATE identity_mfa.recovery_sets SET state=2,row_version=row_version+1 WHERE tenant_id=$1 AND user_id=$2 AND set_id=$3 AND factor_id=$3 AND factor_method='otp' AND state=1 AND row_version=1 AND set_version=1 AND created_command_id=$4 AND created_purpose='identity.mfa.enable'`, string(m.TenantID), string(m.UserID), m.FactorID, parent)
	if err != nil {
		return bad(err)
	}
	if n != 1 {
		return bad(identity.ForbiddenError{})
	}
	n, err = w.Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1,version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND active_factors=0 AND version=$3::numeric`, string(m.TenantID), string(m.UserID), strconv.FormatUint(p.pending.AuthorityVersion, 10))
	if err != nil {
		return bad(err)
	}
	if n != 1 {
		return bad(identity.ForbiddenError{})
	}
	p.applied = true
	if err = p.CheckFeatureCommit(ctx, w, c); err != nil {
		return bad(err)
	}
	return identity.FeatureReceipt{Operation: otpConfirmationOperation(), BeforeVersion: p.pending.RowVersion, AfterVersion: p.pending.RowVersion + 1}, nil
}

func (p *totpURIPhase) recoverOTPConfirmation(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, feature, life, err := w.FeatureScope(p)
	if err != nil || feature.Operation != otpConfirmationOperation() || life.EventType != "factor.enrolled.v1" || life.BeforeVersion == 0 || life.AfterVersion != life.BeforeVersion+1 {
		return kernel.RecoveryUnknown, invalidEnrollment()
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, invalidEnrollment()
	}
	rows, err := w.Query(ctx, `SELECT f.user_id,f.factor_id,f.activation_before_version::text,r.state,r.row_version::text FROM identity_mfa.otp_factors f LEFT JOIN identity_mfa.recovery_sets r ON r.tenant_id=f.tenant_id AND r.user_id=f.user_id AND r.factor_id=f.factor_id AND r.set_id=f.factor_id AND r.factor_method='otp' WHERE f.tenant_id=$1 AND f.activation_command_id=$2`, string(b.TenantID), id)
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
	var user, factor, before string
	var state *int16
	var version *string
	if rows.Scan(&user, &factor, &before, &state, &version) != nil || rows.Next() || rows.Err() != nil || user != string(b.UserID) || factor != b.RecordID || before != strconv.FormatUint(life.BeforeVersion, 10) || state == nil || *state < 2 || version == nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	v, err := strconv.ParseUint(*version, 10, 64)
	if err != nil || v < 2 {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return kernel.RecoveryCommitted, nil
}
