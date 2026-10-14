package mfapostgres

import (
	"context"
	"encoding/base64"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func (p *totpURIPhase) admitOTPSend(ctx context.Context, w kernel.Work) error {
	if p.sendInput == nil || p.pending == nil || p.pending.Input.OTP == nil {
		return invalidEnrollment()
	}
	if err := p.checkOTPSendState(ctx, w, false); err != nil {
		return err
	}
	return p.primary.Check(ctx, w, p, p.command)
}

// Root, factor and recipient stay locked through the effect. OTP's native
// issuance separately fences its original directory/credential/recipient and
// send-family authority. A late check cannot renew either original lifetime.
func (p *totpURIPhase) checkOTPSendState(ctx context.Context, w kernel.Work, applied bool) error {
	if p.sendInput == nil || p.pending == nil || p.pending.Input.OTP == nil {
		return invalidEnrollment()
	}
	m := *p.pending.Input.OTP
	b := p.pending.binding()
	rows, err := w.Query(ctx, `SELECT version::text,active_factors FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE`, string(m.TenantID), string(m.UserID))
	if err != nil {
		return err
	}
	var authority string
	var active int32
	if !rows.Next() || rows.Scan(&authority, &active) != nil {
		rows.Close()
		return identity.ForbiddenError{}
	}
	extra, rowErr := rows.Next(), rows.Err()
	rows.Close()
	if extra || rowErr != nil || active != 0 || authority != strconv.FormatUint(p.pending.AuthorityVersion, 10) {
		return identity.ForbiddenError{}
	}
	rows, err = w.Query(ctx, `SELECT row_version::text,created_command_id,identifier_id,identifier_version::text,verification_version::text,channel,enrollment_expires_at,last_send_command_id,COALESCE(last_send_before_version::text,'') FROM identity_mfa.otp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=1 FOR UPDATE`, string(m.TenantID), string(m.UserID), m.FactorID)
	if err != nil {
		return err
	}
	var version, identifier, iv, vv, channel, before string
	var parent, sendID []byte
	var expires time.Time
	if !rows.Next() || rows.Scan(&version, &parent, &identifier, &iv, &vv, &channel, &expires, &sendID, &before) != nil {
		rows.Close()
		return identity.ForbiddenError{}
	}
	extra, rowErr = rows.Next(), rows.Err()
	rows.Close()
	expected := p.pending.RowVersion
	if applied {
		expected++
	}
	if extra || rowErr != nil || version != strconv.FormatUint(expected, 10) || base64.RawURLEncoding.EncodeToString(parent) != string(b.CommandID) || identifier != string(m.IdentifierID) || iv != strconv.FormatUint(m.IdentifierVersion, 10) || vv != strconv.FormatUint(m.VerificationVersion, 10) || channel != otpChannelText(m.Channel) || !expires.Equal(m.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	if applied && (base64.RawURLEncoding.EncodeToString(sendID) != string(p.request.CommandID) || before != strconv.FormatUint(p.pending.RowVersion, 10)) {
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

func (p *totpURIPhase) applyOTPSend(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p.preparedSend == nil || p.sendInput == nil {
		return identity.FeatureReceipt{}, invalidEnrollment()
	}
	if err := p.preparedSend.Persist(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	id, _ := base64.RawURLEncoding.Strict().DecodeString(string(p.request.CommandID))
	n, err := w.Exec(ctx, `UPDATE identity_mfa.otp_factors SET last_send_command_id=$4,last_send_before_version=row_version,row_version=row_version+1 WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=1 AND row_version=$5::numeric`, string(p.request.TenantID), string(p.pending.binding().UserID), string(p.request.EnrollmentID), id, strconv.FormatUint(p.pending.RowVersion, 10))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	p.applied = true
	if err := p.CheckFeatureCommit(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: otpSendOperation(), BeforeVersion: p.pending.RowVersion, AfterVersion: p.pending.RowVersion + 1}, nil
}
