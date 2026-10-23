package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/session"
)

var _ mfapg.OTPActivePrimarySource = (*PasswordActiveTOTPPrimarySource)(nil)

// PrepareOTPSend authenticates actual current cookie custody for the keyed
// active-OTP action, not the historical pending enrollment. MFA must bind the
// original factor, action and verified recipient separately and perform current
// owner/CSRF checks in Work. The returned observation's deadline is unchanged.
func (s *PasswordActiveTOTPPrimarySource) PrepareOTPSend(ctx context.Context, r mfa.OtpSendRequest, command identity.CommandID) (mfapg.OTPActivePrimary, session.GetResult, error) {
	if ctx == nil || s == nil || s.sessions == nil || r.StepUp == nil || r.Validate() != nil {
		return nil, session.GetResult{}, session.ErrInvalidSessionCommand
	}
	if _, err := identity.ParseCommandID(string(command)); err != nil {
		return nil, session.GetResult{}, session.ErrInvalidSessionCommand
	}
	return s.prepareCurrent(ctx, activeSessionRequest{TenantID: r.TenantID, UserID: identity.UserID(r.Caller.Request.Subject.ID), CommandID: command, OperationID: "identity.mfa.otp-send", Session: r.StepUp.Session, CSRFToken: r.StepUp.CSRFToken})
}

// RestoreOTPSend verifies possession against only the MFA-authenticated original
// current-session snapshot. It performs no IO, pending-enrollment translation,
// factor verification or freshness renewal. Current Work checks remain required.
func (s *PasswordActiveTOTPPrimarySource) RestoreOTPSend(ctx context.Context, r mfa.OtpSendRequest, command identity.CommandID, wire []byte) (mfapg.OTPActivePrimary, error) {
	if ctx == nil || s == nil || s.sessions == nil || r.StepUp == nil || r.Validate() != nil || len(wire) < 1 || len(wire) > 32768 {
		return nil, session.ErrInvalidSessionCommand
	}
	if _, err := identity.ParseCommandID(string(command)); err != nil {
		return nil, session.ErrInvalidSessionCommand
	}
	return s.restoreCurrent(ctx, activeSessionRequest{TenantID: r.TenantID, UserID: identity.UserID(r.Caller.Request.Subject.ID), CommandID: command, OperationID: "identity.mfa.otp-send", Session: r.StepUp.Session, CSRFToken: r.StepUp.CSRFToken}, wire)
}

// PrepareOTPVerify reads the real current password/MFA session for the explicit
// active-OTP verification arm. It grants neither code comparison nor factor
// proof. The OTP/MFA owners must restore the exact send and independently bind
// its session, factor, action, recipient and original expiry before comparison.
func (s *PasswordActiveTOTPPrimarySource) PrepareOTPVerify(ctx context.Context, r mfa.OtpVerifyRequest) (mfapg.OTPActivePrimary, session.GetResult, error) {
	if ctx == nil || s == nil || s.sessions == nil || r.StepUp == nil || r.Validate() != nil {
		return nil, session.GetResult{}, session.ErrInvalidSessionCommand
	}
	return s.prepareCurrent(ctx, activeSessionRequest{TenantID: r.TenantID, UserID: identity.UserID(r.Caller.Request.Subject.ID), CommandID: r.CommandID, OperationID: "identity.mfa.otp-verify", Session: r.StepUp.Session, CSRFToken: r.StepUp.CSRFToken})
}

// RestoreOTPVerify checks original current-session custody without IO or
// renewed authority. Only MFA-authenticated snapshot bytes are accepted here;
// this source does not establish that the submitted OTP or send is valid.
func (s *PasswordActiveTOTPPrimarySource) RestoreOTPVerify(ctx context.Context, r mfa.OtpVerifyRequest, wire []byte) (mfapg.OTPActivePrimary, error) {
	if ctx == nil || s == nil || s.sessions == nil || r.StepUp == nil || r.Validate() != nil || len(wire) < 1 || len(wire) > 32768 {
		return nil, session.ErrInvalidSessionCommand
	}
	return s.restoreCurrent(ctx, activeSessionRequest{TenantID: r.TenantID, UserID: identity.UserID(r.Caller.Request.Subject.ID), CommandID: r.CommandID, OperationID: "identity.mfa.otp-verify", Session: r.StepUp.Session, CSRFToken: r.StepUp.CSRFToken}, wire)
}
