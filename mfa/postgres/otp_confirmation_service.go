package mfapostgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/risk"
)

// OTPEnrollmentConfirmationConfig selects the original native primary source
// and retained OTP attempt key. Origins, issuance, original custody and store
// owners are inherited from the actual sender, not new request-selected policy.
type OTPEnrollmentConfirmationConfig struct {
	Primary           OTPEnrollmentConfirmationPrimarySource
	AttemptKeyVersion uint32
}

// OTPEnrollmentConfirmationService confirms a pending OTP factor without a
// login session, another primary-proof consumption or trusted-device issuance.
// It borrows immutable native owners; concurrent calls use separate phases.
type OTPEnrollmentConfirmationService struct {
	state *otpEnrollmentConfirmationState
}
type otpEnrollmentConfirmationState struct {
	shared  *totpURIState
	sender  *otpEnrollmentSendState
	primary OTPEnrollmentConfirmationPrimarySource
	owner   OTPEnrollmentConfirmationOwner
	key     uint32
}

func otpConfirmationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-verify", SchemaID: "mfa-otp-enrollment-confirm", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// NewOTPEnrollmentConfirmationService freezes native composition without IO,
// code generation or activation. The sender must own actual retained MFA/OTP
// custody and a complete consuming contributor. Install OTP consuming history
// before use. Missing risk, original primary, key or selected owner denies.
func NewOTPEnrollmentConfirmationService(sender *OTPEnrollmentSendService, c OTPEnrollmentConfirmationConfig) (*OTPEnrollmentConfirmationService, error) {
	if sender == nil || sender.state == nil || nilEnrollmentPrimary(c.Primary) || c.AttemptKeyVersion == 0 {
		return nil, invalidEnrollment()
	}
	owner, ok := sender.state.issuance.(OTPEnrollmentConfirmationOwner)
	if !ok || nilEnrollmentPrimary(owner) || nilEnrollmentPrimary(owner.ConfirmationContributor()) || owner.ValidateConfirmationKey(c.AttemptKeyVersion) != nil {
		return nil, invalidEnrollment()
	}
	shared := &totpURIState{enrollment: sender.state.common.enrollment, config: TOTPURIConfig{AllowedOrigins: slices.Clone(sender.state.common.config.AllowedOrigins)}}
	profile, err := shared.enrollment.config.Counters.CommandCounters.Policy.Admit(risk.Action(otpConfirmationOperation().OperationID))
	if err != nil || profile.Profile.Class != risk.CredentialMutation {
		return nil, invalidEnrollment()
	}
	frame := append(slices.Clone(sender.state.common.identity[:]), []byte("mfa-otp-enrollment-confirm-v1\x00")...)
	frame = binary.BigEndian.AppendUint32(frame, c.AttemptKeyVersion)
	shared.identity = sha256.Sum256(frame)
	clear(frame)
	return &OTPEnrollmentConfirmationService{state: &otpEnrollmentConfirmationState{shared: shared, sender: sender.state, primary: c.Primary, owner: owner, key: c.AttemptKeyVersion}}, nil
}

// OtpVerify accepts only explicit pending enrollment. It authenticates the
// actual original send and primary, retains one server-owned OTP attempt in the
// existing preparation, then atomically activates factor/recovery authority and
// finalizes OTP. Wrong submissions charge once; replay/recovery create no code,
// factor successor, session, proof, delivery or renewed original lifetime.
func (s *OTPEnrollmentConfirmationService) OtpVerify(ctx context.Context, r mfa.OtpVerifyRequest) (out mfa.OtpVerifyResult, err error) {
	if ctx == nil || s == nil || s.state == nil || r.Validate() != nil {
		return out, invalidEnrollment()
	}
	if r.Enrollment == nil || r.TrustDevice || !slices.Contains(s.state.shared.config.AllowedOrigins, r.Origin) {
		return out, identity.ForbiddenError{}
	}
	state := s.state
	ctx, stop := context.WithTimeout(ctx, state.shared.enrollment.config.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out.Enrollment = mfa.Enrollment{}
		}
	}()
	p := &totpURIPhase{state: state.shared, otpConfirmation: state, otpConfirmRequest: r, request: mfa.TotpUriRequest{TenantID: r.TenantID, CommandID: r.CommandID, EnrollmentID: mfa.EnrollmentID(r.FactorID), Session: r.Enrollment.Session, CSRFToken: r.Enrollment.CSRFToken, Caller: r.Caller, Origin: r.Origin, Network: r.Network}}
	defer p.destroy()
	if err = p.loadOTPConfirmation(ctx); err != nil {
		return out, err
	}
	c, registry, err := state.shared.enrollment.coordinator(p)
	if err != nil {
		return out, err
	}
	p.coordinator, p.registry = c, registry
	if err = p.buildCommand(); err != nil {
		return out, err
	}
	result, err := c.ExecutePreparedFeature(ctx, p.command, p.plan)
	out.Outcome = result.Outcome
	if err == nil && result.Outcome == identity.CommitOutcomeCommitted {
		out.Enrollment = mfa.Enrollment{ID: mfa.EnrollmentID(r.FactorID), FactorMethod: "otp", Version: p.pending.RowVersion + 1, ExpiresAt: p.pending.metadata().ExpiresAt}
	}
	if err == nil && result.Outcome == identity.CommitOutcomeNotCommitted {
		err = identity.ForbiddenError{}
	}
	return out, err
}

// RecoverOtpVerify reconciles original code/session/proof-free history under
// current result-access authorization. Complete frozen native participants,
// including OTP, must agree; absence or expired live custody is not rollback.
func (s *OTPEnrollmentConfirmationService) RecoverOtpVerify(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out mfa.OtpVerifyResult, err error) {
	if ctx == nil || s == nil || s.state == nil || q.OperationID != otpConfirmationOperation().OperationID {
		return out, invalidEnrollment()
	}
	ctx, stop := context.WithTimeout(ctx, s.state.shared.enrollment.config.MaximumDuration)
	defer stop()
	p := &totpURIPhase{state: s.state.shared, otpConfirmation: s.state}
	c, _, err := s.state.shared.enrollment.coordinator(p)
	if err != nil {
		return out, err
	}
	receipt, err := c.RecoverFeatureCommand(ctx, q, caller)
	out.Outcome = receipt.Outcome
	return out, err
}

func (OTPEnrollmentConfirmationConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.OTPEnrollmentConfirmationConfig(redacted)"))
}
func (OTPEnrollmentConfirmationConfig) MarshalJSON() ([]byte, error) { return nil, invalidEnrollment() }
func (OTPEnrollmentConfirmationConfig) MarshalText() ([]byte, error) { return nil, invalidEnrollment() }
func (OTPEnrollmentConfirmationService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.OTPEnrollmentConfirmationService(redacted)"))
}
func (OTPEnrollmentConfirmationService) MarshalJSON() ([]byte, error) {
	return nil, invalidEnrollment()
}
func (OTPEnrollmentConfirmationService) MarshalText() ([]byte, error) {
	return nil, invalidEnrollment()
}
