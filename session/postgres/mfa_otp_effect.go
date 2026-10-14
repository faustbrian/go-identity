package postgres

import (
	"context"
	"fmt"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// MFAOTPCompletionEffect persists an original-password session only after
// actual OTP and child checks and the shared MFA transition in this same Work.
// It owns no transaction, comparison, pool, goroutine or callback. Configuration
// remains immutable and calls borrow independent serial native Work handles.
type MFAOTPCompletionEffect struct{ native *MFATOTPCompletionEffect }

// NewMFAPasswordOTPCompletionEffect selects the closed password/secondary-OTP
// profile without IO, migration, authentication or issuance. Install selected
// OTP/factor/continuation, password-MFA session and issuance histories first.
// Original password/browser, current credential/policy and actual same-Work
// OTP/child consumption remain the native MFA service's responsibilities.
func NewMFAPasswordOTPCompletionEffect(c Config, p IdentifierAdmissionConfig) (*MFAOTPCompletionEffect, error) {
	engine, err := NewMFAPasswordTOTPCompletionEffect(c, p)
	if err != nil {
		return nil, err
	}
	return &MFAOTPCompletionEffect{native: engine}, nil
}

// Apply binds complete original primary/child/factor/remember provenance to
// actual recorded consuming OTP and continuation custody. Metadata or a TOTP/
// recovery handle cannot substitute for that same-Work proof. All current
// authority/time fences repeat around writes; errors roll back session, OTP,
// child, shared attempt, risk, audit and lifecycle through the sole coordinator.
func (e *MFAOTPCompletionEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.MFACompletionContributor, command identity.Command, recipient kernel.RecipientRecord, completed mfapg.LockedOTPCompletion) (identity.FeatureReceipt, error) {
	if e == nil || e.native == nil {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	return e.native.applyNativeMFA(ctx, w, owner, command, recipient, "otp", func(ctx context.Context) (mfa.ContinuationSpec, mfaRecordedFactor, identity.CommandID, error) {
		scope, factor, primary, err := mfapg.RequireRecordedOTPCompletion(ctx, w, owner, command, completed)
		return scope, mfaRecordedFactor{FactorID: factor.FactorID, EnrollmentVersion: factor.EnrollmentVersion, FactorAuthorityVersion: factor.FactorAuthorityVersion, ScopeDigest: factor.ScopeDigest}, primary, err
	})
}

// Recover votes only from the exact historical OTP-specific issuance identity;
// it never compares, consumes, generates or redelivers a credential. The sole
// coordinator reconciles it with all original participants and the journal.
func (e *MFAOTPCompletionEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.MFACompletionContributor) (kernel.RecoveryStatus, error) {
	if e == nil || e.native == nil {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	return e.native.recoverNativeMFA(ctx, w, owner, "otp")
}

// Format prevents diagnostic traversal of native configuration.
func (*MFAOTPCompletionEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.MFAOTPCompletionEffect(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (*MFAOTPCompletionEffect) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText denies implicit textual configuration export.
func (*MFAOTPCompletionEffect) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

func mfaOTPIssuanceDigest(binding [32]byte, user, id, family string, record []byte) [32]byte {
	return nativeIssuanceDigest("identity-session-mfa-otp-issuance-v1\x00", binding, user, id, family, record)
}
