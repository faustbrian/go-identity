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

// MFARecoveryCompletionEffect persists original-primary sessions only after the
// actual recovery-code burn and continuation completion in this same Work.
// Configuration is immutable; it owns no transaction, pool, callback or goroutine.
// This is a native effect, not a public recovery-code authentication service.
type MFARecoveryCompletionEffect struct{ native *MFATOTPCompletionEffect }

// NewMFARecoveryCompletionEffect selects genuine magic-link-primary/recovery
// issuance without IO. Install MFARecoveryMigrationSource and MFA issuance
// history after predecessors. The native owner must independently authenticate
// original primary/browser/child and current MFA policy before recording a burn.
func NewMFARecoveryCompletionEffect(c Config, p MagicLinkAdmissionConfig) (*MFARecoveryCompletionEffect, error) {
	engine, err := NewMFATOTPCompletionEffect(c, p)
	if err != nil {
		return nil, err
	}
	return &MFARecoveryCompletionEffect{native: engine}, nil
}

// NewMFAPasswordRecoveryCompletionEffect selects original password-primary and
// credential custody instead of magic-link authority. It never compares a
// password or converts metadata into proof. Installation, ownership and bounded
// execution follow NewMFARecoveryCompletionEffect; configuration performs no IO.
func NewMFAPasswordRecoveryCompletionEffect(c Config, p IdentifierAdmissionConfig) (*MFARecoveryCompletionEffect, error) {
	engine, err := NewMFAPasswordTOTPCompletionEffect(c, p)
	if err != nil {
		return nil, err
	}
	return &MFARecoveryCompletionEffect{native: engine}, nil
}

// Apply requires actual same-invocation recorded consumption, original primary
// and remember/factor/set provenance, current directory/credential/policy fences
// and remaining issuance lifetime. Projection-only or TOTP custody cannot
// substitute the handle. Burn, child, session, risk, audit and lifecycle commit
// or roll back through the sole coordinator. Return every error to abort.
func (e *MFARecoveryCompletionEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.MFACompletionContributor, command identity.Command, recipient kernel.RecipientRecord, completed mfapg.LockedRecoveryCompletion) (identity.FeatureReceipt, error) {
	if e == nil || e.native == nil {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	return e.native.applyNativeMFA(ctx, w, owner, command, recipient, "recovery-code", func(ctx context.Context) (mfa.ContinuationSpec, mfaRecordedFactor, identity.CommandID, error) {
		scope, set, primary, err := mfapg.RequireRecordedRecoveryCompletion(ctx, w, owner, command, completed)
		if err != nil {
			return mfa.ContinuationSpec{}, mfaRecordedFactor{}, "", err
		}
		_, plan, err := w.MFACompletionConsumption(owner)
		if err != nil {
			return mfa.ContinuationSpec{}, mfaRecordedFactor{}, "", err
		}
		return scope, mfaRecordedFactor{FactorID: set.FactorID, EnrollmentVersion: set.FactorEnrollmentVersion, FactorAuthorityVersion: scope.FactorVersion, ScopeDigest: plan.ScopeDigest, RecoverySetID: identity.CommandID(set.SetID), RecoverySetVersion: set.SetVersion}, primary, nil
	})
}

// Recover votes only from original method-specific retained issuance evidence.
// It needs no current code, bearer or live session and cannot redeliver or repeat
// authentication. The coordinator reconciles the vote with the original journal
// and other participants; uncertain or unavailable evidence remains unknown.
func (e *MFARecoveryCompletionEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.MFACompletionContributor) (kernel.RecoveryStatus, error) {
	if e == nil || e.native == nil {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	return e.native.recoverNativeMFA(ctx, w, owner, "recovery-code")
}

// Format prevents traversal into deployment configuration.
func (*MFARecoveryCompletionEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.MFARecoveryCompletionEffect(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (*MFARecoveryCompletionEffect) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit export and map-key disclosure.
func (*MFARecoveryCompletionEffect) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

func mfaRecoveryIssuanceDigest(binding [32]byte, user, id, family string, record []byte) [32]byte {
	return nativeIssuanceDigest("identity-session-mfa-recovery-issuance-v1\x00", binding, user, id, family, record)
}
