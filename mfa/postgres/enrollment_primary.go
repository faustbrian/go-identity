package mfapostgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// TOTPEnrollmentPrimary extends the protected primary participant with original
// request preparation and secret-free recovery. Snapshot exports only transient
// provenance for native authenticated encryption; it is never naked authority.
// Original supplies immutable historical session metadata, not current access.
// Methods are bounded and do not own transactions, clocks, caches or goroutines.
type TOTPEnrollmentPrimary interface {
	TOTPEnrollmentPrimaryAdmission
	Admit(context.Context, kernel.Work, kernel.FeatureExecutionContributor, identity.Command) error
	Deadline() (time.Time, error)
	Original() (session.Session, error)
	Snapshot() ([]byte, error)
	Command(identity.CommandBinding, []identity.FeatureField) (identity.Command, error)
	Recover(context.Context, kernel.RecoveryWork, kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error)
}

// TOTPEnrollmentPrimarySource is the consumer-owned native primary boundary.
// Select a real platform adapter, not a consumer-written authentication callback.
// PrepareEnrollment validates original signed evidence and current possession
// outside Work. RestoreEnrollment is IO-free and accepts only provenance the
// native enrollment owner has authenticated under its complete encrypted input
// binding. Neither return value grants mutation: the protected participant must
// consume/check exact primary authority atomically with pending-factor effects.
// The original request, factor identity and evidence cannot change on retry.
type TOTPEnrollmentPrimarySource interface {
	PrepareEnrollment(context.Context, mfa.EnableRequest, identity.CommandID, mfa.FactorID) (TOTPEnrollmentPrimary, error)
	RestoreEnrollment(context.Context, mfa.EnableRequest, identity.CommandID, mfa.FactorID, []byte) (TOTPEnrollmentPrimary, error)
	RecoverEnrollment(context.Context, kernel.RecoveryWork, kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error)
}

// TOTPURIPrimary is original-session custody for a separate pending-enrollment
// disclosure. Admit must fence current primary owners, the retained synchronizer
// and the exact parent enrollment's consumed verification record in the borrowed
// Work. It cannot consume another proof or renew any original freshness boundary.
type TOTPURIPrimary interface {
	Admit(context.Context, kernel.Work, kernel.FeatureExecutionContributor, identity.Command) error
	Check(context.Context, kernel.Work, kernel.FeatureExecutionContributor, identity.Command) error
	Deadline() (time.Time, error)
	Original() (session.Session, error)
	Command(identity.CommandBinding, []identity.FeatureField) (identity.Command, error)
}

// TOTPURIPrimarySource restores only provenance authenticated by the native
// enrollment owner's original encrypted request binding. Parent command and
// row version come from the pending factor, not transport-supplied metadata.
// Origin policy, factor expiry, risk and atomic revelation remain MFA's owners.
type TOTPURIPrimarySource interface {
	RestoreEnrollmentForURI(context.Context, mfa.TotpUriRequest, identity.CommandID, uint64, []byte) (TOTPURIPrimary, error)
}

// TOTPConfirmationPrimarySource restores the same original enable provenance
// for code-confirmed activation, not URI disclosure or login-child completion.
// It must enforce original session/synchronizer and retained parent proof use.
// Restoration grants no activation: MFA still owns actual code verification,
// current factor/recovery policy and atomic required session effects.
type TOTPConfirmationPrimarySource interface {
	RestoreEnrollmentForConfirmation(context.Context, mfa.TotpVerifyRequest, identity.CommandID, uint64, []byte) (TOTPConfirmationPrimary, error)
}

// TOTPConfirmationPrimary shares the bounded primary method vocabulary but
// requires custody for the enrollment-confirmation schema/lifecycle only.
// An implementation must reject using this value in a URI or login command.
type TOTPConfirmationPrimary interface{ TOTPURIPrimary }

// OTPEnrollmentSendPrimarySource restores the exact original enable/session
// custody for native pending OTP sending. assigned is the sole request-key
// owner's command ID. Restoration grants no factor or delivery authority;
// current Admit/Check and unchanged synchronizer/parent consumption are required.
type OTPEnrollmentSendPrimarySource interface {
	RestoreEnrollmentForOTPSend(context.Context, mfa.OtpSendRequest, identity.CommandID, identity.CommandID, uint64, []byte) (TOTPURIPrimary, error)
}

// OTPEnrollmentConfirmationPrimarySource restores the original enable/session
// and synchronizer only for authenticated pending OTP confirmation. It cannot
// consume the primary proof again, select login custody or renew freshness.
type OTPEnrollmentConfirmationPrimarySource interface {
	RestoreEnrollmentForOTPConfirmation(context.Context, mfa.OtpVerifyRequest, identity.CommandID, uint64, []byte) (TOTPURIPrimary, error)
}

// TOTPReplacementPrimarySource restores an original active-session snapshot
// only after MFA authenticates its committed factor-update parent. Neither
// method translates it into password-enable evidence, creates factor proof or
// renews the retained validity deadline. MFA fences original replacement
// lineage and current predecessor authority in the protected Work.
type TOTPReplacementPrimarySource interface {
	RestoreReplacementForURI(context.Context, mfa.TotpUriRequest, []byte, time.Time) (TOTPReplacementPrimary, error)
	RestoreReplacementForConfirmation(context.Context, mfa.TotpVerifyRequest, []byte, time.Time) (TOTPReplacementPrimary, error)
}

// TOTPReplacementPrimary separates immutable authenticated parent custody from
// a new bounded authoritative observation. ReadCurrent runs before protected
// locks and retains its first actual read deadline; repeated calls must not
// renew that observation. OriginalDeadline identifies the unchanged parent's
// initial observation, not continuing permission. Historical outcome replay
// restores original custody without requiring a still-active source session.
type TOTPReplacementPrimary interface {
	TOTPURIPrimary
	ReadCurrent(context.Context) error
	OriginalDeadline() (time.Time, error)
}

// TOTPReplacementContinuationConfig explicitly selects the same native
// management owner that created the successor and its original-session adapter.
// Owners are borrowed and must outlive all bounded continuation calls.
type TOTPReplacementContinuationConfig struct {
	Management *FactorUpdateService
	Primary    TOTPReplacementPrimarySource
	// Sessions is required for confirmation and unused by URI revelation.
	Sessions RecoveryRegenerationSessionEffects
}
