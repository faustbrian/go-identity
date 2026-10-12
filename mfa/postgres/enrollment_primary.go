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
