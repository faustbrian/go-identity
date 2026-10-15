package mfapostgres

import (
	"context"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
)

// OTPEnrollmentConfirmationOwner restores only the actual original send's
// authenticated issuance. MFA supplies its original root and retained input and
// output after authenticating its existing encrypted preparation. Restoration
// generates nothing, renews no validity and grants no comparison/admission.
// The real OTP adapter implements this port; applications do not supply stores.
type OTPEnrollmentConfirmationOwner interface {
	RestoreEnrollmentConfirmation(context.Context, identity.Command, []byte, uint64, []byte) (OTPEnrollmentConfirmation, error)
	ConfirmationContributor() kernel.OTPExecutionContributor
	// ValidateConfirmationKey checks retained native key availability without
	// IO, generation, disclosure or selecting a replacement key version.
	ValidateConfirmationKey(uint32) error
}

// OTPEnrollmentConfirmation retains opaque original issuance at the OTP owner.
// Prepare reads the exact challenge version, creates a fresh server-owned
// attempt and maps the submitted code onto the already frozen MFA root. It
// performs no comparison or mutation. The selected retained attempt key must
// exist; never replace it or the original expiry with a current default.
// Contributor is the real reservation/check/finalize/recovery participant. MFA
// must enlist it in its sole coordinator and enforce current original primary,
// pending factor, recipient and risk before comparison and protected activation.
// The pool and request inputs are borrowed for the bounded call; no handles are
// retained. Copies of the returned command do not grant execution authority.
type OTPEnrollmentConfirmation interface {
	Prepare(context.Context, *database.Pool, identity.Command, auth.OneTimeCode, uint32) (identity.Command, kernel.OTPAttemptPlan, error)
	// RestorePrepared authenticates the original code-free mapped metadata
	// retained in MFA's encrypted preparation, conserves its attempt/version,
	// and independently matches the submitted code and actual session bearer.
	// It performs no IO, comparison, debit, remapping or freshness renewal.
	RestorePrepared(context.Context, identity.Command, auth.OneTimeCode, identity.FeatureCommandSpec) (identity.Command, kernel.OTPAttemptPlan, error)
	Contributor() kernel.OTPExecutionContributor
}
