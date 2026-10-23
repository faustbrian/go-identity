package mfapostgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// OTPActiveIssuanceOwner is the real OTP owner's explicit authenticated
// step-up profile. MFA retains current session/CSRF, factor, action and risk
// admission in its sole Work. OTP owns generation, digest/challenge storage,
// shared send limits, consuming attempts and encrypted delivery. Original
// records must remain in MFA's existing authenticated preparation; they are
// neither an independent journal nor live permission. No pending-enrollment
// or partial-login owner can silently select this profile.
type OTPActiveIssuanceOwner interface {
	PrepareStepUpSend(context.Context, *database.Pool, identity.CommandBinding, session.Session, kernel.RecipientRecord, time.Time, time.Time) ([]byte, error)
	GenerateStepUpSend(context.Context, identity.Command, []byte, uint64) ([]byte, error)
	RestoreStepUpSend(context.Context, identity.Command, []byte, uint64, []byte) (OTPEnrollmentPreparedSend, error)
	RecoverStepUpSend(context.Context, kernel.RecoveryWork, kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error)
	RestoreStepUpVerification(context.Context, identity.Command, []byte, uint64, []byte) (OTPActiveVerification, error)
	ConfirmationContributor() kernel.OTPExecutionContributor
	ValidateConfirmationKey(uint32) error
	DeliveryContributor() *deliverypg.Contributor
	Configuration() ([32]byte, error)
}

// OTPActiveVerification lends the real OTP attempt participant for the exact
// original active send. Its preparation vocabulary is shared, not enrollment
// authority: the native owner must bind the original send, source session,
// factor and action and atomically consume OTP with signed factor evidence.
// Prepare/RestorePrepared do not compare or debit a code or renew freshness.
type OTPActiveVerification interface{ OTPEnrollmentConfirmation }
