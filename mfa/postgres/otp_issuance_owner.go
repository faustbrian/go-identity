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

// OTPEnrollmentIssuanceOwner is the narrow native OTP port for pending-factor
// sending. Use the real OTP adapter, not application-written code/delivery/risk
// stores. MFA owns original parent/CSRF/factor/risk admission and the sole Work;
// OTP owns generation, same-code custody, shared send limits and digest storage.
// Original preparation bytes are code/bearer-free and may only be restored after
// MFA authenticates its existing encrypted original request binding.
type OTPEnrollmentIssuanceOwner interface {
	PrepareEnrollmentSend(context.Context, *database.Pool, identity.CommandBinding, session.Session, kernel.RecipientRecord, time.Time, time.Time) ([]byte, error)
	GenerateEnrollmentSend(context.Context, identity.Command, []byte, uint64) ([]byte, error)
	RestoreEnrollmentSend(context.Context, identity.Command, []byte, uint64, []byte) (OTPEnrollmentPreparedSend, error)
	RecoverEnrollmentSend(context.Context, kernel.RecoveryWork, kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error)
	DeliveryContributor() *deliverypg.Contributor
	Configuration() ([32]byte, error)
}

// OTPEnrollmentPreparedSend retains the real OTP/delivery effect, not an
// authentication result. Persist must use only this exact native MFA root and
// borrowed Work; return errors to the coordinator and recheck current original
// parent, factor, recipient, risk and lifetime after waits before commit.
type OTPEnrollmentPreparedSend interface {
	Plan() (kernel.DeliveryPlan, error)
	Persist(context.Context, kernel.Work, kernel.FeatureExecutionContributor, identity.Command) error
}
