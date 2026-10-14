package postgres

import (
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// PasswordSignupSessionFields freezes the complete prospective single-factor
// password session into session.result fields. It retains the new user separately
// from anonymous registration scope. No verifier, cookie or bearer is projected.
// Like signin's structural record mapping, this grants no authentication or
// verification/MFA policy admission. Native registration must retain all fields
// before fingerprinting and admit the exact original in its transaction.
func PasswordSignupSessionFields(record session.Session) ([]identity.FeatureField, error) {
	return PasswordSigninSessionFields(record)
}

// PasswordSignupSession restores only the complete session-owned fields of the
// closed paired password-signup v1 command. Missing, malformed, foreign, mixed,
// ordinary and signin variants deny. No normalization, policy decision, flow
// consumption, authentication or freshness renewal occurs. Inputs must remain
// immutable during this bounded call; correlated fields must not be logged.
func PasswordSignupSession(command identity.Command) (session.Session, error) {
	p, ok := command.PasswordSignupFeature()
	_, _, custody := command.PasswordSignupCustody()
	if !ok || !custody || p.Operation != passwordSignupSessionOperation(p.Binding) {
		return session.Session{}, session.ErrInvalidSessionCommand
	}
	return passwordSessionFromFeature(p)
}

func passwordSignupSessionOperation(b identity.CommandBinding) identity.FeatureOperation {
	op := passwordSessionOperation(b)
	op.OperationID, op.SchemaID = "identity.password.signup", "password-signup"
	return op
}
