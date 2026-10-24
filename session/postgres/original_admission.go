package postgres

import (
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// Validate checks the trusted native admission profile without IO. It creates
// no proof, authority or permission. Zero/invalid fields return a redacted
// InvalidInput error; immutable concurrent reads are safe.
func (profile IdentifierAdmissionConfig) Validate() error {
	if !profile.valid() {
		return identity.InvalidInputError{Field: "session_admission_profile"}
	}
	return nil
}

// OriginalSessionAdmission derives the session owner's exact original primary
// expectations for an already frozen record and its command subject/actor.
// Profile is trusted composition, not request input. Derivation validates every
// owner scope key and the supported single-factor credential/method pairing.
// Anonymous, organization, factor and passkey records deny until their owners
// are composed; no required dimension is omitted. Invalid inputs return zero
// expectations and redacted Forbidden. No IO, primary lookup, clock read,
// authentication, permission decision or freshness renewal occurs.
//
// Native workflows must compare the returned expectations through their live
// primary owners, authenticate the separately submitted bearer, RequireSession
// against this same original record, and recheck temporal validity after waits.
// Neither reconstructed metadata nor these caller-owned expectations authorize
// use. Concurrent immutable reads are safe; do not mutate profile concurrently.
func OriginalSessionAdmission(profile IdentifierAdmissionConfig, original session.Session, binding identity.CommandBinding) (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
	s, err := original.Bindings()
	if err != nil {
		return kernel.DirectoryAuthorityAdmission{}, kernel.CredentialAdmission{}, kernel.UserAuthorizationAdmission{}, identity.ForbiddenError{}
	}
	return sessionAdmissionBindings(profile, original, binding, s.SessionID, s.Version)
}

// OriginalMFAPasswordSessionAdmission derives the exact original password and
// authorization expectations of a completed password/MFA session. It retains
// the native password-primary linkage and factor scope checks; single-factor,
// organization and passkey records deny. This explicit profile does not broaden
// OriginalSessionAdmission. No IO, authentication or freshness renewal occurs.
//
// Callers must separately authenticate possession, fence the original MFA
// factor ID/enrollment/authority through its native owner, require this same
// original session/family, and recheck validity in protected Work. Returned
// expectations alone grant no permission. Immutable reads are concurrency-safe.
func OriginalMFAPasswordSessionAdmission(profile IdentifierAdmissionConfig, original session.Session, binding identity.CommandBinding) (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
	s, err := original.Bindings()
	if err != nil {
		return kernel.DirectoryAuthorityAdmission{}, kernel.CredentialAdmission{}, kernel.UserAuthorizationAdmission{}, identity.ForbiddenError{}
	}
	return passwordMFASessionAdmission(profile, original, binding, s.SessionID, s.Version)
}

// OriginalPasskeySessionAdmission derives the exact original primary directory,
// credential and authorization expectations of a passkey session. Unlike
// OriginalSessionAdmission it retains both RP/passkey and known-empty factor
// dimensions; password, completed-MFA and organization profiles deny. The action's
// target record never replaces the session's authenticating credential.
//
// This pure derivation performs no IO, signature verification, authentication or
// freshness renewal. The native owner must separately authenticate possession,
// require this same session/family, fence the RP/mapping and factor generations
// through PasskeySessionAuthority, and recheck time after waits in protected Work.
// A fresh action also needs a genuine action-bound WebAuthn assertion; a session
// timestamp or these caller-owned expectations do not constitute that proof.
// Immutable profile and record reads support concurrent independent calls.
func OriginalPasskeySessionAdmission(profile PasskeyAdmissionConfig, original session.Session, binding identity.CommandBinding) (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
	return passkeySessionAdmission(profile, original, binding)
}
