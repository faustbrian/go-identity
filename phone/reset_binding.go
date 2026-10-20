package phone

import identity "github.com/faustbrian/go-identity"

// ErrPasswordResetBinding denies invalid original recovery target input.
const ErrPasswordResetBinding NumberError = "identity.phone.password_reset_binding_invalid"

// PasswordResetIdentifierBinding derives the original sessionless recovery
// target from an owner-canonical Number, exact tenant and a borrowed deployment-
// owned 32..64-byte identifier key. Trusted initiation stores the result in
// session.PreAuthIntent.IdentifierBinding with PreAuthPhonePasswordRecovery;
// the native reset owner must recompute and compare it before account discovery
// or credential work. A caller-selected commitment is never authority.
//
// Framing is identical to PasswordSigninIdentifierBinding except for domain
// identity-phone-password-reset-binding-v1 NUL and fixed action
// identity.phone.password-reset-request. Neither password nor OTP signin
// commitments can substitute. Canonical aliases share the same target; display
// spelling, a session policy and remember choices are not part of recovery.
// Retain the original key/profile for the original flow's absolute lifetime;
// key rotation or retries do not renew it. This derives no cookie, proof, OTP,
// recipient eligibility or risk decision, and enables no recovery workflow.
//
// No IO, callbacks or goroutines run. The caller owns the immutable key during
// this bounded synchronous call. Invalid input returns zero and the redacted
// ErrPasswordResetBinding sentinel without exposing the number or key.
func PasswordResetIdentifierBinding(number Number, tenant identity.TenantID, key []byte) ([32]byte, error) {
	return signinIdentifierBinding(number, tenant, key, "identity-phone-password-reset-binding-v1\x00", "identity.phone.password-reset-request", ErrPasswordResetBinding)
}
