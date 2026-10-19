package phone

import identity "github.com/faustbrian/go-identity"

// ErrOTPSigninBinding denies invalid original OTP identifier-binding input.
const ErrOTPSigninBinding NumberError = "identity.phone.otp_signin_binding_invalid"

// OTPSigninIdentifierBinding derives the original phone-OTP pre-auth target
// commitment from an owner-canonical Number, exact tenant and a borrowed,
// deployment-owned 32..64-byte identifier key. It grants no phone possession,
// OTP correctness, account eligibility or authentication. Trusted initiation
// retains it in session.PreAuthIntent.IdentifierBinding; the native workflow
// must compare the same binding before recipient discovery or code work.
// Never accept a browser-selected commitment or reuse a password-signin flow.
//
// Framing matches PasswordSigninIdentifierBinding except for the fixed domain
// identity-phone-otp-signin-binding-v1 NUL and action identity.phone.signin.
// It therefore retains tenant, exact versioned number profile, metadata revision
// and E.164, but is not interchangeable with the password workflow. Display
// spelling is not identity. Preserve the selected key/profile throughout the
// original flow lifetime; copies and retries must not renew that lifetime.
// No IO, callbacks or goroutines run; the caller keeps the key immutable during
// this bounded synchronous call. Invalid input returns zero and the redacted
// ErrOTPSigninBinding sentinel without exposing the number or key.
func OTPSigninIdentifierBinding(number Number, tenant identity.TenantID, key []byte) ([32]byte, error) {
	return signinIdentifierBinding(number, tenant, key, "identity-phone-otp-signin-binding-v1\x00", "identity.phone.signin", ErrOTPSigninBinding)
}
