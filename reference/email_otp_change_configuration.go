package reference

import (
	"fmt"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// EmailOTPChangeConfiguration has the same explicit bounded issuance and key
// fields as EmailOTPVerificationConfiguration, but Policy must select email
// change. It requires Email.Change with its old-address notice, actual password
// session authority and an independent request-key namespace. The graph supplies
// the original native owner; callers cannot substitute origin custody. Native
// selection enables no HTTP route or automatic login. First-primary establishment
// additionally requires Email.OTPChangeInitialPrimary and the original explicit
// sole-verified change policy; zero retains genuine-primary replacement only.
type EmailOTPChangeConfiguration EmailOTPVerificationConfiguration

func composeEmailOTPChange(c StoreConfiguration, d ReferenceDependencies, base otppg.SendConfig, crypto *envelope.Service, e *emailState) (*otppg.EmailChangeService, error) {
	if c.Email == nil || c.Email.OTPChange == nil || e == nil || e.change == nil || c.Email.OTPVerification != nil && c.Email.OTPChange.RequestKeys.Namespace == c.Email.OTPVerification.RequestKeys.Namespace {
		return nil, identity.InvalidInputError{Field: "reference_email_otp_change"}
	}
	n := *c.Email.OTPChange
	base, err := emailOTPSendConfig(c, EmailOTPVerificationConfiguration(n), base, "identity.otp.email-change-confirm")
	if err != nil {
		return nil, err
	}
	return otppg.NewEmailChangeService(d.PostgreSQL, otppg.EmailChangeConfig{Send: base, Domain: n.Domain, Source: e.change, CurrentAttemptKeyVersion: n.CurrentAttemptKeyVersion, AllowInitialPrimary: c.Email.OTPChangeInitialPrimary, VerificationHooks: n.VerificationHooks}, crypto)
}

// Format redacts retained session/request keys and deployment configuration.
func (EmailOTPChangeConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.EmailOTPChangeConfiguration(redacted)"))
}

// MarshalJSON rejects implicit key export.
func (EmailOTPChangeConfiguration) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// MarshalText rejects implicit key export.
func (EmailOTPChangeConfiguration) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}
