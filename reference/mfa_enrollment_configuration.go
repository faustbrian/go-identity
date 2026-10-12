package reference

import (
	"fmt"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

// MFAEnrollmentConfiguration explicitly selects native first-factor TOTP
// enable, separate reveal-once provisioning and code-confirmed activation.
// Native.Primary and Native.Risk.Evaluation must be absent: this graph supplies
// its actual password verification and counted risk owners. Primary configures
// the existing signed reauthentication target and freshness, not another engine.
// CSRFKeys must match retained session synchronizers; AllowedOrigins is exact
// HTTPS management policy. No HTTP route is selected by this configuration.
type MFAEnrollmentConfiguration struct {
	Native               mfapg.TOTPEnrollmentConfig
	Primary              passwordpg.MFAEnablePrimaryConfig
	CSRFKeys             []session.CSRFKey
	AllowedOrigins       []string
	ComparisonKey        [32]byte
	ComparisonKeyVersion uint32
}

type mfaEnrollmentState struct {
	enable  *mfapg.TOTPEnrollmentService
	uri     *mfapg.TOTPURIService
	confirm *mfapg.TOTPConfirmationService
}

func composeMFAEnrollment(c StoreConfiguration, d ReferenceDependencies, verification *passwordVerificationState, evaluation risk.Evaluator) (*mfaEnrollmentState, error) {
	if c.MFAEnrollment == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_mfa_enrollment"}
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	if !ok || keys == nil || d.PostgreSQL == nil || c.PasswordVerification == nil || verification == nil || verification.native == nil || c.OTP == nil {
		return nil, invalid
	}
	p, o := c.MFAEnrollment, c.OTP
	n := p.Native
	if n.Primary != nil || n.Risk.Evaluation != (risk.Evaluator{}) || n.MaximumDuration > o.Timeout || n.Counters.Schema != c.Velocity.Schema || n.Counters.CommandCounters == nil || n.Counters.CommandCounters.Policy != c.Velocity.Native.Policy || n.RequestKeys.Policy.PolicyVersion != o.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(n.RequestKeys.Policy.Authorization, o.RequestKeys.Policy.Authorization) {
		return nil, invalid
	}
	for _, policy := range []*kernel.CommandQueryPolicy{n.Coordinator.QueryPolicy, n.Coordinator.AdmissionPolicy} {
		if policy == nil || policy.PolicyVersion != o.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(policy.Authorization, o.RequestKeys.Policy.Authorization) {
			return nil, invalid
		}
	}
	primary, err := passwordpg.NewMFAEnablePrimarySource(verification.native, p.Primary)
	if err != nil {
		return nil, invalid
	}
	cookie, err := passwordpg.NewCookieMFAEnablePrimarySource(primary, p.CSRFKeys)
	if err != nil {
		return nil, invalid
	}
	n.Primary = cookie
	n.Risk.Evaluation = evaluation
	enable, err := mfapg.NewTOTPEnrollmentService(d.PostgreSQL, n, keys)
	if err != nil {
		return nil, invalid
	}
	uri, err := mfapg.NewTOTPURIService(enable, mfapg.TOTPURIConfig{Primary: cookie, AllowedOrigins: p.AllowedOrigins})
	if err != nil {
		return nil, invalid
	}
	confirm, err := mfapg.NewTOTPConfirmationService(enable, mfapg.TOTPConfirmationConfig{Primary: cookie, AllowedOrigins: p.AllowedOrigins, ComparisonKey: p.ComparisonKey, ComparisonKeyVersion: p.ComparisonKeyVersion})
	if err != nil {
		return nil, invalid
	}
	return &mfaEnrollmentState{enable: enable, uri: uri, confirm: confirm}, nil
}

// Format redacts native cryptographic and policy custody.
func (MFAEnrollmentConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.MFAEnrollmentConfiguration(redacted)"))
}

// MarshalJSON denies implicit sensitive configuration export.
func (MFAEnrollmentConfiguration) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// MarshalText denies implicit sensitive configuration export.
func (MFAEnrollmentConfiguration) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
