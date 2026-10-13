package reference

import (
	"fmt"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
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
	// ActiveStepUp independently selects native authenticated TOTP proof issuance.
	// Primary must be absent; this graph supplies the real cookie/session owner.
	// This selects no HTTP routes or login-completion fallback.
	ActiveStepUp *mfapg.TOTPActiveStepUpConfig
	// Regeneration separately selects fresh-proof-consuming whole-set replacement.
	// Primary and Sessions must be absent; this graph supplies real native owners.
	// ActiveStepUp is required. No HTTP route is selected by this field.
	Regeneration *mfapg.RecoveryRegenerationConfig
	// Listing explicitly selects safe TOTP/recovery metadata through the graph's
	// existing real session owner. It selects no HTTP route or trusted devices.
	Listing bool
}

type mfaEnrollmentState struct {
	enable     *mfapg.TOTPEnrollmentService
	uri        *mfapg.TOTPURIService
	confirm    *mfapg.TOTPConfirmationService
	stepup     *mfapg.TOTPActiveStepUpService
	regenerate *mfapg.RecoveryRegenerationService
	listing    *mfa.ListService
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
	state := &mfaEnrollmentState{enable: enable, uri: uri, confirm: confirm}
	if p.Regeneration != nil && p.ActiveStepUp == nil {
		return nil, invalid
	}
	if p.ActiveStepUp != nil {
		if c.Session == nil || p.ActiveStepUp.Primary != nil {
			return nil, invalid
		}
		validation := c.Session.Native.Validation
		validation.Clock = c.Session.Native.Execution.Clock
		primary, err := sessionpg.NewPasswordActiveTOTPPrimarySource(d.PostgreSQL, sessionpg.PasswordActiveTOTPPrimaryConfig{Session: sessionpg.SessionServiceConfig{Repository: c.PasswordVerification.Native.Session, Profile: c.PasswordVerification.Native.Profile, Validation: validation}, CSRFKeys: p.CSRFKeys})
		if err != nil {
			return nil, invalid
		}
		selected := *p.ActiveStepUp
		selected.Primary = primary
		state.stepup, err = mfapg.NewTOTPActiveStepUpService(enable, selected)
		if err != nil {
			return nil, invalid
		}
		if p.Regeneration != nil {
			if p.Regeneration.Primary != nil || p.Regeneration.Sessions != nil {
				return nil, invalid
			}
			effects, err := sessionpg.NewMFARecoverySessionEffect(c.PasswordVerification.Native.Session, c.PasswordVerification.Native.Profile)
			if err != nil {
				return nil, invalid
			}
			native := *p.Regeneration
			native.Primary = primary
			native.Sessions = effects
			state.regenerate, err = mfapg.NewRecoveryRegenerationService(enable, state.stepup, native)
			if err != nil {
				return nil, invalid
			}
		}
	}
	return state, nil
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
