package reference

import (
	"fmt"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
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
	// FactorManagement separately selects native protected factor updates.
	// Primary/Sessions must be absent: this graph supplies real session owners.
	// ActiveStepUp is required; this field selects no HTTP routes or regeneration.
	// Email removal requires actual PasswordReset request/completion composition;
	// RemovalRecovery must be absent because this graph supplies that owner.
	FactorManagement *mfapg.FactorUpdateConfig
	// Disable independently selects native disable-purpose mutation. Primary,
	// Sessions and Recovery must be absent: the graph supplies actual owners.
	// Requires ActiveStepUp and complete selected emailed-password-reset recovery;
	// it selects no HTTP route or factor-update operation.
	Disable *mfapg.DisableConfig
	// Listing explicitly selects safe TOTP/recovery metadata through the graph's
	// existing real session owner. It selects no HTTP route or trusted devices.
	Listing bool
}

type mfaEnrollmentState struct {
	enable      *mfapg.TOTPEnrollmentService
	uri         *mfapg.TOTPURIService
	confirm     *mfapg.TOTPConfirmationService
	stepup      *mfapg.TOTPActiveStepUpService
	regenerate  *mfapg.RecoveryRegenerationService
	manage      *mfapg.FactorUpdateService
	disable     *mfapg.DisableService
	emailChange bool
}

func composeMFAEnrollment(c StoreConfiguration, d ReferenceDependencies, verification *passwordVerificationState, evaluation risk.Evaluator, reset *passwordpg.ResetService) (*mfaEnrollmentState, error) {
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
	if (p.Regeneration != nil || p.FactorManagement != nil || p.Disable != nil) && p.ActiveStepUp == nil {
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
		state.emailChange = selected.EmailChange
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
		if p.FactorManagement != nil {
			if p.FactorManagement.Primary != nil || p.FactorManagement.Sessions != nil || p.FactorManagement.RemovalRecovery != nil {
				return nil, invalid
			}
			effects, err := sessionpg.NewMFAFactorUpdateSessionEffect(c.PasswordVerification.Native.Session, c.PasswordVerification.Native.Profile)
			if err != nil {
				return nil, invalid
			}
			native := *p.FactorManagement
			native.Primary, native.Sessions = primary, effects
			if native.RemovalRecoveryPath != 0 {
				if native.RemovalRecoveryPath != auth.RecoveryPathEmail {
					return nil, invalid
				}
				native.RemovalRecovery, err = passwordpg.NewFactorRemovalRecoverySource(reset)
				if err != nil {
					return nil, invalid
				}
			}
			state.manage, err = mfapg.NewFactorUpdateService(enable, state.stepup, native)
			if err != nil {
				return nil, invalid
			}
			if native.Replacement != nil {
				effects, err := sessionpg.NewMFATOTPReplacementSessionEffect(c.PasswordVerification.Native.Session, c.PasswordVerification.Native.Profile)
				if err != nil {
					return nil, invalid
				}
				selected := &mfapg.TOTPReplacementContinuationConfig{Management: state.manage, Primary: primary, Sessions: effects}
				state.uri, err = mfapg.NewTOTPURIService(enable, mfapg.TOTPURIConfig{Primary: cookie, AllowedOrigins: p.AllowedOrigins, Replacement: selected})
				if err != nil {
					return nil, invalid
				}
				state.confirm, err = mfapg.NewTOTPConfirmationService(enable, mfapg.TOTPConfirmationConfig{Primary: cookie, AllowedOrigins: p.AllowedOrigins, ComparisonKey: p.ComparisonKey, ComparisonKeyVersion: p.ComparisonKeyVersion, Replacement: selected})
				if err != nil {
					return nil, invalid
				}
			}
		}
		if p.Disable != nil {
			if p.Disable.Primary != nil || p.Disable.Sessions != nil || p.Disable.Recovery != nil || p.Disable.RecoveryPath != auth.RecoveryPathEmail {
				return nil, invalid
			}
			effects, err := sessionpg.NewMFADisableSessionEffect(c.PasswordVerification.Native.Session, c.PasswordVerification.Native.Profile)
			if err != nil {
				return nil, invalid
			}
			recovery, err := passwordpg.NewFactorRemovalRecoverySource(reset)
			if err != nil {
				return nil, invalid
			}
			native := *p.Disable
			native.Primary, native.Sessions, native.Recovery = primary, effects, recovery
			state.disable, err = mfapg.NewDisableService(enable, state.stepup, native)
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
