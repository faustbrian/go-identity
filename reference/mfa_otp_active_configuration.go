package reference

import (
	"fmt"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// MFAOTPActiveStepUpConfiguration selects native action-bound OTP proof
// issuance, not enrollment/login fallback or HTTP. Native.Primary/Issuance must
// be absent: the graph supplies actual owners. Policy is consuming-only
// PurposeStepUp. Delivery templates and retained keys use this same graph.
type MFAOTPActiveStepUpConfiguration struct {
	Native mfapg.OTPActiveStepUpConfig
	Policy otp.AttemptPolicy
	// FactorManagement explicitly selects native OTP rename and atomic session
	// revocation. Explicit email recovery also enables sole-active-OTP removal.
	// Primary/Sessions/RemovalRecovery and replacement overrides must be nil;
	// the graph supplies the actual selected password-reset recovery owner.
	FactorManagement *mfapg.FactorUpdateConfig
}

func composeMFAOTPActiveStepUp(c StoreConfiguration, d ReferenceDependencies, state *mfaOTPEnrollmentState, store otppg.ContributorConfig, delivery *deliverypg.Contributor, reset *passwordpg.ResetService) error {
	invalid := identity.InvalidInputError{Field: "reference_mfa_otp_active"}
	p := c.MFAOTPEnrollment
	if p == nil || p.ActiveStepUp == nil || c.PasswordSignin == nil || c.PasswordSignin.OTP == nil || c.Session == nil || c.PasswordVerification == nil {
		return invalid
	}
	native := p.ActiveStepUp.Native
	if native.Primary != nil || native.Issuance != nil {
		return invalid
	}
	validation := c.Session.Native.Validation
	validation.Clock = c.Session.Native.Execution.Clock
	primary, err := sessionpg.NewPasswordActiveTOTPPrimarySource(d.PostgreSQL, sessionpg.PasswordActiveTOTPPrimaryConfig{Session: sessionpg.SessionServiceConfig{Repository: c.PasswordVerification.Native.Session, Profile: c.PasswordVerification.Native.Profile, Validation: validation}, CSRFKeys: p.CSRFKeys})
	if err != nil {
		return err
	}
	issuer, err := otppg.NewMFAActiveIssuer(otppg.MFAActiveIssuerConfig{Store: store, Session: otppg.SessionAdmissionConfig{Store: c.Session.Native.Execution.Repository, Profile: c.PasswordSignin.Native.Profile, RetainedTokenKeys: p.SessionKeys, FreshnessLimit: p.FreshnessLimit}, Delivery: delivery, Policy: p.ActiveStepUp.Policy, TemplateID: p.TemplateID, TemplateVersion: p.TemplateVersion, ProviderVersion: c.OTP.ProviderVersion, LocaleChain: p.LocaleChain, Templates: c.Delivery.Templates})
	if err != nil {
		return err
	}
	native.Primary, native.Issuance = primary, issuer
	state.active, err = mfapg.NewOTPActiveStepUpService(state.enable, native)
	if err != nil {
		return err
	}
	state.activeIssuer = issuer
	if selected := p.ActiveStepUp.FactorManagement; selected != nil {
		if selected.Primary != nil || selected.Sessions != nil || selected.RemovalRecovery != nil || selected.RemovalRecoveryPath != 0 && selected.RemovalRecoveryPath != auth.RecoveryPathEmail || selected.Replacement != nil {
			return invalid
		}
		effects, e := sessionpg.NewMFAFactorUpdateSessionEffect(c.PasswordVerification.Native.Session, c.PasswordVerification.Native.Profile)
		if e != nil {
			return e
		}
		management := *selected
		management.Primary, management.Sessions = primary, effects
		if management.RemovalRecoveryPath == auth.RecoveryPathEmail {
			management.RemovalRecovery, err = passwordpg.NewFactorRemovalRecoverySource(reset)
			if err != nil {
				return err
			}
		}
		state.manage, err = mfapg.NewOTPFactorUpdateService(state.enable, state.active, management)
		if err != nil {
			return err
		}
	}
	return nil
}

// Format redacts signing and borrowed native configuration.
func (MFAOTPActiveStepUpConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.MFAOTPActiveStepUpConfiguration(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (MFAOTPActiveStepUpConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

// MarshalText rejects implicit configuration export.
func (MFAOTPActiveStepUpConfiguration) MarshalText() ([]byte, error) {
	return nil, identity.ForbiddenError{}
}
