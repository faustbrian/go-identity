package postgres

import (
	"fmt"
	identity "github.com/faustbrian/go-identity"

	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// SelectedSessionAdmissionConfig explicitly selects single-factor, passkey and
// original magic-link/TOTP owners. An MFA record requires the MFA selection; a
// failed factor read never falls back to a single-factor profile. All selected
// owners must share deployment, policy namespace and audience.
type SelectedSessionAdmissionConfig struct {
	SingleFactor SingleFactorSessionAdmissionConfig
	MFAMagicLink *MagicLinkAdmissionConfig
	// MFAPassword selects genuine password-plus-TOTP/OTP/recovery owners independently
	// of single-factor password and magic-link profiles. No fallback is allowed.
	MFAPassword *IdentifierAdmissionConfig
	// Passkey selects the owned RP/mapping and known-empty factor authority.
	// Stored passkey provenance selects only this owner, never another method.
	Passkey *PasskeySessionAdmission
	// MFAPasskey independently selects original passkey plus confirmed TOTP.
	// It cannot fall back to the known-empty Passkey selection or password MFA.
	MFAPasskey *MFAPasskeySessionAdmission
}

// SelectedSessionServiceConfig retains the native repository and validation
// budgets and ownership. Install every selected owner's migration histories.
// The pool is borrowed and must outlive calls; no application store is needed.
type SelectedSessionServiceConfig struct {
	Repository Config
	Admission  SelectedSessionAdmissionConfig
	Validation session.ServiceConfig
}

func selectedSessionAdmission(c SelectedSessionAdmissionConfig) ([]session.AuthenticationKind, string, error) {
	if c.MFAPasskey != nil {
		p := c.MFAPasskey.Profile
		if !p.valid() || nilIssueDependency(c.MFAPasskey.Authority) || c.Passkey != nil && c.Passkey.Profile != p {
			return nil, "", session.ErrInvalidInput
		}
		common := OTPAdmissionConfig{p.GlobalAuthorityID, p.PolicyNamespace, p.Audience}
		profiles := []*OTPAdmissionConfig{c.SingleFactor.OTP}
		for _, v := range []*IdentifierAdmissionConfig{c.SingleFactor.Verified, c.MFAPassword} {
			if v != nil {
				profiles = append(profiles, &OTPAdmissionConfig{v.GlobalAuthorityID, v.PolicyNamespace, v.Audience})
			}
		}
		for _, v := range []*MagicLinkAdmissionConfig{c.SingleFactor.MagicLink, c.MFAMagicLink} {
			if v != nil {
				profile := OTPAdmissionConfig(*v)
				profiles = append(profiles, &profile)
			}
		}
		for _, v := range profiles {
			if v != nil && *v != common {
				return nil, "", session.ErrInvalidInput
			}
		}
		var methods []session.AuthenticationKind
		var previous string
		if c.Passkey != nil || c.SingleFactor.Verified != nil || c.SingleFactor.OTP != nil || c.SingleFactor.MagicLink != nil || c.MFAMagicLink != nil || c.MFAPassword != nil {
			prior := c
			prior.MFAPasskey = nil
			var err error
			methods, previous, err = selectedSessionAdmission(prior)
			if err != nil {
				return nil, "", err
			}
		}
		found := false
		for _, kind := range methods {
			found = found || kind == session.AuthenticationVerified
		}
		if !found {
			methods = append(methods, session.AuthenticationVerified)
		}
		return methods, nativeAdmissionCacheProfile("native-selected-passkey-totp-session-v1", previous, p.GlobalAuthorityID, p.PolicyNamespace, p.Audience, p.RPNamespace), nil
	}
	if c.Passkey != nil {
		p := c.Passkey.Profile
		if !p.valid() || nilIssueDependency(c.Passkey.Authority) {
			return nil, "", session.ErrInvalidInput
		}
		common := OTPAdmissionConfig{p.GlobalAuthorityID, p.PolicyNamespace, p.Audience}
		profiles := []*OTPAdmissionConfig{c.SingleFactor.OTP}
		if v := c.SingleFactor.Verified; v != nil {
			profiles = append(profiles, &OTPAdmissionConfig{v.GlobalAuthorityID, v.PolicyNamespace, v.Audience})
		}
		for _, v := range []*MagicLinkAdmissionConfig{c.SingleFactor.MagicLink, c.MFAMagicLink} {
			if v != nil {
				profile := OTPAdmissionConfig(*v)
				profiles = append(profiles, &profile)
			}
		}
		if v := c.MFAPassword; v != nil {
			profiles = append(profiles, &OTPAdmissionConfig{v.GlobalAuthorityID, v.PolicyNamespace, v.Audience})
		}
		for _, v := range profiles {
			if v != nil && *v != common {
				return nil, "", session.ErrInvalidInput
			}
		}
		var methods []session.AuthenticationKind
		var previous string
		if c.SingleFactor.Verified != nil || c.SingleFactor.OTP != nil || c.SingleFactor.MagicLink != nil || c.MFAMagicLink != nil || c.MFAPassword != nil {
			prior := c
			prior.Passkey = nil
			var err error
			methods, previous, err = selectedSessionAdmission(prior)
			if err != nil {
				return nil, "", err
			}
		}
		found := false
		for _, kind := range methods {
			found = found || kind == session.AuthenticationVerified
		}
		if !found {
			methods = append(methods, session.AuthenticationVerified)
		}
		return methods, nativeAdmissionCacheProfile("native-selected-passkey-session-v1", previous, p.GlobalAuthorityID, p.PolicyNamespace, p.Audience, p.RPNamespace), nil
	}
	if c.MFAPassword != nil {
		p := *c.MFAPassword
		if !p.valid() || p.AuthenticationMethod != "password" || p.CredentialKind != identity.CredentialPassword || p.CredentialOwner != "identity/password" {
			return nil, "", session.ErrInvalidInput
		}
		one := c.SingleFactor
		if one.Verified != nil && *one.Verified != p {
			return nil, "", session.ErrInvalidInput
		}
		one.Verified = &p
		if c.MFAMagicLink != nil {
			one.MagicLink = c.MFAMagicLink
		}
		if _, _, err := singleFactorAdmission(one); err != nil {
			return nil, "", err
		}
		prior := c
		prior.MFAPassword = nil
		var methods []session.AuthenticationKind
		var previous string
		if c.SingleFactor.Verified != nil || c.SingleFactor.OTP != nil || c.SingleFactor.MagicLink != nil || c.MFAMagicLink != nil {
			var err error
			methods, previous, err = selectedSessionAdmission(prior)
			if err != nil {
				return nil, "", err
			}
		}
		found := false
		for _, kind := range methods {
			found = found || kind == session.AuthenticationVerified
		}
		if !found {
			methods = append(methods, session.AuthenticationVerified)
		}
		return methods, nativeAdmissionCacheProfile("native-selected-password-totp-otp-recovery-session-v2", previous, p.GlobalAuthorityID, p.PolicyNamespace, p.Audience, p.AuthenticationMethod, string(p.CredentialKind), p.CredentialOwner), nil
	}
	if c.MFAMagicLink == nil {
		return singleFactorAdmission(c.SingleFactor)
	}
	p := *c.MFAMagicLink
	if !OTPAdmissionConfig(p).valid() {
		return nil, "", session.ErrInvalidInput
	}
	one := c.SingleFactor
	var methods []session.AuthenticationKind
	var singleProfile string
	if one.Verified != nil || one.OTP != nil || one.MagicLink != nil {
		var err error
		methods, singleProfile, err = singleFactorAdmission(one)
		if err != nil {
			return nil, "", err
		}
	}
	// Reuse the native common-owner validator, without enabling its synthetic
	// magic-link selection at runtime. MFA-only remains distinct from combined.
	if one.MagicLink != nil && *one.MagicLink != p {
		return nil, "", session.ErrInvalidInput
	}
	one.MagicLink = &p
	if _, _, err := singleFactorAdmission(one); err != nil {
		return nil, "", err
	}
	found := false
	for _, kind := range methods {
		found = found || kind == session.AuthenticationMagicLink
	}
	if !found {
		methods = append(methods, session.AuthenticationMagicLink)
	}
	profile := nativeAdmissionCacheProfile("native-selected-mfa-session-v1", singleProfile, p.GlobalAuthorityID, p.PolicyNamespace, p.Audience)
	return methods, profile, nil
}

// NewSelectedSessionService freezes all explicitly selected owner profiles
// without IO, writes or goroutines. One primary lookup dispatches on immutable
// stored provenance. Cache custody binds the complete selected set and retains
// the earliest contributing read deadline; selecting MFA cannot renew it.
// With no additional MFA/passkey selection, single-factor cache identity is
// unchanged. Passkey selection shares one lookup, not another reader fallback.
func NewSelectedSessionService(pool *database.Pool, c SelectedSessionServiceConfig) (*session.SessionService, error) {
	methods, profile, err := selectedSessionAdmission(c.Admission)
	if err != nil {
		return nil, err
	}
	return newSelectedNativeSessionService(pool, SingleFactorSessionServiceConfig{Repository: c.Repository, Admission: c.Admission.SingleFactor, Validation: c.Validation}, c.Admission.MFAMagicLink, c.Admission.MFAPassword, c.Admission.Passkey, c.Admission.MFAPasskey, methods, profile)
}

// Format redacts deployment, profile and key configuration.
func (SelectedSessionAdmissionConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SelectedSessionAdmissionConfig(redacted)"))
}

// MarshalJSON rejects implicit correlated configuration export.
func (SelectedSessionAdmissionConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit configuration export and map-key disclosure.
func (SelectedSessionAdmissionConfig) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// Format redacts deployment, profile and key configuration.
func (SelectedSessionServiceConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SelectedSessionServiceConfig(redacted)"))
}

// MarshalJSON rejects implicit correlated configuration export.
func (SelectedSessionServiceConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit configuration export and map-key disclosure.
func (SelectedSessionServiceConfig) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
