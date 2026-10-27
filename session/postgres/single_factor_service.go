package postgres

import (
	"fmt"
	"strings"

	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// SingleFactorSessionAdmissionConfig explicitly selects owned authentication
// profiles. At least one is required; deployment, policy namespace and audience
// must agree. No selection implies authority for another method. Organization,
// MFA and passkey dimensions remain denied until their owners are composed.
type SingleFactorSessionAdmissionConfig struct {
	Verified  *IdentifierAdmissionConfig
	OTP       *OTPAdmissionConfig
	MagicLink *MagicLinkAdmissionConfig
}

// SingleFactorSessionServiceConfig selects one bounded primary lookup followed
// by dispatch on the stored authentication kind. Repository and Validation
// retain their existing ownership, cancellation and lifetime contracts. Install
// every selected method's native migration histories before calls. No fallback
// reader, caller-owned domain store, transaction or policy callback is accepted.
type SingleFactorSessionServiceConfig struct {
	Repository Config
	Admission  SingleFactorSessionAdmissionConfig
	Validation session.ServiceConfig
}

func singleFactorAdmission(c SingleFactorSessionAdmissionConfig) ([]session.AuthenticationKind, string, error) {
	var methods []session.AuthenticationKind
	var common OTPAdmissionConfig
	fields := []string{"native-single-factor-session-v1"}
	selectProfile := func(kind session.AuthenticationKind, profile OTPAdmissionConfig) bool {
		if !profile.valid() || len(methods) > 0 && profile != common {
			return false
		}
		common = profile
		methods = append(methods, kind)
		fields = append(fields, fmt.Sprint(kind), profile.GlobalAuthorityID, profile.PolicyNamespace, profile.Audience)
		return true
	}
	if c.Verified != nil {
		p := *c.Verified
		if !p.valid() || p.CredentialKind == identity.CredentialPasskey || !selectProfile(session.AuthenticationVerified, OTPAdmissionConfig{p.GlobalAuthorityID, p.PolicyNamespace, p.Audience}) {
			return nil, "", session.ErrInvalidInput
		}
		fields = append(fields, p.AuthenticationMethod, fmt.Sprint(p.CredentialKind), p.CredentialOwner)
	}
	if c.OTP != nil && !selectProfile(session.AuthenticationOTP, *c.OTP) {
		return nil, "", session.ErrInvalidInput
	}
	if c.MagicLink != nil && !selectProfile(session.AuthenticationMagicLink, OTPAdmissionConfig(*c.MagicLink)) {
		return nil, "", session.ErrInvalidInput
	}
	if len(methods) == 0 {
		return nil, "", session.ErrInvalidInput
	}
	return methods, nativeAdmissionCacheProfile(fields...), nil
}

// NewSingleFactorSessionService freezes selected native profiles without IO,
// caches, goroutines or writes. One primary digest lookup identifies the record;
// only that method's selected owner path may authenticate it. A denial or outage
// never tries another profile. The caller closes the primary pool after calls
// finish. Cache custody binds the entire selected set and exact owner/store
// profiles, preserving the earliest original authority-read expiry.
func NewSingleFactorSessionService(pool *database.Pool, c SingleFactorSessionServiceConfig) (*session.SessionService, error) {
	methods, profile, err := singleFactorAdmission(c.Admission)
	if err != nil {
		return nil, err
	}
	return newSelectedNativeSessionService(pool, c, nil, nil, nil, nil, nil, methods, profile)
}

func newSelectedNativeSessionService(pool *database.Pool, c SingleFactorSessionServiceConfig, mfa *MagicLinkAdmissionConfig, passwordMFA *IdentifierAdmissionConfig, passkey *PasskeySessionAdmission, mfaPasskey *MFAPasskeySessionAdmission, organization *OrganizationPasswordSessionAdmission, methods []session.AuthenticationKind, profile string) (*session.SessionService, error) {
	if c.Repository.MaximumDuration > c.Validation.MaximumDuration {
		return nil, session.ErrInvalidInput
	}
	var audience string
	if p := c.Admission.Verified; p != nil {
		audience = p.Audience
	}
	if p := c.Admission.OTP; p != nil {
		audience = p.Audience
	}
	if p := c.Admission.MagicLink; p != nil {
		audience = p.Audience
	}
	if mfa != nil {
		audience = mfa.Audience
	}
	if passwordMFA != nil {
		audience = passwordMFA.Audience
	}
	if passkey != nil {
		audience = passkey.Profile.Audience
	}
	if mfaPasskey != nil {
		audience = mfaPasskey.Profile.Audience
	}
	if p := organization; p != nil {
		audience = p.Profile.Audience
	}
	if audience != c.Validation.Audience {
		return nil, session.ErrInvalidInput
	}
	native, err := NewRepository(pool, c.Repository)
	if err != nil {
		return nil, err
	}
	domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.Repository.MaximumDuration})
	if err != nil {
		return nil, err
	}
	policy, err := authority.NewAuthorityStore(pool.Raw(), c.Repository.MaximumDuration)
	if err != nil {
		return nil, session.ErrInvalidInput
	}
	r := &primarySessionReader{native: native, domain: domain, policy: policy, clock: c.Validation.Clock}
	clone := func(value string) string { return strings.Clone(value) }
	if p := c.Admission.Verified; p != nil {
		r.profile = *p
		r.profile.GlobalAuthorityID, r.profile.PolicyNamespace, r.profile.Audience = clone(p.GlobalAuthorityID), clone(p.PolicyNamespace), clone(p.Audience)
		r.profile.AuthenticationMethod, r.profile.CredentialOwner = clone(p.AuthenticationMethod), clone(p.CredentialOwner)
	}
	if p := c.Admission.OTP; p != nil {
		r.otp = &OTPAdmissionConfig{clone(p.GlobalAuthorityID), clone(p.PolicyNamespace), clone(p.Audience)}
	}
	if p := c.Admission.MagicLink; p != nil {
		r.magicLink = &MagicLinkAdmissionConfig{clone(p.GlobalAuthorityID), clone(p.PolicyNamespace), clone(p.Audience)}
	}
	if p := mfa; p != nil {
		r.mfaMagicLink = &MagicLinkAdmissionConfig{clone(p.GlobalAuthorityID), clone(p.PolicyNamespace), clone(p.Audience)}
	}
	if mfa != nil || passwordMFA != nil || mfaPasskey != nil {
		r.mfaFactors, err = mfapg.NewTOTPSessionFactorReader(pool, c.Repository.MaximumDuration)
		if err != nil {
			return nil, session.ErrInvalidInput
		}
	}
	if p := passwordMFA; p != nil {
		r.mfaOTPFactors, err = mfapg.NewOTPSessionFactorReader(pool, c.Repository.MaximumDuration)
		if err != nil {
			return nil, session.ErrInvalidInput
		}
		copied := *p
		copied.GlobalAuthorityID, copied.PolicyNamespace, copied.Audience, copied.AuthenticationMethod, copied.CredentialOwner = clone(p.GlobalAuthorityID), clone(p.PolicyNamespace), clone(p.Audience), clone(p.AuthenticationMethod), clone(p.CredentialOwner)
		r.mfaPasswordReader = &primarySessionReader{native: native, domain: domain, policy: policy, clock: c.Validation.Clock, profile: copied, mfaPassword: true, mfaFactors: r.mfaFactors, mfaOTPFactors: r.mfaOTPFactors}
	}
	if p := passkey; p != nil {
		selected := &passkeySessionSelection{profile: freezePasskeyProfile(p.Profile), authority: p.Authority}
		r.passkeyReader = &primarySessionReader{native: native, domain: domain, policy: policy, clock: c.Validation.Clock, passkey: selected}
	}
	if p := mfaPasskey; p != nil {
		selected := &mfaPasskeySessionSelection{profile: freezePasskeyProfile(p.Profile), authority: p.Authority}
		r.mfaPasskeyReader = &primarySessionReader{native: native, domain: domain, policy: policy, clock: c.Validation.Clock, mfaFactors: r.mfaFactors, mfaPasskey: selected}
	}
	if p := organization; p != nil {
		copied := *p
		r.organizationPasswordReader = &primarySessionReader{native: native, domain: domain, policy: policy, clock: c.Validation.Clock, profile: copied.Profile, organizationPassword: &copied}
		return session.NewOrganizationBearerProfileSessionService(r, c.Validation, methods, nativeAdmissionCacheProfile(c.Repository.Schema, profile))
	}
	return session.NewSelectedProfileSessionService(r, c.Validation, methods, nativeAdmissionCacheProfile(c.Repository.Schema, profile))
}

// Format redacts correlated native owner configuration.
func (SingleFactorSessionAdmissionConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SingleFactorSessionAdmissionConfig(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (SingleFactorSessionAdmissionConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// Format redacts key and deployment configuration.
func (SingleFactorSessionServiceConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SingleFactorSessionServiceConfig(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (SingleFactorSessionServiceConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
