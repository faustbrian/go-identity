package postgres

import (
	"fmt"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// SSOOIDCSessionAdmission selects original single-factor enterprise OIDC
// cookie sessions. Use the same selection for the native reader and strict
// cookie revoke-one executor. Authority must enforce the original selected
// organization and active member on the same primary and in existing Work.
// This does not enable social OAuth, provider logout, or session rotation.
type SSOOIDCSessionAdmission struct {
	Profile   IdentifierAdmissionConfig
	Authority OrganizationSessionAuthority
}

func (p SSOOIDCSessionAdmission) valid() bool {
	return p.Profile.valid() && p.Profile.AuthenticationMethod == "sso-oidc" && p.Profile.CredentialKind == identity.CredentialProvider && p.Profile.CredentialOwner == "sso" && !nilIssueDependency(p.Authority)
}

// Format redacts deployment and borrowed authority details.
func (SSOOIDCSessionAdmission) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SSOOIDCSessionAdmission(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (SSOOIDCSessionAdmission) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

func ssoOIDCCredentialSessionAdmission(p SSOOIDCSessionAdmission, record session.Session, binding identity.CommandBinding) (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
	deny := func() (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
		return kernel.DirectoryAuthorityAdmission{}, kernel.CredentialAdmission{}, kernel.UserAuthorizationAdmission{}, identity.ForbiddenError{}
	}
	if !p.valid() || record.MFAAuthentication() != (session.MFAAuthentication{}) {
		return deny()
	}
	if _, continued := record.CredentialContinuation(); continued {
		return deny()
	}
	if _, err := record.CSRFState().Bindings(); err != nil {
		return deny()
	}
	spec, err := record.Bindings()
	if err != nil || spec.Authentication.Proof.Purpose != "session-issue" {
		return deny()
	}
	vector, err := spec.Authority.Bindings()
	if err != nil || !vector.Organization.Present || !vector.Factor.Present || vector.Passkey.Present {
		return deny()
	}
	return credentialSessionAdmissionBindingsWithOrganization(p.Profile, record, binding, spec.SessionID, spec.Version,
		vector.Factor, session.OptionalAuthorityBinding{}, vector.Organization, authentication.AssuranceSingleFactor)
}

func selectedSSOOIDCAdmission(c SelectedSessionAdmissionConfig) ([]session.AuthenticationKind, string, error) {
	p := c.SSOOIDC
	if p == nil || !p.valid() {
		return nil, "", session.ErrInvalidInput
	}
	common := OTPAdmissionConfig{p.Profile.GlobalAuthorityID, p.Profile.PolicyNamespace, p.Profile.Audience}
	var existingProfiles []OTPAdmissionConfig
	for _, profile := range []*IdentifierAdmissionConfig{c.SingleFactor.Verified, c.SingleFactor.OAuth, c.MFAPassword} {
		if profile != nil {
			existingProfiles = append(existingProfiles, OTPAdmissionConfig{profile.GlobalAuthorityID, profile.PolicyNamespace, profile.Audience})
		}
	}
	for _, profile := range []*MagicLinkAdmissionConfig{c.SingleFactor.MagicLink, c.MFAMagicLink} {
		if profile != nil {
			existingProfiles = append(existingProfiles, OTPAdmissionConfig(*profile))
		}
	}
	if profile := c.SingleFactor.OTP; profile != nil {
		existingProfiles = append(existingProfiles, *profile)
	}
	if profile := c.Passkey; profile != nil {
		existingProfiles = append(existingProfiles, OTPAdmissionConfig{profile.Profile.GlobalAuthorityID, profile.Profile.PolicyNamespace, profile.Profile.Audience})
	}
	if profile := c.MFAPasskey; profile != nil {
		existingProfiles = append(existingProfiles, OTPAdmissionConfig{profile.Profile.GlobalAuthorityID, profile.Profile.PolicyNamespace, profile.Profile.Audience})
	}
	if profile := c.OrganizationPassword; profile != nil {
		existingProfiles = append(existingProfiles, OTPAdmissionConfig{profile.Profile.GlobalAuthorityID, profile.Profile.PolicyNamespace, profile.Profile.Audience})
	}
	for _, profile := range existingProfiles {
		if profile != common {
			return nil, "", session.ErrInvalidInput
		}
	}
	var methods []session.AuthenticationKind
	var previous string
	if len(existingProfiles) > 0 {
		prior := c
		prior.SSOOIDC = nil
		var err error
		methods, previous, err = selectedSessionAdmission(prior)
		if err != nil {
			return nil, "", err
		}
	}
	for _, method := range methods {
		if method == session.AuthenticationVerified {
			return methods, nativeAdmissionCacheProfile("native-sso-oidc-cookie-session-v1", previous, common.GlobalAuthorityID, common.PolicyNamespace, common.Audience), nil
		}
	}
	return append(methods, session.AuthenticationVerified), nativeAdmissionCacheProfile("native-sso-oidc-cookie-session-v1", previous, common.GlobalAuthorityID, common.PolicyNamespace, common.Audience), nil
}
