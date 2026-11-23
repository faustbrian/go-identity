package reference

import (
	"slices"

	identity "github.com/faustbrian/go-identity"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/faustbrian/go-sso/oidc"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

// EnterpriseOIDCLogoutConfiguration selects native logout for this installed
// OIDC provider. Empty EndSessionEndpoint permits local-only logout. The final
// redirect list is exact and independent from sign-in redirects.
type EnterpriseOIDCLogoutConfiguration struct {
	EndSessionEndpoint     string
	FinalRedirectAllowlist []string
}

type enterpriseOIDCLogoutState struct {
	service  *ssopg.ProviderLogoutService
	endpoint string
	final    []string
	expose   bool
}

func composeEnterpriseOIDCLogout(c StoreConfiguration, d ReferenceDependencies, state *enterpriseOIDCState) (*enterpriseOIDCLogoutState, error) {
	selected := c.EnterpriseOIDC.Logout
	if selected == nil {
		return nil, nil
	}
	execution := c.Session.Native.Execution
	validation := c.Session.Native.Validation
	validation.Clock = execution.Clock
	authority, err := organizationpg.NewRepository(d.PostgreSQL, c.Organization.Repository)
	if err != nil {
		return nil, err
	}
	admission := sessionpg.SSOOIDCSessionAdmission{Profile: sessionpg.IdentifierAdmissionConfig{
		GlobalAuthorityID: execution.Profile.GlobalAuthorityID, PolicyNamespace: execution.Profile.PolicyNamespace,
		Audience: execution.Profile.Audience, AuthenticationMethod: "sso-oidc", CredentialKind: identity.CredentialProvider, CredentialOwner: "sso",
	}, Authority: authority}
	profile := state.profile
	var remote []ssopg.ProviderLogoutProfile
	if selected.EndSessionEndpoint != "" {
		login, err := state.completion.SigninProtocolProfile(profile.OrganizationID, profile.ProviderID)
		if err != nil {
			return nil, err
		}
		remote = []ssopg.ProviderLogoutProfile{{OrganizationID: profile.OrganizationID, ProviderID: profile.ProviderID, Protocol: oidc.RPLogoutProfileConfig{
			Issuer: login.Issuer, ClientID: profile.ClientID, EndSessionEndpoint: selected.EndSessionEndpoint,
			CallbackURI: state.origin + "/sso/oidc/" + string(profile.ProviderID) + "/logout/callback",
		}}}
	}
	native, err := ssopg.NewProviderLogoutService(state.start, ssopg.ProviderLogoutConfig{
		Session: validation, Admission: admission, CSRFKeys: c.Session.CSRFKeys, Profiles: remote, FinalRedirectAllowlist: selected.FinalRedirectAllowlist,
	})
	if err != nil {
		return nil, err
	}
	return &enterpriseOIDCLogoutState{service: native, endpoint: selected.EndSessionEndpoint, final: slices.Clone(selected.FinalRedirectAllowlist),
		expose: c.HTTPEnterpriseOIDC != nil && c.HTTPEnterpriseOIDC.ProviderLogout}, nil
}
