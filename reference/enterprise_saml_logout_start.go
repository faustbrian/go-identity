package reference

import (
	"slices"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

// EnterpriseSAMLLogoutStartConfiguration selects the native SP start.
// An empty RedirectEndpoint selects local-only revocation. An approved IdP
// Redirect endpoint requires the retained SAML logout-subject configuration.
// FinalRedirectAllowlist contains exact SP-origin URLs distinct from login
// callbacks; the browser can choose one but cannot supply an IdP endpoint.
type EnterpriseSAMLLogoutStartConfiguration struct {
	RedirectEndpoint       string
	FinalRedirectAllowlist []string
	// RequestKeys owns the original keyed logout, never the canonical sign-in.
	RequestKeys kernel.RequestKeyConfig
}

type enterpriseSAMLLogoutStartState struct {
	local    *ssopg.ProviderSAMLLogoutService
	remote   *ssopg.ProviderSAMLLogoutRedirectService
	endpoint string
	final    []string
}

func validateEnterpriseSAMLLogoutStartSelection(n *EnterpriseSAMLConfiguration, h *HTTPEnterpriseSAMLConfiguration) error {
	invalid := identity.InvalidInputError{Field: "reference_enterprise_saml_logout_start"}
	if n.LogoutStart == nil {
		if h != nil && h.LogoutStart {
			return invalid
		}
		return nil
	}
	if n.LogoutStart.RequestKeys.Namespace == "" || n.LogoutStart.RequestKeys.Namespace == n.Login.RequestKeys.Namespace {
		return invalid
	}
	if n.LogoutStart.RedirectEndpoint == "" {
		return nil
	}
	if n.Logout == nil || h != nil && h.LogoutStart && !h.Logout {
		return invalid
	}
	return nil
}

func composeEnterpriseSAMLLogoutStart(c StoreConfiguration, d ReferenceDependencies, n EnterpriseSAMLConfiguration,
	login *ssopg.ProviderLoginService, custody *ssopg.SAMLLogoutSubjectCustody) (*enterpriseSAMLLogoutStartState, error) {
	selected := n.LogoutStart
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
	// Match the selected session reader's SAML provenance. The native start
	// revalidates that exact admission and original stored synchronizer.
	admission := sessionpg.SSOSAMLSessionAdmission{Profile: sessionpg.IdentifierAdmissionConfig{
		GlobalAuthorityID: execution.Profile.GlobalAuthorityID, PolicyNamespace: execution.Profile.PolicyNamespace,
		Audience: execution.Profile.Audience, AuthenticationMethod: "sso-saml",
		CredentialKind: identity.CredentialProvider, CredentialOwner: "sso",
	}, Authority: authority}
	local, err := ssopg.NewProviderSAMLLogoutServiceWithRequestKeys(login, ssopg.ProviderSAMLLogoutConfig{
		Session: validation, Admission: admission, CSRFKeys: c.Session.CSRFKeys, FinalRedirectAllowlist: selected.FinalRedirectAllowlist,
	}, selected.RequestKeys)
	if err != nil {
		return nil, err
	}
	out := &enterpriseSAMLLogoutStartState{local: local, endpoint: selected.RedirectEndpoint, final: slices.Clone(selected.FinalRedirectAllowlist)}
	if selected.RedirectEndpoint == "" {
		return out, nil
	}
	out.remote, err = local.WithProviderRedirect(custody, []ssopg.ProviderSAMLLogoutRedirectProfile{{
		Provider: n.Profile, IdentityProviderEntityID: n.Logout.IdentityProviderEntityID, Endpoint: selected.RedirectEndpoint,
	}})
	if err != nil {
		return nil, err
	}
	return out, nil
}
