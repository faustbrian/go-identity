package postgres

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestSelectedSSOOAuth2AdmissionSeparatesGraphs(t *testing.T) {
	profile := IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "backend", AuthenticationMethod: "sso-oauth2", CredentialKind: identity.CredentialProvider, CredentialOwner: "sso"}
	oauth2 := SSOOAuth2SessionAdmission{Profile: profile, Authority: organizationReadAuthority{}}
	methods, oauth2Cache, err := selectedSSOOAuth2Admission(SelectedSessionAdmissionConfig{}, oauth2)
	if err != nil || len(methods) != 1 || methods[0] != session.AuthenticationVerified || oauth2Cache == "" {
		t.Fatal("OAuth-only selection did not retain a verified session profile", err)
	}
	oidc := SSOOIDCSessionAdmission{Profile: profile, Authority: organizationReadAuthority{}}
	oidc.Profile.AuthenticationMethod = "sso-oidc"
	configured := SelectedSessionAdmissionConfig{SSOOIDC: &oidc}
	_, oidcCache, err := selectedSessionAdmission(configured)
	if err != nil {
		t.Fatal(err)
	}
	methods, combined, err := selectedSSOOAuth2Admission(configured, oauth2)
	if err != nil || len(methods) != 1 || combined == oidcCache || combined == oauth2Cache || oauth2Cache == oidcCache {
		t.Fatal("enterprise protocol graph shared cache or duplicated authentication kinds", err)
	}
	oidc.Profile.Audience = "different"
	if _, _, err := selectedSSOOAuth2Admission(configured, oauth2); err == nil {
		t.Fatal("mixed enterprise graph accepted mismatched authority scope")
	}
	oauth2.Profile.AuthenticationMethod = "sso-oidc"
	if _, _, err := selectedSSOOAuth2Admission(SelectedSessionAdmissionConfig{}, oauth2); err == nil {
		t.Fatal("OAuth-only selector accepted OIDC provenance")
	}
}
