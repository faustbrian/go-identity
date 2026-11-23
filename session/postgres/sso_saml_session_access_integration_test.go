//go:build integration

package postgres

import "testing"

func TestSSOSAMLSessionAccessAndStrictCookieLogoutPostgres(t *testing.T) {
	assertSSOSessionAccessAndStrictCookieLogout(t, newSSOSessionAccessFixture(t, "sso-saml"))
}

func TestSSOSAMLSessionAccessRequiresExplicitSelectionAndCurrentAuthorityPostgres(t *testing.T) {
	assertSSOSessionAccessRequiresExplicitSelectionAndCurrentAuthority(t, newSSOSessionAccessFixture(t, "sso-saml"))
}
