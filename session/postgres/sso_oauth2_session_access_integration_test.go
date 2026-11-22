//go:build integration

package postgres

import "testing"

// These tests begin with a persisted session and do not claim an OAuth2 exchange.
func TestSSOOAuth2SessionAccessAndStrictCookieLogoutPostgres(t *testing.T) {
	assertSSOSessionAccessAndStrictCookieLogout(t, newSSOSessionAccessFixture(t, "sso-oauth2"))
}

func TestSSOOAuth2SessionAccessRequiresExplicitSelectionAndCurrentAuthorityPostgres(t *testing.T) {
	assertSSOSessionAccessRequiresExplicitSelectionAndCurrentAuthority(t, newSSOSessionAccessFixture(t, "sso-oauth2"))
}

func TestSSOOAuth2AndOIDCSelectedCookieLogoutPostgres(t *testing.T) {
	for _, method := range []string{"sso-oauth2", "sso-oidc"} {
		t.Run(method, func(t *testing.T) {
			f := newSSOSessionAccessFixture(t, method)
			var err error
			f.reader, err = NewSelectedSessionServiceWithSSOOAuth2(f.pool, SelectedSessionServiceConfig{Repository: f.repository, Validation: f.validation, Admission: SelectedSessionAdmissionConfig{SSOOIDC: &f.selection}}, f.oauth2)
			if err != nil {
				t.Fatal("combined enterprise reader", err)
			}
			f.bothSelected = true
			assertSSOSessionAccessAndStrictCookieLogout(t, f)
		})
	}
}
