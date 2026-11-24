package ssohttp

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-sso/saml"
)

func TestSAMLLogoutStartHTTPRelayStateRequiresExplicitCanonicalSelection(t *testing.T) {
	relay := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	urlAlphabetRelay := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("\xfb\xff", 16)))
	standardAlphabetRelay := base64.RawStdEncoding.EncodeToString([]byte(strings.Repeat("\xfb\xff", 16)))
	request := "SAMLRequest=YQ%3D%3D"
	relayField := "RelayState=" + relay
	algorithm := "SigAlg=" + url.QueryEscape(saml.SignatureAlgorithmRSAPSSSHA256)
	signature := "Signature=Yg%3D%3D"
	selected := samlLogoutStartHTTPEndpoint + "&" + strings.Join([]string{request, relayField, algorithm, signature}, "&")
	legacy := samlLogoutStartHTTPSignedRedirect(samlLogoutStartHTTPEndpoint)

	for _, tc := range []struct {
		name        string
		constructor func(SAMLLogoutStartConfig) (identityhttp.OperationDescriptor, error)
		redirect    string
		localOnly   bool
		noEndpoint  bool
		status      int
		outcome     string
	}{
		{"selected canonical relay", NewSAMLLogoutStartOperationWithRelayState, selected, false, false, http.StatusSeeOther, "redirect"},
		{"selected URL alphabet relay", NewSAMLLogoutStartOperationWithRelayState, strings.Replace(selected, relay, urlAlphabetRelay, 1), false, false, http.StatusSeeOther, "redirect"},
		{"selected relay is required", NewSAMLLogoutStartOperationWithRelayState, legacy, false, false, http.StatusServiceUnavailable, "unavailable"},
		{"duplicate relay", NewSAMLLogoutStartOperationWithRelayState, selected + "&" + relayField, false, false, http.StatusServiceUnavailable, "unavailable"},
		{"relay before request", NewSAMLLogoutStartOperationWithRelayState, samlLogoutStartHTTPEndpoint + "&" + strings.Join([]string{relayField, request, algorithm, signature}, "&"), false, false, http.StatusServiceUnavailable, "unavailable"},
		{"relay after algorithm", NewSAMLLogoutStartOperationWithRelayState, samlLogoutStartHTTPEndpoint + "&" + strings.Join([]string{request, algorithm, relayField, signature}, "&"), false, false, http.StatusServiceUnavailable, "unavailable"},
		{"relay after signature", NewSAMLLogoutStartOperationWithRelayState, legacy + "&" + relayField, false, false, http.StatusServiceUnavailable, "unavailable"},
		{"empty relay", NewSAMLLogoutStartOperationWithRelayState, strings.Replace(selected, relayField, "RelayState=", 1), false, false, http.StatusServiceUnavailable, "unavailable"},
		{"short relay", NewSAMLLogoutStartOperationWithRelayState, strings.Replace(selected, relay, base64.RawURLEncoding.EncodeToString(make([]byte, 31)), 1), false, false, http.StatusServiceUnavailable, "unavailable"},
		{"long relay", NewSAMLLogoutStartOperationWithRelayState, strings.Replace(selected, relay, base64.RawURLEncoding.EncodeToString(make([]byte, 33)), 1), false, false, http.StatusServiceUnavailable, "unavailable"},
		{"malformed relay", NewSAMLLogoutStartOperationWithRelayState, strings.Replace(selected, relay, strings.Repeat("!", 43), 1), false, false, http.StatusServiceUnavailable, "unavailable"},
		{"noncanonical trailing bits", NewSAMLLogoutStartOperationWithRelayState, strings.Replace(selected, relay, strings.Repeat("A", 42)+"B", 1), false, false, http.StatusServiceUnavailable, "unavailable"},
		{"padded relay", NewSAMLLogoutStartOperationWithRelayState, strings.Replace(selected, relay, relay+"%3D", 1), false, false, http.StatusServiceUnavailable, "unavailable"},
		{"standard base64 alphabet", NewSAMLLogoutStartOperationWithRelayState, strings.Replace(selected, relay, url.QueryEscape(standardAlphabetRelay), 1), false, false, http.StatusServiceUnavailable, "unavailable"},
		{"noncanonical query escape", NewSAMLLogoutStartOperationWithRelayState, strings.Replace(selected, relay, "%41"+relay[1:], 1), false, false, http.StatusServiceUnavailable, "unavailable"},
		{"malformed query escape", NewSAMLLogoutStartOperationWithRelayState, strings.Replace(selected, relay, "%ZZ"+relay[1:], 1), false, false, http.StatusServiceUnavailable, "unavailable"},
		{"changed fixed query", NewSAMLLogoutStartOperationWithRelayState, strings.Replace(selected, "profile=selected", "profile=other", 1), false, false, http.StatusServiceUnavailable, "unavailable"},
		{"legacy rejects selected relay", NewSAMLLogoutStartOperation, selected, false, false, http.StatusServiceUnavailable, "unavailable"},
		{"legacy retains signed redirect", NewSAMLLogoutStartOperation, legacy, false, false, http.StatusSeeOther, "redirect"},
		{"selected local only with endpoint", NewSAMLLogoutStartOperationWithRelayState, "", true, false, http.StatusOK, "local-only"},
		{"selected local only without endpoint", NewSAMLLogoutStartOperationWithRelayState, "", true, true, http.StatusOK, "local-only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, probe := samlLogoutStartHTTPFixture(t)
			if tc.noEndpoint {
				config.RedirectEndpoint = ""
			}
			probe.result.ProviderRedirect = tc.redirect
			probe.result.LocalOnly = tc.localOnly
			operation, err := tc.constructor(config)
			if err != nil {
				t.Fatal("select SAML logout start profile", err)
			}
			router, _, err := identityhttp.NewRouter(identityhttp.TransportPolicy{
				Network: config.Network, HandlerTimeout: time.Second,
				Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"},
			}, []identityhttp.OperationDescriptor{operation}, nil)
			if err != nil {
				t.Fatal("compose selected SAML logout start through the canonical router", err)
			}

			response := httptest.NewRecorder()
			router.ServeHTTP(response, samlLogoutStartHTTPRequest())
			if response.Code != tc.status || probe.calls != 1 {
				t.Fatal("selected SAML logout changed its authoritative outcome", response.Code)
			}
			wantLocation := ""
			if tc.status == http.StatusSeeOther {
				wantLocation = tc.redirect
			}
			if response.Header().Get("Location") != wantLocation {
				t.Fatal("SAML logout exposed an unselected redirect or changed the signed wire")
			}
			requireSAMLLogoutStartHTTPProjection(t, response, tc.outcome, probe.result.LocalRevocation)
			requireLogoutCookieDeletion(t, response)
			for _, forbidden := range []string{relay, "SAMLRequest", "RelayState", "Signature", logoutSessionWire, "original-logout-key"} {
				if strings.Contains(response.Body.String(), forbidden) {
					t.Fatal("SAML logout JSON exposed native wire or browser credentials")
				}
			}
		})
	}
}
