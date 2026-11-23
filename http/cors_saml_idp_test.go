package identityhttp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestSAMLIDPPostNavigationOnlyAllowsSelectedOriginAndNoScriptAccess(t *testing.T) {
	const path = "/saml2/-selected/idp-init"
	const origin = "https://login.example"
	const idp = "https://idp.example"
	policy := identityhttp.CORSRoutePolicy{Method: http.MethodPost, Path: path, Credentials: identityhttp.CORSSAMLIDPPostNavigation,
		Origins: []identityhttp.Origin{origin, idp}}
	var calls int
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: "sso/saml", OperationID: "identity.sso.saml-idp-init", MaximumSerializedBytes: 8192, ProviderPathIDs: []string{"-selected"},
		CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.WriteHeader(http.StatusNoContent)
		}),
	})
	if err != nil {
		t.Fatal("select the exact installed IdP-init route", err)
	}
	op.Wire = &identityhttp.WireOperation{Definition: []byte(`{
  "operationId":"identity.sso.saml-idp-init",
  "parameters":[{"name":"provider_id","in":"path","required":true,"schema":{"type":"string"}}],
  "responses":{"204":{"description":"Selected navigation"}}
}`)}
	network := networkConfig()
	network.PublicHosts = append(network.PublicHosts, "idp.example")
	transport := identityhttp.TransportPolicy{Network: network, CORS: []identityhttp.CORSRoutePolicy{policy},
		HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}}
	handler, _, err := identityhttp.NewRouter(transport, []identityhttp.OperationDescriptor{op}, nil)
	if err != nil {
		t.Fatal("select the two-origin navigation-only transport", err)
	}
	for _, tc := range []struct {
		path, origin string
		preflight    bool
		status       int
	}{
		{path, idp, false, http.StatusNoContent}, {path, origin, false, http.StatusNoContent},
		{path, "https://foreign.example", false, http.StatusForbidden}, {path, "", false, http.StatusForbidden},
		{path, idp, true, http.StatusForbidden}, {path, origin, true, http.StatusForbidden},
		{"/saml2/other/idp-init", origin, false, http.StatusNotFound},
	} {
		method := http.MethodPost
		if tc.preflight {
			method = http.MethodOptions
		}
		r := corsRequest(method, tc.path, tc.origin)
		if tc.preflight {
			r.Header.Set("Access-Control-Request-Method", http.MethodPost)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.status || w.Header().Get("Access-Control-Allow-Origin") != "" || w.Header().Get("Access-Control-Allow-Credentials") != "" {
			t.Fatalf("unexpected navigation result for %s %s: %d", method, tc.path, w.Code)
		}
	}
	for _, mode := range []identityhttp.CORSCredentialMode{identityhttp.CORSNoCredentials, identityhttp.CORSCookieCredentials, identityhttp.CORSSAMLPostNavigation} {
		wrong := policy
		wrong.Credentials = mode
		transport.CORS = []identityhttp.CORSRoutePolicy{wrong}
		if _, _, err := identityhttp.NewRouter(transport, []identityhttp.OperationDescriptor{op}, nil); err == nil {
			t.Fatal("the selected IdP-init route accepted another transport profile", mode)
		}
	}
	transport.CORS = nil
	if _, _, err := identityhttp.NewRouter(transport, []identityhttp.OperationDescriptor{op}, nil); err == nil {
		t.Fatal("selected IdP-init without its navigation-only transport policy")
	}
	alias := corsRequest(http.MethodPost, path, idp)
	alias.Host = "tenant.example"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, alias)
	if w.Code != http.StatusForbidden {
		t.Fatal("IdP-init admitted a different effective HTTPS origin", w.Code)
	}
	wrongDirection := corsRequest(http.MethodPost, path, origin)
	wrongDirection.Host = "idp.example"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, wrongDirection)
	if w.Code != http.StatusForbidden {
		t.Fatal("IdP-init treated the IdP source origin as the SP destination", w.Code)
	}
	if calls != 2 {
		t.Fatalf("only the two exact selected navigations should dispatch, got %d", calls)
	}
}
