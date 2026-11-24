package identityhttp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestSAMLLogoutNavigationBindsInstalledProviderAndOrigin(t *testing.T) {
	const path = "/saml2/-selected/slo"
	const sp = "https://login.example"
	const idp = "https://idp.example"
	var dispatched int
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: "sso/saml", OperationID: "identity.sso.saml-slo", MaximumSerializedBytes: 8192,
		ProviderPathIDs: []string{"-selected"}, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			dispatched++
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.WriteHeader(http.StatusNoContent)
		}),
	})
	if err != nil {
		t.Fatal("select only the installed provider's logout path", err)
	}
	op.Wire = &identityhttp.WireOperation{Definition: []byte(`{
  "operationId":"identity.sso.saml-slo",
  "parameters":[{"name":"provider_id","in":"path","required":true,"schema":{"type":"string"}}],
  "responses":{"204":{"description":"Selected logout navigation"}}
}`)}
	policy := identityhttp.CORSRoutePolicy{Method: http.MethodPost, Path: path,
		Credentials: identityhttp.CORSSAMLLogoutPostNavigation, Origins: []identityhttp.Origin{sp, idp}}
	transport := identityhttp.TransportPolicy{Network: networkConfig(), CORS: []identityhttp.CORSRoutePolicy{policy},
		HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}}
	h, _, err := identityhttp.NewRouter(transport, []identityhttp.OperationDescriptor{op}, nil)
	if err != nil {
		t.Fatal("construct exact SLO navigation-only routing", err)
	}
	for _, tc := range []struct {
		name, path, origin, host string
		preflight                bool
		status                   int
	}{
		{"installed IdP", path, idp, "login.example", false, http.StatusNoContent},
		{"SP is not the sender", path, sp, "login.example", false, http.StatusForbidden},
		{"foreign sender", path, "https://other.example", "login.example", false, http.StatusForbidden},
		{"missing origin", path, "", "login.example", false, http.StatusForbidden},
		{"opaque origin", path, "null", "login.example", false, http.StatusForbidden},
		{"wrong SP host", path, idp, "tenant.example", false, http.StatusForbidden},
		{"preflight", path, idp, "login.example", true, http.StatusForbidden},
		{"unknown provider", "/saml2/other/slo", sp, "login.example", false, http.StatusNotFound},
		{"escaping alias", "/saml2/%2dselected/slo", idp, "login.example", false, http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			method := http.MethodPost
			if tc.preflight {
				method = http.MethodOptions
			}
			r := corsRequest(method, tc.path, tc.origin)
			r.Host = tc.host
			if tc.preflight {
				r.Header.Set("Access-Control-Request-Method", http.MethodPost)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status || w.Header().Get("Access-Control-Allow-Origin") != "" || w.Header().Get("Access-Control-Allow-Credentials") != "" {
				t.Fatalf("got %d, want %d without CORS access", w.Code, tc.status)
			}
		})
	}
	if dispatched != 1 {
		t.Fatalf("only the exact installed sender may dispatch, got %d", dispatched)
	}
	for _, wrong := range []identityhttp.CORSRoutePolicy{
		{},
		{Method: http.MethodPost, Path: path, Credentials: identityhttp.CORSNoCredentials, Origins: policy.Origins},
		{Method: http.MethodPost, Path: path, Credentials: identityhttp.CORSSAMLIDPPostNavigation, Origins: policy.Origins},
		{Method: http.MethodPost, Path: path, Credentials: policy.Credentials, Origins: []identityhttp.Origin{idp}},
		{Method: http.MethodPost, Path: path, Credentials: policy.Credentials, Origins: policy.Origins, AllowedHeaders: []string{"Content-Type"}},
	} {
		transport.CORS = nil
		if wrong.Path != "" {
			transport.CORS = []identityhttp.CORSRoutePolicy{wrong}
		}
		if _, _, err := identityhttp.NewRouter(transport, []identityhttp.OperationDescriptor{op}, nil); err == nil {
			t.Fatal("logout must require its exact navigation-only policy", wrong)
		}
	}
}
