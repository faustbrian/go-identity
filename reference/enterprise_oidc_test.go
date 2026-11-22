package reference

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReferenceEnterpriseOIDCIsOptIn(t *testing.T) {
	config, dependencies, features := serverFixture(t)
	server, err := NewServer(config, dependencies, features)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []struct{ operation, method, path string }{
		{"identity.sso.signin-start", http.MethodPost, "/v1/sso/signin-start"},
		{"identity.sso.oidc-callback", http.MethodGet, "/sso/oidc/callback"},
	} {
		for _, operation := range server.OpenAPI().Operations() {
			if operation.Record.OperationID == route.operation {
				t.Fatalf("unselected %s advertised", route.operation)
			}
		}
		request := httptest.NewRequest(route.method, "https://login.example"+route.path, nil)
		request.RequestURI = request.URL.RequestURI()
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNotFound || response.Header().Get("Set-Cookie") != "" {
			t.Fatalf("unselected %s exposed: %d", route.operation, response.Code)
		}
	}
	for name, config := range map[string]StoreConfiguration{
		"HTTP without native selection":   {HTTPEnterpriseOIDC: &HTTPEnterpriseOIDCConfiguration{}},
		"native without the common graph": {EnterpriseOIDC: &EnterpriseOIDCConfiguration{}},
	} {
		t.Run(name, func(t *testing.T) {
			state := &storeState{}
			if err := state.composeFeatureStores(config, ReferenceDependencies{}); err == nil || state.features != nil {
				t.Fatal("enterprise selection silently dropped without its required owners")
			}
		})
	}
}
