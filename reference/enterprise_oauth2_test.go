package reference

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReferenceEnterpriseOAuth2IsOptIn(t *testing.T) {
	config, dependencies, features := serverFixture(t)
	server, err := NewServer(config, dependencies, features)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range server.OpenAPI().Operations() {
		if op.Record.OperationID == "identity.sso.oauth-callback" {
			t.Fatal("unselected OAuth2 callback advertised")
		}
	}
	request := httptest.NewRequest(http.MethodGet, "https://login.example/sso/oauth2/callback", nil)
	request.RequestURI = request.URL.RequestURI()
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || response.Header().Get("Set-Cookie") != "" {
		t.Fatal("unselected OAuth2 callback exposed", response.Code)
	}
	for name, config := range map[string]StoreConfiguration{
		"HTTP without native":   {HTTPEnterpriseOAuth2: &HTTPEnterpriseOAuth2Configuration{}},
		"native without owners": {EnterpriseOAuth2: &EnterpriseOAuth2Configuration{}},
	} {
		t.Run(name, func(t *testing.T) {
			state := &storeState{}
			if err := state.composeFeatureStores(config, ReferenceDependencies{}); err == nil || state.features != nil {
				t.Fatal("OAuth2 selection silently dropped without required owners")
			}
		})
	}
}
