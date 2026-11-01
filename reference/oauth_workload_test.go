package reference

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	oauth "github.com/faustbrian/go-oauth-server"
)

func TestReferenceOAuthUnselectedDoesNotAdvertiseOrExposeRoutes(t *testing.T) {
	c, d, f := serverFixture(t)
	s, err := NewServer(c, d, f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.OAuthWorkloads(); err == nil {
		t.Fatal("unselected native OAuth handle exposed")
	}
	for _, op := range s.OpenAPI().Operations() {
		if strings.HasPrefix(op.Record.OperationID, "identity.oauth-server.") {
			t.Fatal("nil selection advertised OAuth")
		}
	}
	for _, action := range []string{"token", "introspect", "revoke"} {
		r := httptest.NewRequest(http.MethodPost, "https://login.example/oauth2/"+action, nil)
		r.RequestURI = r.URL.RequestURI()
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusNotFound || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("nil selection exposed OAuth route", action, w.Code)
		}
	}
	state := &storeState{}
	if err := state.composeFeatureStores(StoreConfiguration{HTTPOAuthWorkload: &HTTPOAuthWorkloadConfiguration{Token: true}}, ReferenceDependencies{}); err == nil || state.features != nil {
		t.Fatal("transport selection created missing native authority")
	}
}

func TestReferenceOAuthZeroHandlesDenyAndRuntimeExportsStayOpaque(t *testing.T) {
	if _, err := (FeatureSet{}).OAuthWorkloads(); err == nil {
		t.Fatal("zero feature set exposed native OAuth")
	}
	var handle OAuthWorkloadService
	if _, err := handle.Token(t.Context(), oauth.TokenRequest{}); err == nil {
		t.Fatal("zero token handle admitted work")
	}
	if _, err := handle.Introspect(t.Context(), oauth.IntrospectRequest{}); err == nil {
		t.Fatal("zero introspection handle admitted work")
	}
	if _, err := handle.Revoke(t.Context(), oauth.RevokeRequest{}); err == nil {
		t.Fatal("zero revocation handle admitted work")
	}
	for _, v := range []any{handle, OAuthWorkloadConfiguration{GlobalAuthorityID: "private-deployment-scope"}, HTTPOAuthWorkloadConfiguration{Namespace: "private-deployment-scope"}} {
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("implicit OAuth custody export accepted")
		}
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			if value := fmt.Sprintf(verb, v); strings.Contains(value, "private-deployment-scope") || !strings.Contains(value, "redacted") {
				t.Fatal("runtime export lost opaque formatting")
			}
		}
	}
}
