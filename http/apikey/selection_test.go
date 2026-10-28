package apikeyhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestSelectedRoutesAndDocumentAgreeWithoutImplicitManagement(t *testing.T) {
	f := newFixture(t)
	f.config.Rotate, f.config.Revoke = false, false
	f.config.Rotator, f.config.Revoker = nil, nil
	feature, err := NewFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: f.config.Network, HandlerTimeout: 3 * time.Second, Document: identityhttp.DocumentConfig{Title: "API keys", Version: "1"}}, ops, nil)
	if err != nil {
		t.Fatal("actual wire/router construction rejected", err)
	}
	var document struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(doc.JSON(), &document) != nil || len(document.Paths) != 1 || document.Paths["/v1/apikey/create"] == nil {
		t.Fatal("selected document disagrees with exact routes")
	}
	for _, action := range []string{"rotate", "delete", "recover"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, f.request(action, `{"keyID":"key-a","expectedVersion":1}`))
		if w.Code != 404 || f.sessions.calls != 0 || f.rate.calls != 0 || f.native.calls != 0 {
			t.Fatal("disabled route reached a selected owner", action, w.Code)
		}
	}
	if _, err := NewFeature(FeatureConfig{Config: f.config.Config}); err == nil {
		t.Fatal("empty selection inferred a feature")
	}
	if f.sessions.calls != 0 || f.rate.calls != 0 || f.native.calls != 0 {
		t.Fatal("construction performed owner IO")
	}
}

func TestClosedMutationFieldsRejectCaseAliases(t *testing.T) {
	for _, body := range []string{`{"KeyID":"key-a","expectedVersion":1}`, `{"keyID":"key-a","ExpectedVersion":1}`} {
		f := newFixture(t)
		w := httptest.NewRecorder()
		fixtureHandler(t, f).ServeHTTP(w, f.request("rotate", body))
		if w.Code != 400 || f.sessions.calls != 0 || f.native.calls != 0 {
			t.Fatal("noncanonical wire field reached authority", w.Code)
		}
	}
}

func TestMiddlewareCannotAttachCredentialHeaders(t *testing.T) {
	f := newFixture(t)
	feature, err := NewFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	headers := []string{"Set-Cookie", "Authorization", "Proxy-Authorization", "X-CSRF-Token", "X-MFA-Token", "Location"}
	m := identityhttp.MiddlewareDescriptor{Owner: "identity/apikey", Middleware: identityhttp.Middleware{Name: "host-response", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, name := range headers {
				w.Header().Set(name, "synthetic-forbidden-value")
			}
			next.ServeHTTP(w, r)
		})
	}}}
	h, _, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: f.config.Network, HandlerTimeout: 3 * time.Second, Document: identityhttp.DocumentConfig{Title: "API keys", Version: "1"}}, ops, []identityhttp.MiddlewareDescriptor{m})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, f.request("rotate", `{"keyID":"key-a","expectedVersion":1}`))
	if w.Code != 403 || f.native.calls != 1 {
		t.Fatal("credential-guard journey did not reach native denial", w.Code)
	}
	for _, name := range headers {
		if w.Header().Get(name) != "" {
			t.Fatal("middleware attached a forbidden credential header", name)
		}
	}
}
