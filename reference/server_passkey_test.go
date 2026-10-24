package reference

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPasskeyHTTPIsAbsentUntilSelected(t *testing.T) {
	c, d, f := serverFixture(t)
	s, err := NewServer(c, d, f)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range s.OpenAPI().Operations() {
		if strings.HasPrefix(operation.Record.OperationID, "identity.passkey.") {
			t.Fatal("default exposed passkey metadata")
		}
	}
	r := httptest.NewRequest(http.MethodPost, "https://login.example/v1/passkey/register-options", strings.NewReader("{}"))
	r.RequestURI = "/v1/passkey/register-options"
	r.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("default exposed a passkey route", w.Code)
	}
	if out, err := composePasskeyHTTP(StoreConfiguration{}, nil, nil, nil, nil, nil, nil, nil, nil); err != nil || out != nil {
		t.Fatal("unselected transport acquired dependencies")
	}
	for _, config := range []HTTPPasskeyConfiguration{{}, {Registration: true}, {Signin: true}, {Inventory: true}, {Discoverable: true}, {Update: true}, {SessionUpdate: true}, {Update: true, SessionUpdate: true}, {Delete: true}, {SessionDeletion: true}, {Delete: true, SessionDeletion: true}} {
		if out, err := composePasskeyHTTP(StoreConfiguration{HTTPPasskey: &config}, nil, nil, nil, nil, nil, nil, nil, nil); err == nil || out != nil {
			t.Fatal("missing native authority exposed transport")
		}
	}
}

func TestPasskeyHTTPGuardRetainsGraphLifetime(t *testing.T) {
	_, _, f := serverFixture(t)
	called := false
	h := &passkeyLifetimeHandler{state: f.state, next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if f.state.active == 0 {
			t.Error("request escaped graph lifetime")
		}
		w.WriteHeader(http.StatusNoContent)
	})}
	r := httptest.NewRequest(http.MethodGet, "https://login.example/v1/passkey/list", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if called || w.Code != http.StatusServiceUnavailable {
		t.Fatal("uninitialized graph exposed transport")
	}
	f.state.features.ready = true
	f.state.features.timeout = time.Second
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !called || w.Code != http.StatusNoContent || f.state.active != 0 {
		t.Fatal("graph request did not drain")
	}
	f.state.closed = true
	called = false
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if called || w.Code != http.StatusServiceUnavailable || w.Header().Get("Set-Cookie") != "" || w.Body.String() != "{\"error\":\"unavailable\"}\n" {
		t.Fatal("retained handler bypassed closure")
	}
}

func TestPasskeyHTTPConfigurationDoesNotExportCallbacks(t *testing.T) {
	c := HTTPPasskeyConfiguration{Registration: true, InventoryRateNamespace: "private-deployment"}
	if _, err := json.Marshal(c); err == nil {
		t.Fatal("configuration serialized")
	}
	if _, err := c.MarshalText(); err == nil {
		t.Fatal("configuration serialized to text")
	}
	if fmt.Sprintf("%#v", c) != "reference.HTTPPasskeyConfiguration(redacted)" {
		t.Fatal("configuration disclosed")
	}
}
