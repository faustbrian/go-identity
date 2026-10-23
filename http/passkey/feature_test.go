package passkeyhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
	"github.com/faustbrian/go-rate-limit/v2/memory"
)

func TestFeatureSelectsActualPairsAndMatchesDenialWire(t *testing.T) {
	c, owner, flow, device := signinFixture(t)
	c.Discoverable = true
	feature, err := NewFeature(FeatureConfig{Signin: &c})
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	h, document, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: c.Network, HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}}, ops, nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(document.JSON(), &doc) != nil || len(doc.Paths) != 2 || doc.Paths["/v1/passkey/signin-options"] == nil || doc.Paths["/v1/passkey/signin-verify"] == nil || owner.options != 0 || owner.sources != 0 {
		t.Fatal("feature exposed unselected metadata or performed IO")
	}
	parsed, err := openapi.ParseJSON(t.Context(), bytes.NewReader(document.JSON()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"signin-options", "signin-verify"} {
		body := `{"mode":"identified","flowID":"AAAAAAAAAAAAAAAAAAAAAQ","identifier":"person@example.invalid"}`
		if operation == "signin-verify" {
			body = `{"mode":"identified","flowID":"AAAAAAAAAAAAAAAAAAAAAQ","identifier":"person@example.invalid","commandID":"AAAAAAAAAAAAAAAAAAAAAg","ceremonyID":"AAAAAAAAAAAAAAAAAAAAAw","response":{"id":"synthetic-assertion"}}`
		}
		r := signinRequest(operation, body, flow, device)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("selected route bypassed native denial", operation, w.Code)
		}
		node := parsed.Raw()
		for _, key := range []string{"paths", r.URL.Path, "post", "responses", strconv.Itoa(w.Code), "content", "application/json", "schema"} {
			var ok bool
			node, ok = node.Lookup(key)
			if !ok {
				t.Fatal("actual denial has no concrete schema", key)
			}
		}
		instance, err := parse.JSON(t.Context(), bytes.NewReader(w.Body.Bytes()), parse.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		report, err := validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
		if err != nil || !report.Valid() {
			t.Fatal("actual denial rejected by selected wire", err)
		}
		bad, _ := parse.JSON(t.Context(), strings.NewReader(`{"error":"denied","credential":"unowned"}`), parse.DefaultLimits())
		report, err = validate.SchemaInstance(t.Context(), parsed, node, bad, validate.InstanceOptions{})
		if err != nil || report.Valid() {
			t.Fatal("wire admits secret/domain payload")
		}
	}
	if owner.options != 1 || owner.sources != 1 || owner.completions != 0 {
		t.Fatal("feature bypassed original native phases")
	}
	off, offDoc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	off.ServeHTTP(w, signinRequest("signin-options", `{}`, flow, device))
	if w.Code != http.StatusNotFound || strings.Contains(string(offDoc.JSON()), "passkey") || owner.options != 1 {
		t.Fatal("disabled feature retained route or metadata")
	}
	if _, err := NewFeature(FeatureConfig{}); err == nil {
		t.Fatal("empty feature accepted")
	}
}

func TestFeatureRunsSelectedRegistrationAndInventoryOwners(t *testing.T) {
	c, owner, _, cookie, device, csrf := registrationFixture(t)
	store, err := memory.New(memory.Options{MaxKeys: 512, Shards: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	rate, err := identityhttp.NewSafeRateLimiter(identityhttp.SafeRateConfig{Shared: &parserRates{store}, Namespace: "passkey-feature-list", Now: c.Now, Degraded: func(context.Context, identityhttp.SafeRateEvent) error { return nil }, MaximumDuration: time.Second, EmergencyMaximumKeys: 64})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rate.Close() })
	inventory := &deniedInventory{}
	list := InventoryConfig{Network: c.Network, Sessions: c.Sessions, Service: inventory, Rate: rate, SessionCookie: c.SessionCookie, PolicyRevision: c.PolicyRevision, Now: c.Now, MaximumDuration: c.MaximumDuration}
	signin, _, _, _ := signinFixture(t)
	f, err := NewFeature(FeatureConfig{Registration: &c, Signin: &signin, Inventory: &list})
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(doc.JSON(), &document) != nil || len(document.Paths) != 5 {
		t.Fatal("wrong complete finite selection")
	}
	for _, operation := range []string{"register-options", "register-verify", "list"} {
		body := `{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ"}`
		if operation == "register-verify" {
			owner.proof.Action = "identity.passkey.register-verify"
			owner.proof.Proof.ID = "AAAAAAAAAAAAAAAAAAAABA"
			body = `{"proofID":"AAAAAAAAAAAAAAAAAAAABA","commandID":"AAAAAAAAAAAAAAAAAAAAAg","ceremonyID":"AAAAAAAAAAAAAAAAAAAAAw","response":{"id":"synthetic-attestation"}}`
		}
		r := registrationRequest(operation, body, cookie, device, csrf)
		if operation == "list" {
			r = signinRequest("list", "", cookie, nil)
			r.Method, r.Body = http.MethodGet, http.NoBody
			r.Header.Del("Content-Type")
			r.Header.Del("Origin")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 || len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" {
			t.Fatal("feature bypassed original owner", operation, w.Code)
		}
	}
	if owner.options != 1 || owner.sources != 1 || owner.completions != 0 || inventory.calls != 1 {
		t.Fatal("selected handlers did not retain native custody")
	}
}
