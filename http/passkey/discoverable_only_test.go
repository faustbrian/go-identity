package passkeyhttp

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	email "github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

func TestSigninDiscoverableOnlyNeedsNoEmailParserAndRejectsIdentified(t *testing.T) {
	c, owner, flow, device := signinFixture(t)
	c.Discoverable, c.DiscoverableOnly = true, true
	c.Address = email.AddressParser{}
	h, err := NewSigninOptionsHandler(c)
	if err != nil {
		t.Fatal("discoverable-only signin requires an unused email parser", err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signinRequest("signin-options", `{"mode":"identified","flowID":"AAAAAAAAAAAAAAAAAAAAAQ","identifier":"person@example.invalid"}`, flow, device))
	if w.Code != 400 || owner.options != 0 {
		t.Fatal("unselected identified mode reached the native owner", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, signinRequest("signin-options", `{"mode":"discoverable","flowID":"AAAAAAAAAAAAAAAAAAAAAQ"}`, flow, device))
	if w.Code != 403 || owner.options != 1 {
		t.Fatal("selected discovery failed to reach native authority", w.Code)
	}
	c.Discoverable = false
	if _, err := NewSigninOptionsHandler(c); err == nil {
		t.Fatal("discovery-only selection implicitly enabled discovery")
	}
	c.Discoverable, c.DiscoverableOnly = true, false
	if _, err := NewSigninOptionsHandler(c); err == nil {
		t.Fatal("combined selection omitted its required identified parser")
	}
}

func TestDiscoverableOnlyWireRejectsUnselectedIdentifiedRequests(t *testing.T) {
	c, _, _, _ := signinFixture(t)
	c.Discoverable, c.DiscoverableOnly = true, true
	c.Address = email.AddressParser{}
	feature, err := NewFeature(FeatureConfig{Signin: &c})
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	_, document, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: c.Network, HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Passkey-only", Version: "1"}}, ops, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := openapi.ParseJSON(t.Context(), bytes.NewReader(document.JSON()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"signin-options", "signin-verify"} {
		node := parsed.Raw()
		for _, part := range []string{"paths", "/v1/passkey/" + name, "post", "requestBody", "content", "application/json", "schema"} {
			var ok bool
			node, ok = node.Lookup(part)
			if !ok {
				t.Fatal("missing selected request schema", part)
			}
		}
		body := map[string]any{"mode": "discoverable", "flowID": "AAAAAAAAAAAAAAAAAAAAAQ"}
		if name == "signin-verify" {
			body["commandID"], body["ceremonyID"] = "AAAAAAAAAAAAAAAAAAAAAg", "AAAAAAAAAAAAAAAAAAAAAw"
			body["response"] = map[string]any{"id": "AQ", "rawId": "AQ", "type": "public-key", "response": map[string]any{"clientDataJSON": "AQ", "authenticatorData": "AQ", "signature": "AQ", "userHandle": "AQ"}}
		}
		for _, mode := range []string{"discoverable", "identified", "discoverable-with-identifier"} {
			body["mode"] = "discoverable"
			delete(body, "identifier")
			if mode != "discoverable" {
				body["identifier"] = "person@example.invalid"
				if mode == "identified" {
					body["mode"] = mode
				}
			}
			wire, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			instance, err := parse.JSON(t.Context(), strings.NewReader(string(wire)), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			report, err := validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionRequest})
			if err != nil || report.Valid() != (mode == "discoverable") {
				t.Fatal("selected wire admits an unselected mode or rejects discovery", name, mode, err)
			}
		}
	}
}
