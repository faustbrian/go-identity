package oauthhttp_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
	oauthhttp "github.com/faustbrian/go-identity/http/oauth"
)

func TestProxyForwardFeatureSelectsTheProviderQueryContract(t *testing.T) {
	c, probe, _, incoming := proxyForwardFixture(t)
	feature, err := oauthhttp.NewProxyForwardFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	services := identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}}
	handler, document, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Preview", Version: "1"}, services)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
			RequestBody json.RawMessage
			Parameters  []struct {
				Name, In string
				Required bool
			}
			Responses map[string]struct {
				Headers map[string]json.RawMessage
				Content json.RawMessage
			}
		}
	}
	if err := json.Unmarshal(document.JSON(), &wire); err != nil {
		t.Fatal(err)
	}
	path := wire.Paths[oauthhttp.ProxyForwardPath]
	op := path["get"]
	if len(wire.Paths) != 1 || len(path) != 1 || op.OperationID != "identity.oauth.proxy-forward" || op.RequestBody != nil {
		t.Fatal("selected query callback advertised an alias or request body")
	}
	required := map[string]bool{}
	for _, parameter := range op.Parameters {
		if _, duplicate := required[parameter.Name]; parameter.In != "query" || duplicate {
			t.Fatal("unexpected parameter contract")
		}
		required[parameter.Name] = parameter.Required
	}
	if len(required) != 6 || !required["iss"] || !required["state"] || required["code"] || required["error"] {
		t.Fatal("query contract lost exact binding fields or denial variant")
	}
	if success := op.Responses["303"]; success.Headers["Location"] == nil || success.Headers["Set-Cookie"] != nil || success.Content != nil {
		t.Fatal("success advertised credential, body or missing fragment redirect")
	}
	post := httptest.NewRequest(http.MethodPost, incoming.URL.String(), nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, post)
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET" || probe.handleCalls != 0 {
		t.Fatal("provider POST alias reached native completion")
	}
}
