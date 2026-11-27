package oauthhttp_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	oauthhttp "github.com/faustbrian/go-identity/http/oauth"
	"github.com/faustbrian/go-identity/session"
)

func TestOneTapRedirectCallbackFeatureDocumentsSelectedFormAndCookieAuthority(t *testing.T) {
	c, _, _, _, _ := oneTapRedirectCallbackFixture(t)
	feature, err := oauthhttp.NewOneTapRedirectCallbackFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	operations := feature.Operations()
	if len(operations) != 1 || operations[0].Record.OperationID != "identity.oauth.onetap-callback" || operations[0].Route.Method != http.MethodPost || operations[0].Route.Path != "/v1/oauth/onetap-callback" || operations[0].Record.HandlerOwner != "identity/oauth/onetap" {
		t.Fatal("redirect feature changed the canonical callback selection")
	}
	policy := operations[0].Record.CSRFOrigin
	if policy.Mode != identityhttp.CSRFBoundOrigin || policy.RefererFallback != identityhttp.RefererFallbackDeny {
		t.Fatal("redirect callback did not select original-bound origin authority")
	}
	_, document, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Redirect callback", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Paths map[string]map[string]struct {
			OperationID string                `json:"operationId"`
			Parameters  []json.RawMessage     `json:"parameters"`
			Security    []map[string][]string `json:"security"`
			RequestBody struct {
				Required bool `json:"required"`
				Content  map[string]struct {
					Schema struct {
						Required             []string              `json:"required"`
						AdditionalProperties struct{ Type string } `json:"additionalProperties"`
						MaxProperties        uint32                `json:"maxProperties"`
						Properties           map[string]struct {
							MinLength int  `json:"minLength"`
							MaxLength int  `json:"maxLength"`
							WriteOnly bool `json:"writeOnly"`
						} `json:"properties"`
					} `json:"schema"`
				} `json:"content"`
			} `json:"requestBody"`
			Responses map[string]struct {
				Description string                     `json:"description"`
				Headers     map[string]json.RawMessage `json:"headers"`
			} `json:"responses"`
		} `json:"paths"`
		Components struct {
			SecuritySchemes map[string]struct{ Type, In, Name string } `json:"securitySchemes"`
		} `json:"components"`
	}
	if err := json.Unmarshal(document.JSON(), &wire); err != nil {
		t.Fatal(err)
	}
	op := wire.Paths["/v1/oauth/onetap-callback"]["post"]
	if len(wire.Paths) != 1 || len(wire.Paths["/v1/oauth/onetap-callback"]) != 1 || op.OperationID != "identity.oauth.onetap-callback" || len(op.Parameters) != 0 {
		t.Fatal("document added sibling routes or sender-header authority")
	}
	form, ok := op.RequestBody.Content["application/x-www-form-urlencoded"]
	if !ok || len(op.RequestBody.Content) != 1 || !op.RequestBody.Required || !slices.Equal(form.Schema.Required, []string{"state", "credential", "g_csrf_token"}) || form.Schema.AdditionalProperties.Type != "string" || form.Schema.MaxProperties != c.Network.Limits.MaximumFields {
		t.Fatal("document does not describe the bounded extensible form parser")
	}
	if len(form.Schema.Properties) != 3 || form.Schema.Properties["state"].MinLength != 22 || form.Schema.Properties["state"].MaxLength != 22 || form.Schema.Properties["credential"].MaxLength != c.Provider.MaxTokenBytes || !form.Schema.Properties["credential"].WriteOnly || form.Schema.Properties["g_csrf_token"].MaxLength != 1024 || !form.Schema.Properties["g_csrf_token"].WriteOnly {
		t.Fatal("document changed state, credential or Google CSRF bounds")
	}
	if len(op.Security) != 1 || len(op.Security[0]) != 2 || len(wire.Components.SecuritySchemes) != 2 {
		t.Fatal("original frontchannel and Google cookies must be required together")
	}
	for component, name := range map[string]string{"OneTapRedirectCallbackFrontchannel": "__Secure-identity_frontchannel", "OneTapRedirectCallbackGoogleCSRF": "g_csrf_token"} {
		scheme, exists := wire.Components.SecuritySchemes[component]
		_, required := op.Security[0][component]
		if !exists || !required || scheme.Type != "apiKey" || scheme.In != "cookie" || scheme.Name != name {
			t.Fatal("document changed original callback cookie authority", component)
		}
	}
	if op.Responses["200"].Headers["Set-Cookie"] == nil || op.Responses["503"].Headers["Set-Cookie"] != nil || !strings.Contains(op.Responses["503"].Description, "No cookies") {
		t.Fatal("document changed fresh delivery versus replay cookie custody")
	}
}

func TestOneTapRedirectCallbackFeatureExecutesOriginalProofAndCommitOnlyDelivery(t *testing.T) {
	for _, mode := range []string{"google mismatch", "native denied", "replay", "fresh"} {
		t.Run(mode, func(t *testing.T) {
			c, p, _, r, popup := oneTapRedirectCallbackFixture(t)
			p.result, p.err = oneTapCallbackHTTPResult(t, popup, session.BrowserSession), nil
			r.Header.Set("Origin", "null")
			r.Header.Set("Referer", "https://untrusted.example/")
			wantStatus, wantCalls := http.StatusOK, 1
			switch mode {
			case "google mismatch":
				r.Header.Set("Cookie", "__Secure-identity_frontchannel="+strings.Repeat("A", 43)+"; g_csrf_token=other")
				wantStatus, wantCalls = http.StatusForbidden, 0
			case "native denied":
				p.err = identity.ForbiddenError{}
				wantStatus = http.StatusForbidden
			case "replay":
				p.result.Session.Replayed = true
				wantStatus = http.StatusServiceUnavailable
			}
			feature, err := oauthhttp.NewOneTapRedirectCallbackFeature(c)
			if err != nil {
				t.Fatal(err)
			}
			h, _, err := identityhttp.NewRouter(identityhttp.TransportPolicy{
				Network: c.Network, HandlerTimeout: c.MaximumDuration,
				Document: identityhttp.DocumentConfig{Title: "Redirect callback", Version: "1"},
				CORS:     []identityhttp.CORSRoutePolicy{{Method: http.MethodPost, Path: "/v1/oauth/onetap-callback", Credentials: identityhttp.CORSOneTapRedirectNavigation, Origins: []identityhttp.Origin{c.Origin}}},
			}, feature.Operations(), nil)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != wantStatus || p.calls != wantCalls || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Location") != "" || w.Header().Get("Access-Control-Allow-Origin") != "" || w.Header().Get("Access-Control-Allow-Credentials") != "" {
				t.Fatal("selected redirect feature changed proof, delivery or navigation custody", w.Code, p.calls)
			}
			if mode == "fresh" {
				cookies := w.Result().Cookies()
				if w.Body.String() != "{\"status\":\"signed_in\"}\n" || len(cookies) != 2 || cookies[0].Name != "__Host-identity_session" || cookies[1].Name != "__Host-identity_csrf" {
					t.Fatal("fresh commit did not issue exactly the native session and CSRF cookies")
				}
			} else {
				requireNoSigninCredentials(t, w)
				wantBody := "{\"error\":\"denied\"}\n"
				if mode == "replay" {
					wantBody = "{\"error\":\"unavailable\"}\n"
				}
				if w.Body.String() != wantBody {
					t.Fatal("denial or replay did not retain its stable redacted result")
				}
			}
		})
	}
}
