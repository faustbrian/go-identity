package passkeyhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
	passkey "github.com/faustbrian/go-passkey"
)

// Only the declared native workflow port is doubled; transport and rates are
// real. The genuine PostgreSQL Reference journey separately proves issuance.
type conditionalDenial struct {
	*deniedSignin
	conditional   int
	lastDiscovery passkey.KeyedDiscoverableOptionsRequest
}

func (o *conditionalDenial) KeyedConditionalAuthenticationOptions(_ context.Context, r passkey.KeyedDiscoverableOptionsRequest) (passkey.KeyedConditionalOptionsResult, error) {
	o.conditional++
	o.lastDiscovery = r
	if o.err != nil {
		return passkey.KeyedConditionalOptionsResult{CommandID: o.commandID}, o.err
	}
	return passkey.KeyedConditionalOptionsResult{}, identity.ForbiddenError{}
}

func TestConditionalSigninUsesNativeProjectionWithoutFallbackOrNewMode(t *testing.T) {
	for _, mode := range []string{"discoverable", "identified", "conditional"} {
		t.Run(mode, func(t *testing.T) {
			c, ordinary, flow, device := signinFixture(t)
			owner := &conditionalDenial{deniedSignin: ordinary}
			c.Discoverable, c.Conditional, c.Service = true, true, owner
			h, err := NewSigninOptionsHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			body := `{"mode":"` + mode + `","flowID":"AAAAAAAAAAAAAAAAAAAAAQ"}`
			if mode == "identified" {
				body = `{"mode":"identified","flowID":"AAAAAAAAAAAAAAAAAAAAAQ","identifier":"person@example.invalid"}`
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, signinRequest("signin-options", body, flow, device))
			if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("options denial issued authentication")
			}
			switch mode {
			case "discoverable":
				if w.Code != 403 || owner.conditional != 1 || ordinary.options != 0 || owner.lastDiscovery.FlowID != "AAAAAAAAAAAAAAAAAAAAAQ" || owner.lastDiscovery.IdempotencyKey == (identity.IdempotencyKey{}) {
					t.Fatal("conditional projection fell back or lost original keyed flow", w.Code)
				}
			case "identified":
				if w.Code != 403 || owner.conditional != 0 || ordinary.options != 1 {
					t.Fatal("conditional selection changed identified options", w.Code)
				}
			case "conditional":
				if w.Code != 400 || owner.conditional != 0 || ordinary.options != 0 {
					t.Fatal("presentation became another durable mode", w.Code)
				}
			}
		})
	}
}

func TestConditionalUnknownOptionsRetainOriginalCommandWithoutSecrets(t *testing.T) {
	c, ordinary, flow, device := signinFixture(t)
	ordinary.commandID = "AAAAAAAAAAAAAAAAAAAAAg"
	ordinary.err = identity.UnknownCommitError{CommandID: ordinary.commandID}
	owner := &conditionalDenial{deniedSignin: ordinary}
	c.Discoverable, c.Conditional, c.Service = true, true, owner
	h, err := NewSigninOptionsHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signinRequest("signin-options", `{"mode":"discoverable","flowID":"AAAAAAAAAAAAAAAAAAAAAQ"}`, flow, device))
	var out struct {
		CommandID     identity.CommandID `json:"commandID"`
		CommitOutcome string             `json:"commitOutcome"`
		Options       json.RawMessage    `json:"options"`
	}
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || w.Code != 503 || out.CommandID != ordinary.commandID || out.CommitOutcome != "unknown" || len(out.Options) != 0 || owner.conditional != 1 || ordinary.options != 0 || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("unknown conditional options lost original recovery or disclosed challenge", w.Code)
	}
}

func TestConditionalVerificationRetainsDiscoverableSourceAndCompletion(t *testing.T) {
	c, ordinary, flow, device := signinFixture(t)
	owner := &conditionalDenial{deniedSignin: ordinary}
	c.Discoverable, c.Conditional, c.Service = true, true, owner
	h, err := NewSigninVerifyHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signinRequest("signin-verify", `{"mode":"discoverable","flowID":"AAAAAAAAAAAAAAAAAAAAAQ","commandID":"AAAAAAAAAAAAAAAAAAAAAg","ceremonyID":"AAAAAAAAAAAAAAAAAAAAAw","response":{"id":"synthetic-assertion"}}`, flow, device))
	if w.Code != 403 || ordinary.sources != 1 || ordinary.completions != 0 || owner.conditional != 0 || ordinary.options != 0 || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("conditional presentation bypassed native original discoverable source", w.Code)
	}
}

func TestConditionalOptionsWireMatchesExplicitSelection(t *testing.T) {
	for _, selected := range []struct{ conditional, only bool }{{false, false}, {true, false}, {true, true}} {
		c, ordinary, _, _ := signinFixture(t)
		c.Discoverable, c.DiscoverableOnly, c.Conditional = true, selected.only, selected.conditional
		c.Service = &conditionalDenial{deniedSignin: ordinary}
		feature, err := NewFeature(FeatureConfig{Signin: &c})
		if err != nil {
			t.Fatal(err)
		}
		_, document, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Conditional", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := openapi.ParseJSON(t.Context(), bytes.NewReader(document.JSON()), parse.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		node := parsed.Raw()
		for _, part := range []string{"paths", "/v1/passkey/signin-options", "post", "responses", "200", "content", "application/json", "schema"} {
			var ok bool
			node, ok = node.Lookup(part)
			if !ok {
				t.Fatal("missing selected options schema", part)
			}
		}
		for _, mediation := range []string{"", "conditional", "required"} {
			options := map[string]any{"publicKey": map[string]any{"challenge": strings.Repeat("A", 43), "timeout": 300000, "userVerification": "required", "rpId": "tenant.example"}}
			if mediation != "" {
				options["mediation"] = mediation
			}
			wire, err := json.Marshal(map[string]any{"commandID": "AAAAAAAAAAAAAAAAAAAAAQ", "commitOutcome": "committed", "replayed": false, "options": options})
			if err != nil {
				t.Fatal(err)
			}
			instance, err := parse.JSON(t.Context(), bytes.NewReader(wire), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			report, err := validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
			want := mediation == "" && !(selected.conditional && selected.only) || mediation == "conditional" && selected.conditional
			if err != nil || report.Valid() != want {
				t.Fatal("conditional wire disagrees with selected presentation", selected, mediation, err)
			}
		}
	}
}
