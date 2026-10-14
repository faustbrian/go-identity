package otphttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	otphttp "github.com/faustbrian/go-identity/http/otp"
	"github.com/faustbrian/go-identity/otp"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

func TestSigninFeatureSelectsOnlyRealOriginalFlow(t *testing.T) {
	c, owner, body := fixture(t)
	owner.result = func(_ context.Context, r otp.SigninRequest) (otp.SigninResult, error) { return issuance(t, c, r), nil }
	feature, err := otphttp.NewSigninFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	selected := identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}}
	h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, selected)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if json.Unmarshal(doc.JSON(), &document) != nil {
		t.Fatal("invalid document")
	}
	paths := document["paths"].(map[string]any)
	if len(paths) != 1 || paths["/v1/otp/signin"] == nil || owner.sources != 0 || owner.attempts != 0 {
		t.Fatal("feature advertised unrelated operations or invoked native owners")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(body))
	if w.Code != 200 || owner.sources != 1 || owner.attempts != 1 || len(w.Result().Cookies()) != 1 || w.Header().Get("X-CSRF-Token") == "" {
		t.Fatal("selected feature did not execute native signin")
	}
	for _, forbidden := range []string{"identifier", "remember", "destination"} {
		definition := paths["/v1/otp/signin"].(map[string]any)["post"].(map[string]any)
		wire := definition["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
		if wire["properties"].(map[string]any)[forbidden] != nil {
			t.Fatal("wire accepts replacement original-flow input")
		}
	}
	off, offDoc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	off.ServeHTTP(w, request(body))
	if w.Code != 404 || strings.Contains(string(offDoc.JSON()), "otp.signin") || owner.attempts != 1 {
		t.Fatal("disabled feature retained route or metadata")
	}
}

func TestSigninFeatureActualResponsesMatchConcreteWire(t *testing.T) {
	for _, mode := range []string{"success", "unknown", "invalid", "origin", "host", "method", "plaintext", "router-origin"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, body := fixture(t)
			owner.result = func(_ context.Context, r otp.SigninRequest) (otp.SigninResult, error) {
				out := issuance(t, c, r)
				if mode == "unknown" {
					out.Issuance.CommitOutcome = identity.CommitOutcomeUnknown
				}
				return out, nil
			}
			feature, err := otphttp.NewSigninFeature(c)
			if err != nil {
				t.Fatal(err)
			}
			ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
			if err != nil {
				t.Fatal(err)
			}
			h, doc, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: c.Network, HandlerTimeout: c.MaximumDuration, Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}}, ops, nil)
			if err != nil {
				t.Fatal(err)
			}
			r := request(body)
			want := 200
			media := "application/json"
			switch mode {
			case "unknown":
				want = 503
			case "invalid":
				r = request(`{"identifier":"replacement","code":"123456"}`)
				want = 400
			case "origin", "router-origin":
				r.Header.Set("Origin", "https://foreign.example")
				want = 403
				media = "text/plain"
			case "host":
				r.Host = "unknown.example"
				want = 421
			case "method":
				r.Method = http.MethodGet
				want = 405
			case "plaintext":
				r.TLS = nil
				r.URL.Scheme = "http"
				want = 403
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want || !strings.HasPrefix(w.Header().Get("Content-Type"), media) {
				t.Fatalf("wrong status/media: %d", w.Code)
			}
			if want != 200 && (len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "") {
				t.Fatal("failure delivered credentials")
			}
			parsed, err := openapi.ParseJSON(context.Background(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			node := parsed.Raw()
			for _, key := range []string{"paths", "/v1/otp/signin", "post", "responses", strconv.Itoa(w.Code), "content", media, "schema"} {
				var ok bool
				node, ok = node.Lookup(key)
				if !ok {
					t.Fatal("actual response missing from wire document")
				}
			}
			response := w.Body.Bytes()
			if media == "text/plain" {
				response, _ = json.Marshal(string(response))
			}
			instance, err := parse.JSON(context.Background(), bytes.NewReader(response), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			report, err := validate.SchemaInstance(context.Background(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
			if err != nil || !report.Valid() {
				t.Fatalf("real response violates concrete wire: %v %+v", err, report.Diagnostics())
			}
			if media == "application/json" {
				var bad map[string]any
				if json.Unmarshal(response, &bad) != nil {
					t.Fatal("invalid response")
				}
				bad["credential"] = "forbidden"
				encoded, _ := json.Marshal(bad)
				instance, _ = parse.JSON(context.Background(), bytes.NewReader(encoded), parse.DefaultLimits())
				report, err = validate.SchemaInstance(context.Background(), parsed, node, instance, validate.InstanceOptions{})
				if err != nil || report.Valid() {
					t.Fatal("wire permits credential-bearing JSON")
				}
			}
		})
	}
}

func TestSigninFeatureWireRejectsControlBearingOriginalInput(t *testing.T) {
	c, _, body := fixture(t)
	feature, err := otphttp.NewSigninFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	_, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := openapi.ParseJSON(context.Background(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	node := parsed.Raw()
	for _, key := range []string{"paths", "/v1/otp/signin", "post", "requestBody", "content", "application/json", "schema"} {
		var ok bool
		node, ok = node.Lookup(key)
		if !ok {
			t.Fatal("missing request schema")
		}
	}
	for _, field := range []string{"", "code", "flowID", "sendCommandID", "remember"} {
		var input map[string]any
		if json.Unmarshal([]byte(body), &input) != nil {
			t.Fatal("invalid fixture")
		}
		if field == "remember" {
			input[field] = true
		} else if field != "" {
			input[field] = input[field].(string) + "\n"
		}
		encoded, _ := json.Marshal(input)
		instance, err := parse.JSON(context.Background(), bytes.NewReader(encoded), parse.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		report, err := validate.SchemaInstance(context.Background(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionRequest})
		if err != nil || report.Valid() != (field == "") {
			t.Fatalf("wire accepted invalid original input field=%q err=%v", field, err)
		}
	}
}

func TestSigninFeatureRouterBindsRealTypedPhases(t *testing.T) {
	c, owner, body := fixture(t)
	owner.result = func(_ context.Context, r otp.SigninRequest) (otp.SigninResult, error) { return issuance(t, c, r), nil }
	feature, err := otphttp.NewSigninFeatureWithMiddleware(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	observed := false
	h, _, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: c.Network, HandlerTimeout: c.MaximumDuration, Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}}, ops, []identityhttp.MiddlewareDescriptor{hook(identityhttp.MiddlewareAfterHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		state, ok := identityhttp.PipelineValue[otphttp.SigninState](r)
		out, attempted := state.Attempt()
		observed = ok && attempted && out.SignedIn && out.CommitOutcome == "committed"
		next.ServeHTTP(w, r)
	})})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(body))
	if w.Code != 200 || !observed || owner.attempts != 1 || len(w.Result().Cookies()) != 1 {
		t.Fatal("router bound fictitious owner phases or lost response custody")
	}
}
