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

func TestSigninRecoveryFeatureSelectsRealHistoryOnly(t *testing.T) {
	c, o, body, _ := recoveryFixture(t)
	feature, err := otphttp.NewSigninRecoveryFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if json.Unmarshal(doc.JSON(), &document) != nil {
		t.Fatal("document")
	}
	paths := document["paths"].(map[string]any)
	if len(paths) != 1 || paths["/v1/otp/signin/recover"] == nil || paths["/v1/otp/signin"] != nil || o.calls != 0 {
		t.Fatal("wrong selection or constructor IO")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, recoveryRequest(body))
	if w.Code != 200 || o.calls != 1 || len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" {
		t.Fatal("selected recovery did not execute safely")
	}
	off, offDoc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	off.ServeHTTP(w, recoveryRequest(body))
	if w.Code != 404 || strings.Contains(string(offDoc.JSON()), "otp.signin") || o.calls != 1 {
		t.Fatal("disabled recovery exposed route or metadata")
	}
}

func TestSigninRecoveryFeatureActualResponsesMatchWire(t *testing.T) {
	for _, mode := range []string{"committed", "not-committed", "unknown", "invalid", "origin", "host", "method", "plaintext"} {
		t.Run(mode, func(t *testing.T) {
			c, o, body, _ := recoveryFixture(t)
			if mode == "unknown" {
				o.result.Issuance.CommitOutcome = identity.CommitOutcomeUnknown
				o.result.SessionID = ""
			}
			if mode == "not-committed" {
				o.result.Issuance.CommitOutcome = identity.CommitOutcomeNotCommitted
				o.result.SessionID = ""
			}
			feature, err := otphttp.NewSigninRecoveryFeature(c)
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
			r := recoveryRequest(body)
			want := 200
			media := "application/json"
			switch mode {
			case "unknown":
				want = 503
			case "invalid":
				r = recoveryRequest(`{"code":"123456"}`)
				want = 400
			case "origin":
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
			if w.Code != want || !strings.HasPrefix(w.Header().Get("Content-Type"), media) || len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatalf("unsafe response status=%d", w.Code)
			}
			parsed, err := openapi.ParseJSON(context.Background(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			node := parsed.Raw()
			for _, key := range []string{"paths", "/v1/otp/signin/recover", "post", "responses", strconv.Itoa(w.Code), "content", media, "schema"} {
				var ok bool
				node, ok = node.Lookup(key)
				if !ok {
					t.Fatal("response schema absent")
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
				t.Fatalf("actual history violates schema: %v %+v", err, report.Diagnostics())
			}
			if media == "application/json" {
				var bad map[string]any
				json.Unmarshal(response, &bad)
				bad["credential"] = "forbidden"
				encoded, _ := json.Marshal(bad)
				instance, _ = parse.JSON(context.Background(), bytes.NewReader(encoded), parse.DefaultLimits())
				report, err = validate.SchemaInstance(context.Background(), parsed, node, instance, validate.InstanceOptions{})
				if err != nil || report.Valid() {
					t.Fatal("recovery wire permits credentials")
				}
			}
			if mode == "committed" {
				var raw map[string]any
				json.Unmarshal(doc.JSON(), &raw)
				op := raw["paths"].(map[string]any)["/v1/otp/signin/recover"].(map[string]any)["post"].(map[string]any)
				if op["responses"].(map[string]any)["200"].(map[string]any)["headers"] != nil {
					t.Fatal("recovery advertised credential headers")
				}
			}
		})
	}
}

func TestSigninRecoveryFeatureRequestGrammarMatchesOriginalCorrelation(t *testing.T) {
	c, _, body, _ := recoveryFixture(t)
	feature, err := otphttp.NewSigninRecoveryFeature(c)
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
	for _, key := range []string{"paths", "/v1/otp/signin/recover", "post", "requestBody", "content", "application/json", "schema"} {
		var ok bool
		node, ok = node.Lookup(key)
		if !ok {
			t.Fatal("request schema absent")
		}
	}
	for _, mode := range []string{"valid", "code", "remember", "digest-string", "digest-zero", "fingerprint", "attemptID", "flowID", "missing"} {
		var input map[string]any
		json.Unmarshal([]byte(body), &input)
		recovery := input["recovery"].(map[string]any)
		switch mode {
		case "code":
			input["code"] = "123456"
		case "remember":
			input["remember"] = true
		case "digest-string":
			recovery["scopeDigest"] = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		case "digest-zero":
			recovery["scopeDigest"] = [32]byte{}
		case "fingerprint":
			recovery["attempt"].(map[string]any)["fingerprint"] = "foreign\n"
		case "attemptID":
			recovery["attempt"].(map[string]any)["attemptID"] = "foreign\n"
		case "flowID":
			input["flowID"] = "foreign\n"
		case "missing":
			delete(recovery, "sendCommandID")
		}
		data, _ := json.Marshal(input)
		instance, err := parse.JSON(context.Background(), bytes.NewReader(data), parse.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		report, err := validate.SchemaInstance(context.Background(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionRequest})
		if err != nil || report.Valid() != (mode == "valid") {
			t.Fatalf("wrong request grammar mode=%s err=%v", mode, err)
		}
	}
}

func TestCombinedSigninRecoveryRetainsDistinctTypedOwners(t *testing.T) {
	c, signin, signinBody := fixture(t)
	recovery, history, body, _ := recoveryFixture(t)
	signin.result = func(_ context.Context, r otp.SigninRequest) (otp.SigninResult, error) { return issuance(t, c, r), nil }
	observed := false
	middleware := hook(identityhttp.MiddlewareAfterHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if s, ok := identityhttp.PipelineValue[otphttp.SigninRecoveryState](r); ok {
			out, attempted := s.Attempt()
			observed = attempted && !out.SignedIn && out.CommitOutcome == "committed"
		}
		next.ServeHTTP(w, r)
	})
	feature, err := otphttp.NewSigninFeatureWithRecoveryAndMiddleware(c, recovery, []identityhttp.MiddlewareDescriptor{middleware})
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil || len(ops) != 2 || signin.attempts != 0 || history.calls != 0 {
		t.Fatal("combined selection is partial or invokes owners")
	}
	h, doc, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: c.Network, HandlerTimeout: c.MaximumDuration, Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}}, ops, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Operations()) != 2 {
		t.Fatal("combined metadata is incomplete")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(signinBody))
	if w.Code != 200 || signin.attempts != 1 || len(w.Result().Cookies()) != 1 {
		t.Fatal("combined signin unavailable")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, recoveryRequest(body))
	if w.Code != 200 || !observed || history.calls != 1 || len(w.Result().Cookies()) != 0 {
		t.Fatal("combined recovery bypassed typed owner")
	}
	recovery.Service = nil
	partial, err := otphttp.NewSigninFeatureWithRecovery(c, recovery)
	if err == nil || len(partial.Operations()) != 0 || signin.attempts != 1 || history.calls != 1 {
		t.Fatal("invalid combined dependencies returned partial selection")
	}
}
