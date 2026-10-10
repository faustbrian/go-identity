package passwordhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

// The wire oracle is the owned OpenAPI schema engine against actual selected
// router responses. Native ports are deliberate transport seams, not SQL proof.
func TestVerificationFeatureDocumentMatchesSelectedRouter(t *testing.T) {
	for _, scenario := range []string{"success", "mismatch", "unknown", "not-committed", "committed-error", "cancel", "rate", "rate-outage", "key", "inactive", "host", "method", "path", "plaintext", "origin"} {
		t.Run(scenario, func(t *testing.T) {
			f, c, work := newVerification(t)
			feature, err := passwordhttp.NewBearerVerificationFeature(c)
			if err != nil {
				t.Fatal(err)
			}
			if work.calls != 0 || f.reader.calls != 0 || f.rate.calls != 0 {
				t.Fatal("constructor invoked owner")
			}
			ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
			if err != nil || len(ops) != 1 || ops[0].Record.Idempotency != "none" || ops[0].Record.CSRFOrigin.Mode != identityhttp.CSRFNone {
				t.Fatal("wrong selected profile")
			}
			h, doc, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: c.Network, HandlerTimeout: c.MaximumDuration, Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}}, ops, nil)
			if err != nil {
				t.Fatal(err)
			}
			var root struct {
				Paths map[string]map[string]struct {
					Security   []map[string][]string `json:"security"`
					Parameters []map[string]any      `json:"parameters"`
				} `json:"paths"`
			}
			if json.Unmarshal(doc.JSON(), &root) != nil || len(root.Paths) != 1 || doc.Version() != "3.1.1" {
				t.Fatal("wrong selected document")
			}
			operation := root.Paths["/v1/password/verify"]["post"]
			if len(operation.Security) != 1 || len(operation.Security[0]) != 1 || operation.Security[0]["PasswordVerificationBearer"] == nil || len(operation.Parameters) != 0 {
				t.Fatal("wrong bearer or key policy")
			}
			r := verificationRequest(f)
			want := 200
			media := "application/json"
			switch scenario {
			case "mismatch":
				work.result = password.VerificationResult{}
				want = 403
			case "unknown":
				work.result.Outcome = identity.CommitOutcomeUnknown
				work.err = context.DeadlineExceeded
				want = 503
			case "committed-error":
				work.err = context.DeadlineExceeded
				want = 503
			case "not-committed":
				work.result.Outcome = identity.CommitOutcomeNotCommitted
				want = 503
			case "cancel":
				ctx, cancel := context.WithCancel(r.Context())
				defer cancel()
				r = r.WithContext(ctx)
				work.cancel = cancel
				want = 503
			case "rate":
				f.rate.limited = true
				want = 429
			case "rate-outage":
				f.rate.fail = true
				want = 503
			case "key":
				r.Header.Set("Idempotency-Key", "forbidden")
				want = 400
			case "inactive":
				f.reader.observation.Active = false
				want = 401
			case "host":
				r.Host = "foreign.example"
				want = 421
			case "method":
				r.Method = http.MethodGet
				want = 405
			case "path":
				r.URL.Path, r.RequestURI = "/v1/password/unselected", "/v1/password/unselected"
				want = 404
			case "plaintext":
				r.TLS = nil
				r.URL.Scheme = "http"
				want = 403
			case "origin":
				r.Header.Set("Origin", "https://foreign.example")
				want, media = 403, "text/plain"
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want || w.Header().Get("Cache-Control") != "no-store" || len(w.Header().Values("Set-Cookie")) != 0 {
				t.Fatalf("wrong response: %d", w.Code)
			}
			if scenario == "rate" && (w.Header().Get("Retry-After") != "1" || work.calls != 0) {
				t.Fatal("wrong bounded rate denial")
			}
			parsed, err := openapi.ParseJSON(context.Background(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			schema := parsed.Raw()
			for _, key := range []string{"paths", "/v1/password/verify", "post", "responses", strconv.Itoa(w.Code), "content", media, "schema"} {
				var ok bool
				schema, ok = schema.Lookup(key)
				if !ok {
					t.Fatalf("missing wire schema %s", key)
				}
			}
			body := w.Body.Bytes()
			if media == "text/plain" {
				body, _ = json.Marshal(w.Body.String())
			}
			instance, err := parse.JSON(context.Background(), bytes.NewReader(body), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			report, err := validate.SchemaInstance(context.Background(), parsed, schema, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
			if err != nil || !report.Valid() {
				t.Fatalf("actual response rejected: %v %+v", err, report.Diagnostics())
			}
			if media == "text/plain" {
				return
			}
			var mutated map[string]any
			if json.Unmarshal(w.Body.Bytes(), &mutated) != nil {
				t.Fatal("invalid actual JSON")
			}
			if want == 200 {
				mutated["credential"] = "forbidden"
			} else {
				mutated["proof"] = map[string]any{"proofID": "forbidden"}
			}
			badJSON, _ := json.Marshal(mutated)
			bad, _ := parse.JSON(context.Background(), bytes.NewReader(badJSON), parse.DefaultLimits())
			badReport, err := validate.SchemaInstance(context.Background(), parsed, schema, bad, validate.InstanceOptions{})
			if err != nil || badReport.Valid() {
				t.Fatal("wire admitted credential or error proof")
			}
			if scenario == "success" {
				request := parsed.Raw()
				for _, key := range []string{"paths", "/v1/password/verify", "post", "requestBody", "content", "application/json", "schema"} {
					request, _ = request.Lookup(key)
				}
				for _, candidate := range []struct {
					body  string
					valid bool
				}{
					{`{"password":"synthetic","purpose":"identity.password.verify","action":"identity.password.change","audience":"identity-service"}`, true},
					{`{"password":"","purpose":"identity.password.verify","action":"identity.password.change","audience":"identity-service"}`, false},
					{`{"password":"synthetic","purpose":"identity.password.verify","action":"identity.password.change"}`, false},
					{`{"password":"synthetic","purpose":"identity.password.verify","action":"identity.password.change","audience":"identity-service","tenantID":"other"}`, false},
					{`{"password":"synthetic","purpose":"identity.password.verify","action":"identity.password.change","audience":"identity-service","idempotencyKey":"other"}`, false},
				} {
					value, err := parse.JSON(context.Background(), strings.NewReader(candidate.body), parse.DefaultLimits())
					if err != nil {
						t.Fatal(err)
					}
					report, err := validate.SchemaInstance(context.Background(), parsed, request, value, validate.InstanceOptions{Direction: validate.DirectionRequest})
					if err != nil || report.Valid() != candidate.valid {
						t.Fatal("request contract mismatch")
					}
				}
			}
		})
	}
}

func TestPasswordFeatureComposesSelectedOperationsAndDeniesPartialSelection(t *testing.T) {
	f, c, work := newVerification(t)
	feature, err := passwordhttp.NewFeature(passwordhttp.FeatureConfig{Change: &f.config, BearerVerification: &c})
	if err != nil {
		t.Fatal(err)
	}
	selection := identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}}
	ops, err := identityhttp.NewOperationDescriptors(selection)
	if err != nil || len(ops) != 2 {
		t.Fatal("combined package contribution collided")
	}
	h, err := identityhttp.NewSelectedHandler(selection)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, verificationRequest(f))
	if w.Code != 200 || work.calls != 1 {
		t.Fatal("combined verification unavailable")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, changeRequest(f))
	if w.Code != 200 || f.work.calls != 1 {
		t.Fatal("combined change unavailable")
	}
	for _, invalid := range []passwordhttp.FeatureConfig{{}, {Change: &passwordhttp.ChangeConfig{}, BearerVerification: &c}, {Change: &f.config, BearerVerification: &passwordhttp.BearerVerificationConfig{}}} {
		partial, err := passwordhttp.NewFeature(invalid)
		if err == nil || partial.ID() != "" {
			t.Fatal("invalid selection returned partial feature")
		}
	}
	disabled, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	disabled.ServeHTTP(w, verificationRequest(f))
	if w.Code != 404 || len(doc.Operations()) != 0 || work.calls != 1 {
		t.Fatal("disabled verification exposed")
	}
}

func TestCombinedPasswordFeatureKeepsCookieChangeAndBearerVerificationDistinct(t *testing.T) {
	f, c, work := newVerification(t)
	cookie := newChange(t, session.CredentialCookie)
	selected := passwordhttp.FeatureConfig{Change: &cookie.config, BearerVerification: &c}
	seen := 0
	feature, err := passwordhttp.NewFeatureWithMiddleware(selected, []identityhttp.MiddlewareDescriptor{{Owner: "identity/password", Middleware: identityhttp.Middleware{Name: "observe", Phase: identityhttp.MiddlewareAfterAuth, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/password/verify" {
				s, ok := identityhttp.PipelineValue[passwordhttp.VerificationState](r)
				if _, user, present := s.Principal(); !ok || !present || user != "user-a" {
					t.Error("verification typed state absent")
				}
			} else {
				if _, ok := identityhttp.PipelineValue[passwordhttp.ChangeState](r); !ok {
					t.Error("change typed state absent")
				}
			}
			seen++
			next.ServeHTTP(w, r)
		})
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	// Exports and original configuration cannot rewrite the frozen contribution.
	ops[0].Wire.Definition[0] = '!'
	c.PolicyRevision = 0
	ops, err = identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: f.config.Network, HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}}, ops, nil)
	if err != nil || len(doc.Operations()) != 2 {
		t.Fatal("combined document failed", err)
	}
	for _, r := range []*http.Request{verificationRequest(f), changeRequest(cookie)} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("selected mode failed %s: %d", r.URL.Path, w.Code)
		}
	}
	if seen != 2 || work.calls != 1 || cookie.work.calls != 1 {
		t.Fatal("combined typed phases lost")
	}
	if _, err := json.Marshal(selected); err == nil || strings.Contains(fmt.Sprintf("%+v", selected), "tenant.example") {
		t.Fatal("feature configuration exported")
	}
}

func TestVerificationFeatureRejectsMissingOwnersWithoutPartialSelection(t *testing.T) {
	f, c, work := newVerification(t)
	for _, mutate := range []func(*passwordhttp.BearerVerificationConfig){
		func(c *passwordhttp.BearerVerificationConfig) { c.Sessions = nil },
		func(c *passwordhttp.BearerVerificationConfig) { c.Verification = nil },
		func(c *passwordhttp.BearerVerificationConfig) { c.Rate = nil },
		func(c *passwordhttp.BearerVerificationConfig) { c.PolicyRevision = 0 },
		func(c *passwordhttp.BearerVerificationConfig) { c.Now = nil },
		func(c *passwordhttp.BearerVerificationConfig) { c.MaximumDuration = 0 },
		func(c *passwordhttp.BearerVerificationConfig) { c.Network = identityhttp.NetworkConfig{} },
	} {
		bad := c
		mutate(&bad)
		partial, err := passwordhttp.NewBearerVerificationFeature(bad)
		if err == nil || partial.ID() != "" {
			t.Fatal("missing owner returned partial feature")
		}
	}
	c.Rate.Close()
	if _, err := passwordhttp.NewBearerVerificationFeature(c); err == nil {
		t.Fatal("closed rate selected")
	}
	if f.reader.calls != 0 || f.rate.calls != 0 || work.calls != 0 {
		t.Fatal("invalid construction invoked owner")
	}
}
