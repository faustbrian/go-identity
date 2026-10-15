package passwordhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

// Native reset is the deliberate IO boundary; transport uses actual network,
// origin, signed-device, decoder and shared primitive rate owners.
type resetRequestWork struct {
	password.ResetService
	base         *changeFixture
	reads, calls int
	last         password.ResetRequestRequest
}

func (s *resetRequestWork) ResetRequestRateSource(ctx context.Context, input identifier.Input) (string, error) {
	s.reads++
	if s.base.rate.calls != 1 || input != "person@EXAMPLE.test" {
		panic("reset destination read before IP admission or changed input")
	}
	return "person@example.test", nil
}

func (s *resetRequestWork) ResetRequest(ctx context.Context, r password.ResetRequestRequest) (password.ResetRequestResult, error) {
	s.calls++
	s.last = r
	if s.base.rate.calls != 2 || r.Validate() != nil {
		panic("unadmitted reset")
	}
	return password.ResetRequestResult{CommandID: "AgICAgICAgICAgICAgICAg", Outcome: identity.CommitOutcomeCommitted, Accepted: true}, nil
}

func TestResetRequestSelectedTransport(t *testing.T) {
	for _, mode := range []string{"success", "unknown-field", "duplicate-json", "missing-key", "authorization", "origin", "wrong-callback", "rate-outage"} {
		t.Run(mode, func(t *testing.T) {
			f, signup, _, device := newSignup(t)
			work := &resetRequestWork{base: f}
			c := passwordhttp.ResetRequestConfig{Network: signup.Network, Service: work, Rate: signup.Rate, Origin: signup.Origin, CallbackURL: "https://identity.test/reset", Device: signup.Device, ActorID: signup.ActorID, PolicyRevision: signup.PolicyRevision, Now: signup.Now, MaximumDuration: signup.MaximumDuration}
			r := signupRequest(f, device)
			r.URL.Path, r.RequestURI = "/v1/password/reset-request", "/v1/password/reset-request"
			body := `{"commandID":"AQEBAQEBAQEBAQEBAQEBAQ","identifier":"person@EXAMPLE.test","callbackURL":"` + c.CallbackURL + `"`
			want := 200
			switch mode {
			case "unknown-field":
				body += `,"userID":"foreign"`
				want = 400
			case "duplicate-json":
				body += `,"identifier":"foreign"`
				want = 400
			case "missing-key":
				r.Header.Del("Idempotency-Key")
				want = 400
			case "authorization":
				r.Header.Set("Authorization", "Bearer foreign")
				want = 400
			case "origin":
				r.Header.Set("Origin", "https://foreign.test")
				want = 403
			case "wrong-callback":
				body = strings.Replace(body, c.CallbackURL, "https://foreign.test/reset", 1)
				want = 400
			case "rate-outage":
				f.rate.fail = true
				want = 503
			}
			r.Body = signupBody(r, body+"}")
			h, err := passwordhttp.NewResetRequestHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			var doc identityhttp.OpenAPIDocument
			if mode == "success" {
				feature, err := passwordhttp.NewFeature(passwordhttp.FeatureConfig{ResetRequest: &c})
				if err != nil {
					t.Fatal(err)
				}
				h, doc, err = identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Reset", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
				if err != nil || len(doc.Operations()) != 1 {
					t.Fatal("reset selected composition", err)
				}
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want {
				t.Fatal("reset HTTP outcome", w.Code, w.Body.String())
			}
			if want != 200 {
				if work.calls != 0 {
					t.Fatal("denied request entered native reset")
				}
				return
			}
			var out passwordhttp.ResetRequestResponse
			if json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Accepted || out.CommitOutcome != "committed" || work.calls != 1 || work.reads != 1 || out.CommandID != "AgICAgICAgICAgICAgICAg" || out.Recovery == nil || out.Recovery.AttemptID != work.last.CommandID {
				t.Fatal("reset acknowledgement lost original recovery scope", w.Body.String())
			}
			if work.last.Caller.Request.Subject.Kind != authorization.SubjectServiceAccount || work.last.TenantID != "tenant-a" || work.last.Device == "" || work.last.Caller.CorrelationID == string(work.last.CommandID) || len(w.Result().Cookies()) != 0 || strings.Contains(w.Body.String(), "person@") {
				t.Fatal("reset input or credentials leaked or caller selected authority")
			}
			feature, err := passwordhttp.NewFeature(passwordhttp.FeatureConfig{ResetRequest: &c})
			if err != nil || feature.ID() != "identity/password" {
				t.Fatal("selected reset feature", err)
			}
			parsed, err := openapi.ParseJSON(context.Background(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			node := parsed.Raw()
			for _, key := range []string{"paths", "/v1/password/reset-request", "post", "responses", "200", "content", "application/json", "schema"} {
				var ok bool
				node, ok = node.Lookup(key)
				if !ok {
					t.Fatal("actual reset schema missing")
				}
			}
			instance, err := parse.JSON(context.Background(), bytes.NewReader(w.Body.Bytes()), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			report, err := validate.SchemaInstance(context.Background(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
			if err != nil || !report.Valid() {
				t.Fatal("reset response contradicts selected schema", err)
			}
		})
	}
}
