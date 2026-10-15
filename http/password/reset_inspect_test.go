package passwordhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

// Only native proof/current-authority IO is substituted. Real typed transport,
// strict parsing, origin admission and shared rate dispatch remain exercised.
type resetInspectWork struct {
	t              *testing.T
	base           *changeFixture
	reads, calls   int
	last           password.ResetInspectRequest
	sourceErr, err error
	valid          bool
}

func (s *resetInspectWork) ResetInspectionRateSource(ctx context.Context, proof capability.Proof, caller authorization.DecisionContext) (identity.UserID, identity.CredentialID, string, time.Duration, error) {
	s.reads++
	if _, bounded := ctx.Deadline(); !bounded || s.base.rate.calls != 1 || proof.ValidateBounds(32, 4096) != nil || caller.Request.Resource.ID != "" || caller.Request.Action != "identity.password.reset-inspect" || caller.Request.Tenant != "tenant-a" {
		s.t.Error("inspection source lacked bounded prior IP admission or trusted scope")
	}
	return "original-user", "original-credential", "original-grant", time.Minute, s.sourceErr
}

func (s *resetInspectWork) ResetInspect(ctx context.Context, request password.ResetInspectRequest) (password.ResetInspectResult, error) {
	s.calls++
	s.last = request
	if _, bounded := ctx.Deadline(); !bounded || s.base.rate.calls != 2 || request.Validate() != nil || request.Caller.Request.Resource.ID != "" {
		s.t.Error("native inspection lacked original-source subject admission")
	}
	return password.ResetInspectResult{Valid: s.valid}, s.err
}

func TestResetInspectionClosedTransportAndDocumentedOutcomes(t *testing.T) {
	for _, mode := range []string{"valid", "invalid", "source-invalid", "source-unavailable", "owner-unavailable", "key", "authorization", "unknown-field", "duplicate-token", "query", "get", "escaped-path", "http", "origin", "trailer", "short", "oversize", "rate-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			f, selected, _, device := newSignup(t)
			rate, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: f.rate, Namespace: "inspect-test", Key: [32]byte{1}, Now: f.clock.Now, MaximumDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = rate.Close() })
			work := &resetInspectWork{t: t, base: f, valid: true}
			signer, err := capability.NewHMACSHA256Signer("synthetic", []byte(strings.Repeat("x", 32)))
			if err != nil {
				t.Fatal(err)
			}
			now := f.clock.Now()
			token, err := capability.Issue(context.Background(), capability.Payload{Version: 1, Issuer: "https://tenant.example", Audiences: []string{"reset"}, Subject: "original-user", Tenant: "tenant-a", Resource: "identity.password/original-credential", Operation: "identity.password.reset-complete", ID: "original-grant", IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), MaxUses: 1}, signer, capability.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			config := passwordhttp.ResetInspectConfig{Network: selected.Network, Service: work, Rate: rate, Origin: selected.Origin, ActorID: selected.ActorID, PolicyRevision: selected.PolicyRevision, MaximumDuration: selected.MaximumDuration}
			feature, err := passwordhttp.NewFeature(passwordhttp.FeatureConfig{ResetInspect: &config})
			if err != nil {
				t.Fatal(err)
			}
			handler, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Inspection", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
			if err != nil || len(doc.Operations()) != 1 {
				t.Fatal("explicit inspection composition failed")
			}
			request := signupRequest(f, device)
			request.Header.Del("Idempotency-Key")
			request.URL.Path = "/v1/password/reset/inspect"
			request.RequestURI = request.URL.Path
			body := `{"token":"` + token + `"}`
			want, valid := 200, true
			switch mode {
			case "invalid":
				work.valid, valid = false, false
			case "source-invalid":
				work.sourceErr, valid = identity.ForbiddenError{}, false
			case "source-unavailable":
				work.sourceErr, want = identity.UnavailableError{}, 503
			case "owner-unavailable":
				work.err, want = identity.UnavailableError{}, 503
			case "key":
				request.Header.Set("Idempotency-Key", "foreign")
				want = 400
			case "authorization":
				request.Header.Set("Authorization", "Bearer foreign")
				want = 400
			case "unknown-field":
				body = strings.TrimSuffix(body, "}") + `,"userID":"foreign"}`
				want = 400
			case "duplicate-token":
				body = strings.TrimSuffix(body, "}") + `,"token":"foreign"}`
				want = 400
			case "query":
				request.URL.RawQuery = "token=foreign"
				want = 400
			case "get":
				request.Method = http.MethodGet
				want = 405
			case "escaped-path":
				request.URL.RawPath = "/v1/password/reset/%69nspect"
				want = 404
			case "http":
				request.TLS = nil
				want = 403
			case "origin":
				request.Header.Set("Origin", "https://foreign.example")
				want = 403
			case "trailer":
				request.Trailer = http.Header{"Idempotency-Key": []string{"foreign"}}
				want = 400
			case "short":
				body = `{"token":"short"}`
				want = 400
			case "oversize":
				body = `{"token":"` + strings.Repeat("x", 4097) + `"}`
				want = 400
			case "rate-unavailable":
				f.rate.fail = true
				want = 503
			}
			request.Body = signupBody(request, body)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != want || recorder.Header().Get("Cache-Control") != "no-store" || len(recorder.Result().Cookies()) != 0 || recorder.Header().Get("Location") != "" || strings.Contains(recorder.Body.String(), token) || strings.Contains(recorder.Body.String(), "original-user") {
				t.Fatal("inspection exposed unsupported state or outcome", recorder.Code)
			}
			if want == 200 {
				var result passwordhttp.ResetInspectResponse
				var fields map[string]json.RawMessage
				if json.Unmarshal(recorder.Body.Bytes(), &result) != nil || json.Unmarshal(recorder.Body.Bytes(), &fields) != nil || result.Valid != valid || len(fields) != 1 {
					t.Fatal("inspection returned more than advisory state")
				}
			} else if mode != "owner-unavailable" && work.calls != 0 {
				t.Fatal("denied transport reached current-authority inspection")
			}
			if work.calls != 0 && work.last.Token.ValidateBounds(32, 4096) == nil {
				t.Fatal("handler retained live bearer custody")
			}
			parsed, err := openapi.ParseJSON(context.Background(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			media := "application/json"
			instance := recorder.Body.Bytes()
			if strings.HasPrefix(recorder.Header().Get("Content-Type"), "text/plain") {
				media = "text/plain"
				instance, err = json.Marshal(recorder.Body.String())
				if err != nil {
					t.Fatal(err)
				}
			}
			node := parsed.Raw()
			for _, key := range []string{"paths", "/v1/password/reset/inspect", "post", "responses", strconv.Itoa(want), "content", media, "schema"} {
				var ok bool
				node, ok = node.Lookup(key)
				if !ok {
					t.Fatal("actual inspection outcome missing from OpenAPI", mode, media)
				}
			}
			value, err := parse.JSON(context.Background(), bytes.NewReader(instance), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			report, err := validate.SchemaInstance(context.Background(), parsed, node, value, validate.InstanceOptions{Direction: validate.DirectionResponse})
			if err != nil || !report.Valid() {
				t.Fatal("inspection response contradicts OpenAPI", mode)
			}
		})
	}
	if handler, err := passwordhttp.NewResetInspectHandler(passwordhttp.ResetInspectConfig{}); handler != nil || !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("missing inspection owners accepted")
	}
}
