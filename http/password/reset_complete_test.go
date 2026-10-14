package passwordhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

// The native proof/workflow port is deliberate IO substitution. Real network,
// origin, device, decoder and primitive rate admission execute in this test.
type resetCompleteWork struct {
	password.ResetService
	t            *testing.T
	base         *changeFixture
	reads, calls int
	sourceErr    error
	last         password.ResetCompleteRequest
	outcome      identity.CommitOutcome
	err          error
	noReceipt    bool
}

func (s *resetCompleteWork) ResetCompletionRateSource(ctx context.Context, p capability.Proof, c authorization.DecisionContext) (identity.UserID, identity.CredentialID, string, time.Duration, error) {
	s.reads++
	if s.base.rate.calls != 1 || p.ValidateBounds(32, 4096) != nil || c.Request.Resource.ID != "" || c.Request.Tenant != "tenant-a" || c.Request.Action != "identity.password.reset-complete" {
		s.t.Error("original proof not authenticated after IP admission")
	}
	return "original-user", "original-credential", "original-grant", time.Hour, s.sourceErr
}
func (s *resetCompleteWork) ResetComplete(ctx context.Context, r password.ResetCompleteRequest) (password.ResetCompleteResult, error) {
	s.calls++
	s.last = r
	if s.base.rate.calls != 2 || r.Validate() != nil || r.Caller.Request.Resource.ID != "" {
		s.t.Error("completion entered without original challenge admission")
	}
	if err := r.NewPassword.Use(func(raw []byte) error {
		if string(raw) != " replacement-password " {
			s.t.Error("password bytes altered")
		}
		return nil
	}); err != nil {
		s.t.Error(err)
	}
	if s.noReceipt {
		return password.ResetCompleteResult{}, s.err
	}
	if s.outcome != 0 && s.outcome != identity.CommitOutcomeCommitted {
		return password.ResetCompleteResult{CommandID: r.CommandID, Outcome: s.outcome}, s.err
	}
	return password.ResetCompleteResult{CommandID: r.CommandID, Outcome: identity.CommitOutcomeCommitted, CredentialVersion: 2, SessionsRevoked: true}, s.err
}

func TestResetCompleteSelectedTransport(t *testing.T) {
	for _, mode := range []string{"success", "key", "authorization", "unknown-field", "duplicate-json", "query", "source-denied", "rate-outage", "origin", "unknown", "native-conflict", "foreign-conflict", "committed-error", "native-denied", "native-invalid-proof"} {
		t.Run(mode, func(t *testing.T) {
			f, signup, _, device := newSignup(t)
			rate, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: f.rate, Namespace: "reset-verify", Now: f.clock.Now, Key: [32]byte{8}, MaximumDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { rate.Close() })
			work := &resetCompleteWork{t: t, base: f}
			signer, err := capability.NewHMACSHA256Signer("synthetic", []byte(strings.Repeat("x", 32)))
			if err != nil {
				t.Fatal(err)
			}
			now := f.clock.Now()
			token, err := capability.Issue(context.Background(), capability.Payload{Version: 1, Issuer: "https://tenant.example", Audiences: []string{"reset"}, Subject: "original-user", Tenant: "tenant-a", Resource: "identity.password/original-credential", Operation: "identity.password.reset-complete", ID: "original-grant", IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Hour), MaxUses: 1}, signer, capability.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			c := passwordhttp.ResetCompleteConfig{Network: signup.Network, Service: work, Rate: rate, Origin: signup.Origin, Device: signup.Device, ActorID: signup.ActorID, PolicyRevision: signup.PolicyRevision, Now: signup.Now, MaximumDuration: signup.MaximumDuration}
			r := signupRequest(f, device)
			r.URL.Path = "/v1/password/reset-complete"
			r.RequestURI = r.URL.Path
			r.Header.Del("Idempotency-Key")
			body := `{"commandID":"AQEBAQEBAQEBAQEBAQEBAQ","token":"` + token + `","newPassword":" replacement-password "`
			want := 200
			entered := false
			switch mode {
			case "key":
				r.Header.Set("Idempotency-Key", "foreign")
				want = 400
			case "authorization":
				r.Header.Set("Authorization", "Bearer foreign")
				want = 400
			case "unknown-field":
				body += `,"userID":"foreign"`
				want = 400
			case "duplicate-json":
				body += `,"token":"foreign"`
				want = 400
			case "query":
				r.URL.RawQuery = "token=foreign"
				want = 400
			case "source-denied":
				work.sourceErr = identity.ForbiddenError{}
				want = 403
			case "rate-outage":
				f.rate.fail = true
				want = 503
			case "origin":
				r.Header.Set("Origin", "https://foreign.test")
				want = 403
			case "unknown":
				work.outcome = identity.CommitOutcomeUnknown
				want = 503
				entered = true
			case "native-conflict":
				work.outcome = identity.CommitOutcomeConflict
				work.err = identity.ConflictError{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ"}
				want = 409
				entered = true
			case "foreign-conflict":
				work.outcome = identity.CommitOutcomeConflict
				work.err = identity.ConflictError{CommandID: "AgICAgICAgICAgICAgICAg"}
				want = 503
				entered = true
			case "committed-error":
				work.err = context.Canceled
				want = 503
				entered = true
			case "native-denied":
				work.noReceipt, work.err, want, entered = true, identity.ForbiddenError{}, 403, true
			case "native-invalid-proof":
				work.noReceipt, work.err, want, entered = true, password.ErrInvalidReset, 403, true
			}
			r.Body = signupBody(r, body+"}")
			h, err := passwordhttp.NewResetCompleteHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			var doc identityhttp.OpenAPIDocument
			if mode == "success" {
				requestConfig := passwordhttp.ResetRequestConfig{Network: signup.Network, Service: &resetRequestWork{base: f}, Rate: signup.Rate, Origin: signup.Origin, CallbackURL: "https://identity.test/reset", Device: signup.Device, ActorID: signup.ActorID, PolicyRevision: signup.PolicyRevision, Now: signup.Now, MaximumDuration: signup.MaximumDuration}
				feature, err := passwordhttp.NewFeature(passwordhttp.FeatureConfig{ResetComplete: &c, ResetRequest: &requestConfig})
				if err != nil {
					t.Fatal(err)
				}
				h, doc, err = identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Reset", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
				if err != nil || len(doc.Operations()) != 2 {
					t.Fatal("completion selected composition", err)
				}
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want {
				t.Fatal("completion outcome", w.Code, w.Body.String())
			}
			if want != 200 {
				if !entered && work.calls != 0 {
					t.Fatal("denied completion mutated password")
				}
				if entered {
					var out passwordhttp.ResetCompleteResponse
					if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Completed || out.SessionsRevoked || out.CredentialVersion != 0 || out.CommandID != "AQEBAQEBAQEBAQEBAQEBAQ" || out.Recovery == nil || work.calls != 1 || work.last.NewPassword.Len() != 0 || work.last.Token.ValidateBounds(32, 4096) == nil {
						t.Fatal("failed completion lost original history or custody", w.Body.String())
					}
				}
				return
			}
			var out passwordhttp.ResetCompleteResponse
			if json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Completed || !out.SessionsRevoked || out.CredentialVersion != 2 || out.CommitOutcome != "committed" || work.calls != 1 || work.reads != 1 {
				t.Fatal("completion receipt missing", w.Body.String())
			}
			if work.last.NewPassword.Len() != 0 || work.last.Token.ValidateBounds(32, 4096) == nil || len(w.Result().Cookies()) != 0 || strings.Contains(w.Body.String(), "replacement-password") || strings.Contains(w.Body.String(), token) {
				t.Fatal("completion custody leaked or survived handler")
			}
			if _, err := passwordhttp.NewFeature(passwordhttp.FeatureConfig{ResetComplete: &c}); err != nil {
				t.Fatal("completion feature", err)
			}
			parsed, err := openapi.ParseJSON(context.Background(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			node := parsed.Raw()
			for _, key := range []string{"paths", "/v1/password/reset-complete", "post", "responses", "200", "content", "application/json", "schema"} {
				var ok bool
				node, ok = node.Lookup(key)
				if !ok {
					t.Fatal("completion wire response absent")
				}
			}
			instance, err := parse.JSON(context.Background(), bytes.NewReader(w.Body.Bytes()), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			report, err := validate.SchemaInstance(context.Background(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
			if err != nil || !report.Valid() {
				t.Fatal("completion response contradicts schema", err)
			}
		})
	}
}
