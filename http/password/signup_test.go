package passwordhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"bytes"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

// The native workflow is the deliberate test boundary. Real normalization,
// transactions and provider custody are covered by the native adapter fixture.
type signupWork struct {
	base           *changeFixture
	reads, calls   int
	last           password.SignupRequest
	input          password.SignupAddressInput
	result         password.SignupResult
	err, sourceErr error
	cancel         context.CancelFunc
	rawMatches     bool
	failIdentifier bool
}

func (s *signupWork) SignupRateSource(ctx context.Context, input password.SignupAddressInput) (string, error) {
	s.reads++
	s.input = input
	if _, ok := ctx.Deadline(); !ok || s.base.rate.calls != 1 {
		panic("source before IP or unbounded")
	}
	if s.failIdentifier {
		s.base.rate.fail = true
	}
	return "person@example.test", s.sourceErr
}
func (s *signupWork) Signup(ctx context.Context, r password.SignupRequest) (password.SignupResult, error) {
	s.calls++
	s.last = r
	_ = r.Password.Use(func(raw []byte) error { s.rawMatches = bytes.Equal(raw, []byte(" synthetic-password ")); return nil })
	if _, ok := ctx.Deadline(); !ok || s.base.rate.calls != 2 {
		panic("unadmitted signup")
	}
	if s.cancel != nil {
		s.cancel()
	}
	return s.result, s.err
}
func (*signupWork) RecoverSignup(context.Context, password.SignupRecoveryRequest) (password.SignupResult, error) {
	panic("transport auto recovered")
}

func newSignup(t *testing.T) (*changeFixture, passwordhttp.SignupConfig, *signupWork, *http.Cookie) {
	f, signin, _, device := newSignin(t)
	work := &signupWork{base: f}
	c := passwordhttp.SignupConfig{Network: signin.Network, Service: work, Rate: signin.Rate, Origin: signin.Origin, CallbackURL: signin.CallbackURL, Lifetime: signin.Lifetime, FlowCookie: signin.FlowCookie, Device: signin.Device, ActorID: signin.ActorID, PolicyRevision: signin.PolicyRevision, Now: signin.Now, MaximumDuration: signin.MaximumDuration, FieldSchema: signupSchema()}
	q := identity.RecoveryQuery{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant-a", AnonymousFlowID: "AQEBAQEBAQEBAQEBAQEBAQ", ActorID: c.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.password.signup"}
	recovery, err := password.NewSignupRecovery(q, identity.PreAuthTransactionID(q.AnonymousFlowID))
	if err != nil {
		t.Fatal(err)
	}
	work.result = password.SignupResult{Outcome: identity.CommitOutcomeCommitted, VerificationRequired: true, Recovery: recovery}
	return f, c, work, device
}
func signupSchema() identity.AttributeSchema {
	return identity.AttributeSchema{ID: "signup-fields", Version: 1, Fields: []identity.FieldPolicy{{Name: "name", Kind: identity.AttributeString, Cardinality: identity.CardinalityScalar, Normalization: identity.NormalizeNone, InputPermission: identity.FieldWrite, OutputPermission: identity.FieldRead, WriteAuthorization: identity.FieldWriteSystem, Sensitivity: identity.SensitivityPersonal, MigrationVersion: 1}}}
}
func signupRequest(f *changeFixture, device *http.Cookie) *http.Request {
	r := signinRequest(f, device)
	r.URL.Path = "/v1/password/signup"
	r.RequestURI = r.URL.Path
	r.Header.Set("Idempotency-Key", "Original-Custody_001")
	r.Body = signupBody(r, `{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","email":"person@EXAMPLE.test","password":" synthetic-password ","callbackURL":""}`)
	return r
}

func serveSignup(t *testing.T, c passwordhttp.SignupConfig, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	h, err := passwordhttp.NewSignupHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	return signupRecorder(h, r)
}

func TestSignupClosedInputAndAdmission(t *testing.T) {
	for _, mode := range []string{"no-key", "duplicate-key", "bad-key", "cookie-key", "body-key", "query-key", "trailer", "authorization", "csrf-alternative", "no-flow", "no-device", "origin", "http", "host", "unknown-field", "duplicate-json", "null-remember", "wrong-callback", "unselected-field", "duplicate-fields", "null-fields", "bad-type", "source-outage", "rate-outage"} {
		t.Run(mode, func(t *testing.T) {
			f, c, work, device := newSignup(t)
			r := signupRequest(f, device)
			want, reads, rates := 400, 0, 0
			body := `{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","email":"person@EXAMPLE.test","password":" synthetic-password ","callbackURL":""`
			switch mode {
			case "no-key":
				r.Header.Del("Idempotency-Key")
			case "duplicate-key":
				r.Header.Add("Idempotency-Key", "foreign")
			case "bad-key":
				r.Header.Set("Idempotency-Key", " original ")
			case "cookie-key":
				r.AddCookie(&http.Cookie{Name: "idempotency_key", Value: "foreign"})
			case "query-key":
				r.URL.RawQuery = "idempotency_key=foreign"
				r.RequestURI += "?" + r.URL.RawQuery
			case "trailer":
				r.Trailer = http.Header{"Idempotency-Key": []string{"foreign"}}
			case "authorization":
				r.Header.Set("Authorization", "Bearer foreign")
			case "csrf-alternative":
				r.Header.Set("X-CSRF-Token", "foreign")
			case "no-flow":
				r.Header.Del("Cookie")
				r.AddCookie(device)
			case "no-device":
				r.Header.Del("Cookie")
				r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: f.wire})
			case "origin":
				r.Header.Set("Origin", "https://foreign.test")
				want = 403
			case "http":
				r.TLS = nil
				want = 403
			case "host":
				r.Host = "unknown.example"
				want = 421
			case "body-key":
				body += `,"idempotencyKey":"foreign"`
			case "unknown-field":
				body += `,"userID":"foreign"`
			case "duplicate-json":
				body += `,"email":"other"`
			case "null-remember":
				body += `,"remember":null`
			case "wrong-callback":
				body = strings.Replace(body, `"callbackURL":""`, `"callbackURL":"https://foreign.test"`, 1)
			case "unselected-field":
				body += `,"allowedFields":[{"name":"admin","kind":"bool","value":true}]`
			case "duplicate-fields":
				body += `,"allowedFields":[{"name":"name","kind":"string","value":"a"},{"name":"name","kind":"string","value":"b"}]`
			case "null-fields":
				body += `,"allowedFields":null`
			case "bad-type":
				body += `,"allowedFields":[{"name":"name","kind":"string","value":1}]`
			case "source-outage":
				work.sourceErr = errors.New("private diagnostic")
				want, reads, rates = 503, 1, 1
			case "rate-outage":
				f.rate.fail = true
				want, rates = 503, 1
			}
			r.Body = signupBody(r, body+"}")
			w := serveSignup(t, c, r)
			if w.Code != want || work.calls != 0 || work.reads != reads || f.rate.calls != rates || len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatalf("hostile request reached signup status=%d reads=%d calls=%d rates=%d", w.Code, work.reads, work.calls, f.rate.calls)
			}
		})
	}
}

func TestSignupNativeHistoryAndReplay(t *testing.T) {
	for _, mode := range []string{"replay", "unknown", "committed-error", "canceled", "conflict", "in-progress", "rollback", "foreign-result", "unsupported-profile", "invalid-result"} {
		t.Run(mode, func(t *testing.T) {
			f, c, work, device := newSignup(t)
			r := signupRequest(f, device)
			want, outcome := 503, "committed"
			switch mode {
			case "replay":
				work.result.Replayed = true
				want = 200
			case "unknown":
				work.result.Outcome = identity.CommitOutcomeUnknown
				work.result.VerificationRequired = false
				outcome = "unknown"
			case "committed-error":
				work.err = errors.New("private diagnostic")
			case "canceled":
				ctx, cancel := context.WithCancel(r.Context())
				defer cancel()
				r = r.WithContext(ctx)
				work.cancel = cancel
			case "conflict":
				work.result.Outcome = identity.CommitOutcomeConflict
				work.result.VerificationRequired = false
				want, outcome = 409, "conflict"
			case "in-progress":
				work.result.Outcome = identity.CommitOutcomeInProgress
				work.result.VerificationRequired = false
				work.result.RetryAfter = 2 * time.Second
				want, outcome = 409, "in_progress"
			case "rollback":
				work.result.Outcome = identity.CommitOutcomeNotCommitted
				work.result.VerificationRequired = false
				want, outcome = 403, "not_committed"
			case "foreign-result":
				q, flow, _ := work.result.Recovery.Bindings()
				q.TenantID = "foreign"
				work.result.Recovery, _ = password.NewSignupRecovery(q, flow)
				outcome = "unknown"
			case "unsupported-profile":
				work.result.VerificationRequired = false
			case "invalid-result":
				work.result = password.SignupResult{}
				outcome = "unknown"
			}
			w := serveSignup(t, c, r)
			var out passwordhttp.SignupResponse
			if w.Code != want || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.CommitOutcome != outcome || work.calls != 1 || work.last.Password.Len() != 0 || len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatalf("history/custody changed status=%d outcome=%s", w.Code, out.CommitOutcome)
			}
			if mode == "foreign-result" && out.Recovery != nil {
				t.Fatal("foreign history disclosed")
			}
			if mode == "in-progress" && w.Header().Get("Retry-After") != "2" {
				t.Fatal("original retry metadata lost")
			}
			for _, private := range []string{"person@", "synthetic-password", "Original-Custody_001", "private diagnostic"} {
				if strings.Contains(w.Body.String(), private) {
					t.Fatal("private input/diagnostic disclosed")
				}
			}
		})
	}
}

func TestSignupTypedFieldShapeAndRemember(t *testing.T) {
	f, c, work, device := newSignup(t)
	r := signupRequest(f, device)
	r.Body = signupBody(r, `{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","email":"person@EXAMPLE.test","password":" synthetic-password ","callbackURL":"","remember":true,"allowedFields":[{"name":"name","kind":"string","value":""}]}`)
	h, err := passwordhttp.NewSignupHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	c.FieldSchema.Fields[0].Name = "changed-after-construction"
	w := signupRecorder(h, r)
	if w.Code != 200 || len(work.last.AllowedFields) != 1 || work.last.AllowedFields[0].Name != "name" || work.last.AllowedFields[0].Value.Scalar.String != "" {
		t.Fatal("selected field snapshot changed")
	}
	remember, err := session.ResolveRememberPolicy(session.PersistentSession, c.Lifetime)
	if err != nil || work.last.RememberPolicy != remember {
		t.Fatal("remember choice changed")
	}
}

func TestSignupFeatureOptInAndActualWire(t *testing.T) {
	f, c, work, device := newSignup(t)
	feature, err := passwordhttp.NewSignupFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	if work.calls != 0 || work.reads != 0 || f.rate.calls != 0 {
		t.Fatal("construction performed IO")
	}
	h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Signup", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	w := signupRecorder(h, signupRequest(f, device))
	if w.Code != 200 || len(doc.Operations()) != 1 {
		t.Fatalf("selected signup absent status=%d", w.Code)
	}
	parsed, err := openapi.ParseJSON(context.Background(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	node := parsed.Raw()
	for _, key := range []string{"paths", "/v1/password/signup", "post", "responses", "200", "content", "application/json", "schema"} {
		var ok bool
		node, ok = node.Lookup(key)
		if !ok {
			t.Fatal("actual response schema absent")
		}
	}
	instance, err := parse.JSON(context.Background(), bytes.NewReader(w.Body.Bytes()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	report, err := validate.SchemaInstance(context.Background(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
	if err != nil || !report.Valid() {
		t.Fatal("actual signup response rejected", err)
	}
	_, disabled, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Disabled", Version: "1"}, identityhttp.FeatureServices{})
	if err != nil || len(disabled.Operations()) != 0 {
		t.Fatal("disabled signup advertised")
	}
}
func signupBody(r *http.Request, body string) io.ReadCloser {
	r.ContentLength = int64(len(body))
	return io.NopCloser(strings.NewReader(body))
}
func signupRecorder(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestSignupRequiredVerificationPreservesKeyAndDestroysPassword(t *testing.T) {
	f, c, work, device := newSignup(t)
	r := signupRequest(f, device)
	// Address is raw owning-workflow input, not a transport normalization.
	r.Body = signupBody(r, `{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","email":"person@EXAMPLE.test","password":" synthetic-password ","callbackURL":""}`)
	h, err := passwordhttp.NewSignupHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := signupRecorder(h, r)
	key, _ := identity.NewIdempotencyKey([]byte("Original-Custody_001"))
	wantKey, _ := key.Digest([32]byte{7})
	gotKey, keyErr := work.last.IdempotencyKey.Digest([32]byte{7})
	if w.Code != 200 || work.calls != 1 || work.reads != 1 || f.rate.calls != 2 || !work.rawMatches || keyErr != nil || gotKey != wantKey || work.last.Email != work.input || work.last.Email != "person@EXAMPLE.test" || work.last.Password.Len() != 0 || work.last.Caller.CorrelationID == "" {
		t.Fatalf("signup custody failed status=%d reads=%d calls=%d rates=%d", w.Code, work.reads, work.calls, f.rate.calls)
	}
	var out passwordhttp.SignupResponse
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.VerificationRequired || out.CommitOutcome != "committed" || out.Recovery == nil {
		t.Fatal("neutral acknowledgement missing")
	}
	if len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("X-CSRF-Token") != "" {
		t.Fatal("verification acknowledgement delivered credentials")
	}
}
func TestSignupMissingComposition(t *testing.T) {
	if h, err := passwordhttp.NewSignupHandler(passwordhttp.SignupConfig{}); h != nil || err == nil {
		t.Fatal("unconfigured signup accepted")
	}
}

func TestSignupMiddlewareCannotReplaceCustodyOrMintCredentials(t *testing.T) {
	for _, stop := range []bool{false, true} {
		t.Run(map[bool]string{false: "unwind", true: "short-circuit"}[stop], func(t *testing.T) {
			f, c, work, device := newSignup(t)
			m := []identityhttp.MiddlewareDescriptor{{Owner: "identity/password", Middleware: identityhttp.Middleware{Name: "inject", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					r.Header.Set("Idempotency-Key", "replacement")
					if stop {
						w.Header()["set-cookie"] = []string{"forged=credential"}
						w.Header()["x-csrf-token"] = []string{"forged"}
						w.Header().Set("Trailer", "Set-Cookie")
						w.WriteHeader(202)
						return
					}
					next.ServeHTTP(w, r)
					w.Header()["set-cookie"] = []string{"forged=credential"}
					w.Header()["x-csrf-token"] = []string{"forged"}
					w.Header().Set(http.TrailerPrefix+"Set-Cookie", "forged=credential")
				})
			}}}}
			h, err := passwordhttp.NewSignupHandlerWithMiddleware(c, m)
			if err != nil {
				t.Fatal(err)
			}
			w := signupRecorder(h, signupRequest(f, device))
			want := 200
			if stop {
				want = 202
			}
			if w.Code != want || len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("middleware minted credentials")
			}
			if stop && work.calls != 0 {
				t.Fatal("short circuit executed signup")
			}
			if !stop {
				key, _ := identity.NewIdempotencyKey([]byte("Original-Custody_001"))
				want, _ := key.Digest([32]byte{8})
				got, err := work.last.IdempotencyKey.Digest([32]byte{8})
				if err != nil || got != want || work.last.Password.Len() != 0 {
					t.Fatal("middleware replaced input/key or leaked password")
				}
			}
			for name := range w.Header() {
				if strings.HasPrefix(name, http.TrailerPrefix) || strings.EqualFold(name, "Trailer") {
					t.Fatal("hook retained trailer")
				}
			}
		})
	}
}

func TestSignupAllTypedArmsRemainLossless(t *testing.T) {
	for _, tc := range []struct {
		kind  identity.AttributeKind
		value string
		want  int
	}{
		{identity.AttributeBool, "false", 200}, {identity.AttributeInt64, "9223372036854775807", 200}, {identity.AttributeInt64, "9223372036854775808", 400}, {identity.AttributeInt64, "1.5", 400}, {identity.AttributeTime, `"2026-10-10T20:00:00+02:00"`, 200}, {identity.AttributeTime, `"0001-01-01T00:00:00Z"`, 400}, {identity.AttributeStringList, "[]", 200}, {identity.AttributeStringList, "null", 400},
	} {
		t.Run(string(tc.kind)+tc.value, func(t *testing.T) {
			f, c, work, device := newSignup(t)
			c.FieldSchema.Fields[0].Kind = tc.kind
			if tc.kind == identity.AttributeStringList {
				c.FieldSchema.Fields[0].Cardinality = identity.CardinalityList
			}
			r := signupRequest(f, device)
			r.Body = signupBody(r, `{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","email":"person@EXAMPLE.test","password":" synthetic-password ","callbackURL":"","allowedFields":[{"name":"name","kind":"`+string(tc.kind)+`","value":`+tc.value+`}]}`)
			w := serveSignup(t, c, r)
			if w.Code != tc.want {
				t.Fatalf("typed arm status=%d", w.Code)
			}
			if tc.want == 200 {
				v := work.last.AllowedFields[0].Value
				switch tc.kind {
				case identity.AttributeBool:
					if v.Scalar.Bool {
						t.Fatal("false lost")
					}
				case identity.AttributeInt64:
					if v.Scalar.Int64 != 9223372036854775807 {
						t.Fatal("integer rounded")
					}
				case identity.AttributeStringList:
					if v.List == nil || len(v.List) != 0 {
						t.Fatal("explicit empty list lost")
					}
				case identity.AttributeTime:
					if v.Scalar.Time.UTC() != time.Date(2026, 10, 10, 18, 0, 0, 0, time.UTC) {
						t.Fatal("time changed")
					}
				}
			}
		})
	}
}

func TestSignupNativeKeyConflictPreservesClassification(t *testing.T) {
	f, c, work, device := newSignup(t)
	work.result = password.SignupResult{}
	work.err = identity.ConflictError{}
	w := serveSignup(t, c, signupRequest(f, device))
	var out passwordhttp.SignupResponse
	if w.Code != 409 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Error != "conflict" || out.Recovery != nil || out.CommandID != "" || out.CommitOutcome != "unknown" || work.calls != 1 || work.last.Password.Len() != 0 {
		t.Fatal("native key conflict became outage or invented history")
	}
}

func TestSignupBothRateOutagesPreserveClassification(t *testing.T) {
	for _, identifier := range []bool{false, true} {
		t.Run(map[bool]string{false: "IP", true: "identifier"}[identifier], func(t *testing.T) {
			f, c, work, device := newSignup(t)
			if identifier {
				work.failIdentifier = true
			} else {
				f.rate.fail = true
			}
			w := serveSignup(t, c, signupRequest(f, device))
			var out passwordhttp.SignupResponse
			if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Error != "rate_limiter_unavailable" || out.CommitOutcome != "none" || work.calls != 0 {
				t.Fatal("shared rate outage classification lost")
			}
			want := 1
			if identifier {
				want = 2
			}
			if f.rate.calls != want {
				t.Fatal("outage did not reach selected bucket")
			}
		})
	}
}
