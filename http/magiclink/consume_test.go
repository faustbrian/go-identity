package magiclinkhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	magiclinkhttp "github.com/faustbrian/go-identity/http/magiclink"
	"github.com/faustbrian/go-identity/magiclink"
	"github.com/faustbrian/go-identity/session"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
)

// Native consuming persistence and atomic rate storage are explicit test seams;
// actual parsing, network/origin, rate composition and credential custody run.
type atomicRate struct {
	ratelimit.StrictBackend
	calls int
	fail  bool
}

func (*atomicRate) Name() string { return "magic-consume-test" }
func (s *atomicRate) AdmitAtomicStrict(ctx context.Context, r ratelimit.AtomicBatchRequest) (ratelimit.AtomicBatchDecision, error) {
	s.calls++
	if s.fail {
		return ratelimit.AtomicBatchDecision{}, ratelimit.UnknownOutcome(nil)
	}
	out := ratelimit.AtomicBatchDecision{CommandID: r.CommandID, Allowed: true}
	for _, v := range r.Requests {
		out.Decisions = append(out.Decisions, ratelimit.Decision{Allowed: true, Limit: v.Policy.Limit(), Remaining: v.Policy.Limit() - 1, Reset: v.Now.Add(v.Policy.Period()), Reason: ratelimit.ReasonAllowed})
	}
	return out, nil
}

type consumeWork struct {
	rate         *atomicRate
	calls, reads int
	last         magiclink.ConsumeRequest
	result       func(magiclink.ConsumeRequest) (magiclink.ConsumeResult, error)
	sourceError  error
}

func (s *consumeWork) ConsumeRateSource(ctx context.Context, r magiclink.ConsumeRequest) (identity.UserID, string, time.Duration, error) {
	s.reads++
	if s.rate.calls != 1 || r.Validate() != nil {
		panic("unadmitted source")
	}
	if s.sourceError != nil {
		return "", "", 0, s.sourceError
	}
	return "user-a", "grant-a", time.Minute, nil
}
func (s *consumeWork) Consume(ctx context.Context, r magiclink.ConsumeRequest) (magiclink.ConsumeResult, error) {
	s.calls++
	s.last = r
	if s.rate.calls != 2 || r.Validate() != nil {
		panic("unadmitted consume")
	}
	return s.result(r)
}
func consumeFixture(t *testing.T) (magiclinkhttp.ConsumeConfig, *consumeWork, string) {
	t.Helper()
	base, _ := fixture(t)
	now := time.Unix(1800000000, 0)
	backend := &atomicRate{}
	rate, e := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: backend, Namespace: "magic-consume", Key: [32]byte{1}, Now: func() time.Time { return now }, MaximumDuration: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { rate.Close() })
	cookie, e := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	if e != nil {
		t.Fatal(e)
	}
	w := &consumeWork{rate: backend}
	c := magiclinkhttp.ConsumeConfig{Network: base.Network, Service: w, Rate: rate, Origin: base.Origin, CallbackURL: base.CallbackURL, SessionCookie: cookie, Device: base.Device, ActorID: base.ActorID, PolicyRevision: base.PolicyRevision, Audience: "identity", Now: func() time.Time { return now }, MaximumDuration: time.Second}
	signer, _ := capability.NewHMACSHA256Signer("test", []byte(strings.Repeat("x", 32)))
	wire, e := capability.Issue(context.Background(), capability.Payload{Version: 1, ID: "grant-a", Issuer: "https://issuer.test", Tenant: "tenant-a", Subject: "user-a", Audiences: []string{"identity"}, Resource: "identity.magiclink/user-a", Operation: "identity.magic-link.consume", IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), MaxUses: 1}, signer, capability.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	body, e := json.Marshal(map[string]string{"commandID": "AQEBAQEBAQEBAQEBAQEBAQ", "preAuthID": "AgICAgICAgICAgICAgICAg", "callbackURL": c.CallbackURL, "token": wire})
	if e != nil {
		t.Fatal(e)
	}
	return c, w, string(body)
}
func consumeRequest(body string) *http.Request {
	r := request(body)
	r.URL.Path = "/v1/magic-link/consume"
	r.RequestURI = r.URL.Path
	r.Header.Del("Idempotency-Key")
	return r
}

func TestConsumeUsesSelectedNativeProofLimitsBeforeSource(t *testing.T) {
	for _, count := range []int{0, 17, 18} {
		c, work, body := consumeFixture(t)
		var fields map[string]string
		if err := json.Unmarshal([]byte(body), &fields); err != nil {
			t.Fatal(err)
		}
		parsed, err := capability.Parse(fields["token"], capability.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		payload := parsed.Payload
		payload.Caveats = make(map[string]string)
		for i := range 18 {
			payload.Caveats[strings.Repeat("x", i+1)] = "bounded"
		}
		limits := capability.DefaultLimits()
		limits.MaxCaveats = 18
		signer, _ := capability.NewHMACSHA256Signer("test", []byte(strings.Repeat("x", 32)))
		fields["token"], err = capability.Issue(context.Background(), payload, signer, limits)
		if err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			c.ProofLimits = capability.DefaultLimits()
			c.ProofLimits.MaxCaveats = count
		}
		work.result = func(magiclink.ConsumeRequest) (magiclink.ConsumeResult, error) {
			return magiclink.ConsumeResult{}, identity.UnavailableError{}
		}
		handler, err := magiclinkhttp.NewConsumeHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		wire, _ := json.Marshal(fields)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, consumeRequest(string(wire)))
		if count == 18 {
			if work.reads != 1 || work.calls != 1 || response.Code != 503 {
				t.Fatal("selected profile did not reach decisive native owner", "source", work.reads, "native", work.calls, "status", response.Code)
			}
		} else if work.reads != 0 || work.calls != 0 || response.Code != 400 {
			t.Fatal("default or narrower profile was silently expanded")
		}
	}
}
func consumingIssuance(t *testing.T, c magiclinkhttp.ConsumeConfig, r magiclink.ConsumeRequest) magiclink.ConsumeResult {
	t.Helper()
	now := c.Now()
	token, _ := session.NewToken(32)
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	digest, _ := token.Digest(key, string(r.TenantID))
	b := func(s string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: s, Version: 1} }
	authority, e := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: b("global"), Tenant: b("tenant"), User: b("user"), Identifier: b("identifier"), Credential: b("credential"), SessionFamily: b("family"), Session: b("session"), Authorization: b("authorization")})
	if e != nil {
		t.Fatal(e)
	}
	remember, e := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if e != nil {
		t.Fatal(e)
	}
	meta, e := session.NewMagicLinkAuthentication(session.MagicLinkAuthenticationSpec{CommandID: r.CommandID, RequestCommandID: "AwMDAwMDAwMDAwMDAwMDAw", CapabilityID: "grant-a", IdentifierID: "AQEBAQEBAQEBAQEBAQEBAQ", IdentifierVersion: 1, VerificationVersion: 1, AuthenticatedAt: now, ValidUntil: now.Add(time.Minute)})
	if e != nil {
		t.Fatal(e)
	}
	csrf, _ := session.NewCSRFToken()
	csrfKey, _ := session.NewCSRFKey(1, make([]byte, 32))
	state, e := csrf.Digest(csrfKey, session.CSRFBinding{TenantID: r.TenantID, SessionID: "session-a", SessionVersion: 1})
	if e != nil {
		t.Fatal(e)
	}
	record, e := session.NewSessionWithMagicLinkAndCSRF(session.SessionSpec{SessionID: "session-a", FamilyID: "family-a", TenantID: r.TenantID, UserID: "user-a", Audience: c.Audience, Version: 1, FamilyVersion: 1, Remember: remember, Authority: authority, Lookup: digest, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationMagicLink}, IssuedAt: now, LastActivityAt: now}, meta, state)
	if e != nil {
		t.Fatal(e)
	}
	cookie, e := c.SessionCookie.Attributes(remember, now, now.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	return magiclink.ConsumeResult{Outcome: identity.CommitOutcomeCommitted, State: auth.SignInStateAuthenticated, Session: session.IssueResult{CommandID: r.CommandID, CommitOutcome: identity.CommitOutcomeCommitted, Session: record, Token: token, Cookie: cookie}, CSRFToken: csrf}
}
func TestConsumeFreshCommitDeliversOnlyOwnedCredentials(t *testing.T) {
	c, w, body := consumeFixture(t)
	var result magiclink.ConsumeResult
	w.result = func(r magiclink.ConsumeRequest) (magiclink.ConsumeResult, error) {
		result = consumingIssuance(t, c, r)
		return result, nil
	}
	h, e := magiclinkhttp.NewConsumeHandler(c)
	if e != nil {
		t.Fatal(e)
	}
	out := httptest.NewRecorder()
	h.ServeHTTP(out, consumeRequest(body))
	if out.Code != 200 || len(out.Result().Cookies()) != 1 {
		t.Fatal("fresh committed delivery withheld", out.Code, out.Body.String())
	}
	cookie := out.Result().Cookies()[0]
	if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || cookie.MaxAge != 0 || cookie.Name != "__Host-identity_session" {
		t.Fatal("unsafe cookie")
	}
	if _, e = session.ParseToken(cookie.Value); e != nil {
		t.Fatal("invalid bearer")
	}
	if _, e = session.ParseCSRFToken(out.Header().Get("X-CSRF-Token")); e != nil {
		t.Fatal("missing synchronizer")
	}
	if _, e = result.Session.Token.Reveal(); e == nil {
		t.Fatal("bearer revealed again")
	}
	if w.last.Token.ValidateBounds(32, 4096) == nil {
		t.Fatal("ingress proof custody retained")
	}
	if strings.Contains(out.Body.String(), cookie.Value) || strings.Contains(out.Body.String(), "user-a") {
		t.Fatal("credential or subject leaked into JSON")
	}
}

func TestConsumeMFAChallengeNeverAuthenticates(t *testing.T) {
	for _, mode := range []string{"fresh", "injected-header", "informational", "error-status", "disabled", "replay", "expired", "unknown", "error", "mixed-session", "delayed"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, body := consumeFixture(t)
			now := c.Now()
			c.Now = func() time.Time { return now }
			c.MFAContinuation = mode != "disabled"
			var proof capability.Proof
			var expectedWire string
			owner.result = func(r magiclink.ConsumeRequest) (magiclink.ConsumeResult, error) {
				var err error
				signer, _ := capability.NewHMACSHA256Signer("test", []byte(strings.Repeat("x", 32)))
				expectedWire, err = capability.Issue(context.Background(), capability.Payload{Version: 1, ID: "AwMDAwMDAwMDAwMDAwMDAw", Issuer: "https://issuer.test", Tenant: "tenant-a", Subject: "user-a", Audiences: []string{"identity"}, Resource: "identity.mfa/user-a", Operation: "identity.mfa.complete", IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), MaxUses: 1}, signer, capability.DefaultLimits())
				if err != nil {
					t.Fatal(err)
				}
				proof, err = capability.ParseProof(expectedWire, capability.DefaultLimits())
				if err != nil {
					t.Fatal(err)
				}
				out := magiclink.ConsumeResult{Outcome: identity.CommitOutcomeCommitted, State: auth.SignInStateChallengeRequired,
					Session:   session.IssueResult{CommandID: r.CommandID, CommitOutcome: identity.CommitOutcomeCommitted},
					Challenge: magiclink.MFAChallengeResult{ID: "AwMDAwMDAwMDAwMDAwMDAw", Proof: proof, Method: "totp", ExpiresAt: now.Add(time.Minute)}}
				switch mode {
				case "replay":
					out.Session.Replayed = true
				case "expired":
					out.Challenge.ExpiresAt = now
				case "unknown":
					out.Outcome, out.Session.CommitOutcome = identity.CommitOutcomeUnknown, identity.CommitOutcomeUnknown
				case "error":
					return out, errors.New("dependency failure")
				case "mixed-session":
					out.Session = consumingIssuance(t, c, r).Session
				}
				return out, nil
			}
			var middleware []identityhttp.MiddlewareDescriptor
			var leaked bool
			if mode == "error-status" {
				middleware = []identityhttp.MiddlewareDescriptor{{Owner: "identity/magiclink", Middleware: identityhttp.Middleware{Name: "failed-response", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { next.ServeHTTP(errorStatusConsumeWriter{w}, r) })
				}}}}
			}
			if mode == "injected-header" || mode == "informational" {
				middleware = []identityhttp.MiddlewareDescriptor{{Owner: "identity/magiclink", Middleware: identityhttp.Middleware{Name: "credential-boundary", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("X-MFA-Token", "forged-before")
						if mode == "informational" {
							next.ServeHTTP(informationalConsumeWriter{ResponseWriter: w, leaked: &leaked}, r)
						} else {
							next.ServeHTTP(w, r)
						}
						w.Header().Set("X-MFA-Token", "forged-after")
					})
				}}}}
			}
			if mode == "delayed" {
				middleware = []identityhttp.MiddlewareDescriptor{{Owner: "identity/magiclink", Middleware: identityhttp.Middleware{Name: "delay", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						next.ServeHTTP(delayedConsumeWriter{ResponseWriter: w, advance: func() { now = now.Add(time.Minute) }}, r)
					})
				}}}}
			}
			h, err := magiclinkhttp.NewConsumeHandlerWithMiddleware(c, middleware)
			if err != nil {
				t.Fatal(err)
			}
			out := httptest.NewRecorder()
			h.ServeHTTP(out, consumeRequest(body))
			var response map[string]any
			if json.Unmarshal(out.Body.Bytes(), &response) != nil || response["signedIn"] != false || len(out.Result().Cookies()) != 0 || out.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("challenge authenticated or delivered session custody")
			}
			wire := out.Header().Get("X-MFA-Token")
			if mode == "fresh" || mode == "injected-header" || mode == "informational" {
				if (out.Code != http.StatusOK && mode != "informational") || leaked || wire != expectedWire || response["challengeID"] != "AwMDAwMDAwMDAwMDAwMDAw" || response["challengeRequired"] != true || strings.Contains(out.Body.String(), wire) {
					t.Fatal("fresh challenge not delivered through owned header", out.Code)
				}
			} else if out.Code == http.StatusOK || wire != "" || response["challengeID"] != nil || response["challengeRequired"] == true {
				t.Fatal("non-deliverable challenge leaked", mode, out.Code)
			}
			if proof.ValidateBounds(32, 4096) == nil {
				t.Fatal("child proof custody retained after HTTP call")
			}
		})
	}
}

type errorStatusConsumeWriter struct{ http.ResponseWriter }

func (w errorStatusConsumeWriter) WriteHeader(status int) {
	if status == http.StatusOK {
		status = http.StatusServiceUnavailable
	}
	w.ResponseWriter.WriteHeader(status)
}

func TestConsumeFailedResponseCommitCannotDeliverSession(t *testing.T) {
	c, owner, body := consumeFixture(t)
	owner.result = func(r magiclink.ConsumeRequest) (magiclink.ConsumeResult, error) {
		return consumingIssuance(t, c, r), nil
	}
	h, err := magiclinkhttp.NewConsumeHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{{Owner: "identity/magiclink", Middleware: identityhttp.Middleware{Name: "failed-response", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { next.ServeHTTP(errorStatusConsumeWriter{w}, r) })
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	out := httptest.NewRecorder()
	h.ServeHTTP(out, consumeRequest(body))
	var result magiclinkhttp.ConsumeResponse
	if json.Unmarshal(out.Body.Bytes(), &result) != nil || result.SignedIn || result.SessionID != "" || result.CommitOutcome != "committed" || out.Code != http.StatusServiceUnavailable || len(out.Result().Cookies()) != 0 || out.Header().Get("X-CSRF-Token") != "" || out.Header().Get("X-MFA-Token") != "" {
		t.Fatal("failed response commitment delivered credentials or lost durable outcome")
	}
}
func TestConsumeWithholdsEveryNonDeliverableOutcome(t *testing.T) {
	for _, mode := range []string{"replay", "unknown", "committed-error", "wrong-command", "foreign-user", "cookie-value", "expired", "panic", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			c, w, body := consumeFixture(t)
			now := time.Unix(1800000000, 0)
			c.Now = func() time.Time { return now }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			w.result = func(r magiclink.ConsumeRequest) (magiclink.ConsumeResult, error) {
				out := consumingIssuance(t, c, r)
				switch mode {
				case "replay":
					out.Session.Replayed = true
				case "unknown":
					out.Outcome = identity.CommitOutcomeUnknown
					out.Session.CommitOutcome = identity.CommitOutcomeUnknown
				case "committed-error":
					return out, errors.New("private diagnostic")
				case "wrong-command":
					out.Session.CommandID = "AwMDAwMDAwMDAwMDAwMDAw"
				case "foreign-user":
					spec, _ := out.Session.Session.Bindings()
					spec.UserID = "foreign"
					out.Session.Session, _ = session.NewSessionWithMagicLinkAndCSRF(spec, out.Session.Session.MagicLinkAuthentication(), out.Session.Session.CSRFState())
				case "cookie-value":
					out.Session.Cookie.Value = "private"
				case "expired":
					now = time.Unix(1800000060, 0)
				case "panic":
					panic("private diagnostic")
				case "cancel":
					cancel()
				}
				return out, nil
			}
			h, e := magiclinkhttp.NewConsumeHandler(c)
			if e != nil {
				t.Fatal(e)
			}
			out := httptest.NewRecorder()
			h.ServeHTTP(out, consumeRequest(body).WithContext(ctx))
			if out.Code == 200 || len(out.Result().Cookies()) != 0 || out.Header().Get("X-CSRF-Token") != "" || strings.Contains(out.Body.String(), "private") {
				t.Fatal("non-deliverable credentials escaped", out.Code, out.Body.String())
			}
			if mode == "committed-error" && !strings.Contains(out.Body.String(), `"commitOutcome":"committed"`) {
				t.Fatal("known commit discarded")
			}
		})
	}
}

func TestConsumeSupersededClassificationWithholdsCredentials(t *testing.T) {
	for _, source := range []bool{false, true} {
		t.Run(map[bool]string{false: "consume", true: "source"}[source], func(t *testing.T) {
			c, work, body := consumeFixture(t)
			if source {
				work.sourceError = magiclink.SupersededError{}
			}
			work.result = func(magiclink.ConsumeRequest) (magiclink.ConsumeResult, error) {
				return magiclink.ConsumeResult{}, magiclink.SupersededError{}
			}
			h, err := magiclinkhttp.NewConsumeHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			h.ServeHTTP(response, consumeRequest(body))
			var out magiclinkhttp.ConsumeResponse
			if json.Unmarshal(response.Body.Bytes(), &out) != nil || response.Code != http.StatusConflict || out.Error != "superseded" || out.SignedIn || out.SessionID != "" || len(response.Result().Cookies()) != 0 || response.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("superseded classification or custody escaped", response.Code, response.Body.String())
			}
			if source && work.calls != 0 {
				t.Fatal("superseded source reached consumption")
			}
		})
	}
}

func TestConsumeFeatureSelectedRoute(t *testing.T) {
	c, w, body := consumeFixture(t)
	w.result = func(r magiclink.ConsumeRequest) (magiclink.ConsumeResult, error) {
		return consumingIssuance(t, c, r), nil
	}
	feature, e := magiclinkhttp.NewFeature(magiclinkhttp.FeatureConfig{Consume: &c})
	if e != nil {
		t.Fatal(e)
	}
	h, doc, e := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Consume", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if e != nil || len(doc.Operations()) != 1 {
		t.Fatal("selected consuming composition", e)
	}
	out := httptest.NewRecorder()
	h.ServeHTTP(out, consumeRequest(body))
	if out.Code != 200 {
		t.Fatal("selected consume", out.Code, out.Body.String())
	}
	if strings.Contains(string(doc.JSON()), "/v1/magic-link/request") {
		t.Fatal("unselected request advertised")
	}
	parsed, e := openapi.ParseJSON(context.Background(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	schema := parsed.Raw()
	for _, key := range []string{"paths", "/v1/magic-link/consume", "post", "responses", "200", "content", "application/json", "schema"} {
		var ok bool
		schema, ok = schema.Lookup(key)
		if !ok {
			t.Fatal("consuming schema absent")
		}
	}
	instance, e := parse.JSON(context.Background(), bytes.NewReader(out.Body.Bytes()), parse.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	report, e := validate.SchemaInstance(context.Background(), parsed, schema, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
	if e != nil || !report.Valid() {
		t.Fatal("actual consuming response contradicts wire schema", e)
	}
	r := consumeRequest(body)
	r.URL.Path = "/v1/magic-link/request"
	r.RequestURI = r.URL.Path
	out = httptest.NewRecorder()
	h.ServeHTTP(out, r)
	if out.Code != 404 || w.calls != 1 {
		t.Fatal("unselected operation exposed")
	}
}

func TestMagicLinkCombinedSelectionAndCredentialCustody(t *testing.T) {
	c, w, body := consumeFixture(t)
	requestConfig, _ := fixture(t)
	w.result = func(r magiclink.ConsumeRequest) (magiclink.ConsumeResult, error) {
		return consumingIssuance(t, c, r), nil
	}
	feature, e := magiclinkhttp.NewFeature(magiclinkhttp.FeatureConfig{Request: &requestConfig, Consume: &c})
	if e != nil {
		t.Fatal(e)
	}
	_, doc, e := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Magic", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if e != nil || len(doc.Operations()) != 2 {
		t.Fatal("combined selection or shared original-flow schema", e)
	}
	h, e := magiclinkhttp.NewConsumeHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{{Owner: "identity/magiclink", Middleware: identityhttp.Middleware{Name: "credential-forgery", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
			out.Header()["set-cookie"] = []string{"private"}
			out.Header().Set("X-CSRF-Token", "private")
			out.Header().Set("Location", "https://foreign.test")
			out.Header().Set("Trailer", "Authorization")
			next.ServeHTTP(out, r)
			out.Header().Set("Set-Cookie", "private")
			out.Header()[http.TrailerPrefix+"Authorization"] = []string{"private"}
		})
	}}}})
	if e != nil {
		t.Fatal(e)
	}
	out := httptest.NewRecorder()
	h.ServeHTTP(out, consumeRequest(body))
	if out.Code != 200 || len(out.Result().Cookies()) != 1 || out.Result().Cookies()[0].Value == "private" || out.Header().Get("X-CSRF-Token") == "private" || out.Header().Get("Location") != "" || out.Header().Get("Trailer") != "" || len(out.Result().Trailer) != 0 || w.calls != 1 {
		t.Fatal("middleware forged or replaced native tuple")
	}
}

func FuzzConsumeBoundedTransport(f *testing.F) {
	f.Add(`{}`)
	f.Add(`{"token":"malformed"}`)
	f.Add(`{"token":"duplicate","token":"duplicate"}`)
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 8192 {
			return
		}
		c, w, _ := consumeFixture(t)
		w.result = func(magiclink.ConsumeRequest) (magiclink.ConsumeResult, error) {
			return magiclink.ConsumeResult{}, errors.New("native denial")
		}
		h, e := magiclinkhttp.NewConsumeHandler(c)
		if e != nil {
			t.Fatal(e)
		}
		out := httptest.NewRecorder()
		h.ServeHTTP(out, consumeRequest(raw))
		if out.Body.Len() > 4096 || w.calls > 1 || len(out.Result().Cookies()) != 0 || out.Header().Get("X-CSRF-Token") != "" || out.Header().Get("Location") != "" {
			t.Fatal("unbounded or unauthorized consuming output")
		}
	})
}

func TestConsumeTransportDenialsNeverEnterOwner(t *testing.T) {
	for _, mode := range []string{"unknown-field", "duplicate-json", "retry-key", "query", "missing-cookie", "duplicate-cookie", "origin", "callback", "scanner-get", "malformed-proof", "rate-outage"} {
		t.Run(mode, func(t *testing.T) {
			c, w, body := consumeFixture(t)
			w.result = func(magiclink.ConsumeRequest) (magiclink.ConsumeResult, error) {
				panic("denied request entered consume")
			}
			want := 400
			switch mode {
			case "unknown-field":
				body = strings.TrimSuffix(body, "}") + `,"userID":"foreign"}`
			case "duplicate-json":
				body = strings.TrimSuffix(body, "}") + `,"token":"foreign"}`
			case "callback":
				body = strings.Replace(body, c.CallbackURL, "https://foreign.test", 1)
			case "malformed-proof":
				var m map[string]string
				_ = json.Unmarshal([]byte(body), &m)
				m["token"] = "malformed"
				b, _ := json.Marshal(m)
				body = string(b)
			}
			r := consumeRequest(body)
			switch mode {
			case "retry-key":
				r.Header.Set("Idempotency-Key", "Original-Custody_001")
			case "query":
				r.URL.RawQuery = "token=foreign"
				r.RequestURI = r.URL.RequestURI()
			case "missing-cookie":
				r.Header.Del("Cookie")
			case "duplicate-cookie":
				r.Header.Add("Cookie", r.Header.Get("Cookie"))
			case "origin":
				r.Header.Set("Origin", "https://foreign.test")
				want = 403
			case "scanner-get":
				r.Method = "GET"
				want = 405
			case "rate-outage":
				w.rate.fail = true
				want = 503
			}
			h, e := magiclinkhttp.NewConsumeHandler(c)
			if e != nil {
				t.Fatal(e)
			}
			out := httptest.NewRecorder()
			h.ServeHTTP(out, r)
			if out.Code != want || w.calls != 0 || len(out.Result().Cookies()) != 0 || out.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("denial escaped transport", out.Code, out.Body.String())
			}
			if mode == "malformed-proof" && (w.rate.calls != 1 || w.reads != 0) {
				t.Fatal("proof parsing bypassed trusted IP budget")
			}
		})
	}
}

type delayedConsumeWriter struct {
	http.ResponseWriter
	advance func()
}

type informationalConsumeWriter struct {
	http.ResponseWriter
	leaked *bool
}

func (w informationalConsumeWriter) WriteHeader(status int) {
	if status == http.StatusOK {
		w.ResponseWriter.WriteHeader(http.StatusEarlyHints)
		*w.leaked = w.ResponseWriter.Header().Get("Set-Cookie") != "" || w.ResponseWriter.Header().Get("X-CSRF-Token") != "" || w.ResponseWriter.Header().Get("X-MFA-Token") != ""
	}
	w.ResponseWriter.WriteHeader(status)
}

func TestConsumeInformationalResponseCannotDeliverCredentials(t *testing.T) {
	c, owner, body := consumeFixture(t)
	owner.result = func(r magiclink.ConsumeRequest) (magiclink.ConsumeResult, error) {
		return consumingIssuance(t, c, r), nil
	}
	var leaked bool
	h, err := magiclinkhttp.NewConsumeHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{{Owner: "identity/magiclink", Middleware: identityhttp.Middleware{Name: "early-hints", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(informationalConsumeWriter{ResponseWriter: w, leaked: &leaked}, r)
		})
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	h.ServeHTTP(httptest.NewRecorder(), consumeRequest(body))
	if leaked {
		t.Fatal("informational response exposed fresh credential tuple before commitment")
	}
}

func (w delayedConsumeWriter) WriteHeader(status int) {
	w.advance()
	w.ResponseWriter.WriteHeader(status)
}

func TestConsumeExpiryAtResponseCommitWithholdsCredentials(t *testing.T) {
	c, owner, body := consumeFixture(t)
	now := c.Now()
	c.Now = func() time.Time { return now }
	owner.result = func(r magiclink.ConsumeRequest) (magiclink.ConsumeResult, error) {
		return consumingIssuance(t, c, r), nil
	}
	h, err := magiclinkhttp.NewConsumeHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{{Owner: "identity/magiclink", Middleware: identityhttp.Middleware{Name: "delayed-commit", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(delayedConsumeWriter{ResponseWriter: w, advance: func() { now = now.Add(time.Minute) }}, r)
		})
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	out := httptest.NewRecorder()
	h.ServeHTTP(out, consumeRequest(body))
	var response magiclinkhttp.ConsumeResponse
	if json.Unmarshal(out.Body.Bytes(), &response) != nil || out.Code != 503 || response.SignedIn || response.CommitOutcome != "committed" || response.SessionID != "" || len(out.Result().Cookies()) != 0 || out.Header().Get("X-CSRF-Token") != "" || owner.calls != 1 {
		t.Fatal("expired response commitment delivered credentials or lost known commit", out.Code)
	}
}
