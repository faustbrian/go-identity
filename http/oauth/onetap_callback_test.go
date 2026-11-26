package oauthhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	oauthhttp "github.com/faustbrian/go-identity/http/oauth"
	"github.com/faustbrian/go-identity/session"
)

const oneTapCallbackHTTPBody = `{"flowId":"AQEBAQEBAQEBAQEBAQEBAQ","credential":"opaque-google-credential","g_csrf_token":"original.google_csrf!"}`

// This boundary double proves transport admission and delivery, not Google's
// verification or native one-use admission, which have separate native tests.
type oneTapCallbackHTTPProbe struct {
	calls   int
	last    oauthhttp.OneTapCallbackHTTPInput
	bounded bool
	result  oauthhttp.OneTapCallbackHTTPResult
	err     error
	before  func()
}

func (p *oneTapCallbackHTTPProbe) complete(ctx context.Context, in oauthhttp.OneTapCallbackHTTPInput) (oauthhttp.OneTapCallbackHTTPResult, error) {
	p.calls++
	p.last = in
	_, p.bounded = ctx.Deadline()
	if p.before != nil {
		p.before()
	}
	return p.result, p.err
}

func oneTapCallbackHTTPFixture(t *testing.T) (oauthhttp.OneTapCallbackConfig, *oneTapCallbackHTTPProbe, *signinStartRate, *http.Request, session.BrowserDevice) {
	t.Helper()
	start, _, rate, cookie, device := signinStartFixture(t)
	authentication, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	csrf, _ := session.NewCSRFCookiePolicy(session.CookieConfig{Name: "__Host-identity_csrf", SameSite: http.SameSiteLaxMode})
	profile := start.Provider
	profile.ID, profile.Issuer, profile.ClientID = "google", "https://accounts.google.com", "trusted-google-client"
	profile.AuthorizationEndpoint, profile.TokenEndpoint = "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token"
	profile.GoogleAccounts = true
	p := &oneTapCallbackHTTPProbe{err: errors.New("private native detail")}
	c := oauthhttp.OneTapCallbackConfig{Network: start.Network, Provider: profile, Complete: p.complete, Rate: start.Rate, Cookie: authentication, FlowCookie: start.FlowCookie, Device: start.Device, CSRFCookie: csrf, Origin: start.Origin, TenantID: "tenant", Audience: "service-a", Now: start.Now, MaximumDuration: time.Second}
	r := httptest.NewRequest(http.MethodPost, "https://app.example/v1/oauth/onetap-callback", strings.NewReader(oneTapCallbackHTTPBody))
	r.RequestURI = r.URL.RequestURI()
	r.RemoteAddr = "[::ffff:192.0.2.1]:1234"
	r.Header.Set("Origin", "https://app.example")
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
	r.AddCookie(cookie)
	r.AddCookie(&http.Cookie{Name: "g_csrf_token", Value: "original.google_csrf!"})
	return c, p, rate, r, device
}

func oneTapCallbackHTTPServe(t *testing.T, c oauthhttp.OneTapCallbackConfig, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	h, err := oauthhttp.NewOneTapCallbackHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestOneTapCallbackHTTPBindsOriginalBrowserAndClearsBorrowedCredential(t *testing.T) {
	c, p, rate, r, device := oneTapCallbackHTTPFixture(t)
	p.before = func() {
		if string(p.last.Callback.Credential.IDToken) != "opaque-google-credential" {
			t.Fatal("credential was changed or prematurely destroyed")
		}
	}
	w := oneTapCallbackHTTPServe(t, c, r)
	if w.Code != 503 || p.calls != 1 || !p.bounded || len(rate.requests) != 1 {
		t.Fatal("callback failed bounded native admission", w.Code)
	}
	if p.last.FlowID != "AQEBAQEBAQEBAQEBAQEBAQ" || p.last.FlowCookie.Token() != strings.Repeat("A", 43) || p.last.Device != device.DeviceID() || p.last.Network != netip.MustParseAddr("192.0.2.1") || p.last.Callback.Origin != string(c.Origin) || p.last.Callback.Redirect != "" {
		t.Fatal("callback replaced trusted browser scope")
	}
	if len(p.last.Callback.CSRFCookies) != 1 || p.last.Callback.CSRFCookies[0] != "original.google_csrf!" || len(p.last.Callback.CSRFBody) != 1 || p.last.Callback.CSRFBody[0] != "original.google_csrf!" {
		t.Fatal("Google double-submit evidence changed")
	}
	for _, b := range p.last.Callback.Credential.IDToken {
		if b != 0 {
			t.Fatal("borrowed callback credential survived handler")
		}
	}
	requireNoSigninCredentials(t, w)
	if strings.Contains(w.Body.String(), "opaque-google-credential") || strings.Contains(w.Body.String(), "private native detail") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("private callback diagnostics escaped")
	}
}

func TestOneTapCallbackHTTPRejectsBeforeNativeOrRate(t *testing.T) {
	cases := []struct {
		name  string
		alter func(*http.Request)
	}{
		{"key", func(r *http.Request) { r.Header.Set("Idempotency-Key", "replacement") }},
		{"csrf-header", func(r *http.Request) { r.Header.Set("X-CSRF-Token", "replacement") }},
		{"authorization", func(r *http.Request) { r.Header.Set("Authorization", "Bearer replacement") }},
		{"query", func(r *http.Request) { r.URL.RawQuery = "credential=replacement"; r.RequestURI = r.URL.RequestURI() }},
		{"missing-origin", func(r *http.Request) { r.Header.Del("Origin") }},
		{"foreign-origin", func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example") }},
		{"duplicate-origin", func(r *http.Request) { r.Header["origin"] = []string{"https://app.example"} }},
		{"foreign-host", func(r *http.Request) { r.Host = "foreign.example" }},
		{"http", func(r *http.Request) { r.TLS = nil; r.URL.Scheme = "http" }},
		{"peer", func(r *http.Request) { r.RemoteAddr = "not-a-peer" }},
		{"no-cookie", func(r *http.Request) { r.Header.Del("Cookie") }},
		{"duplicate-flow", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
		}},
		{"duplicate-device", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "__Host-identity_device", Value: "replacement"}) }},
		{"duplicate-google", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "g_csrf_token", Value: "original.google_csrf!"}) }},
		{"google-mismatch", func(r *http.Request) {
			r.Header.Set("Cookie", strings.ReplaceAll(r.Header.Get("Cookie"), "original.google_csrf!", "other"))
		}},
		{"trailer", func(r *http.Request) { r.Trailer = http.Header{"Credential": {"replacement"}} }},
		{"method", func(r *http.Request) { r.Method = http.MethodGet }},
		{"path", func(r *http.Request) { r.URL.Path = "/v1/oauth/onetap-callback/"; r.RequestURI = r.URL.RequestURI() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, p, rate, r, _ := oneTapCallbackHTTPFixture(t)
			tc.alter(r)
			w := oneTapCallbackHTTPServe(t, c, r)
			if w.Code < 400 || p.calls != 0 || len(rate.requests) != 0 {
				t.Fatal("invalid browser reached native/rate", w.Code)
			}
			requireNoSigninCredentials(t, w)
		})
	}
	for _, body := range []string{`{}`, `null`, `{"flowId":"AQEBAQEBAQEBAQEBAQEBAQ","credential":"x","g_csrf_token":"original.google_csrf!","client_id":"foreign"}`, strings.Replace(oneTapCallbackHTTPBody, `"flowId"`, `"flowID"`, 1), strings.Replace(oneTapCallbackHTTPBody, `"credential":"opaque-google-credential"`, `"credential":null`, 1), strings.TrimSuffix(oneTapCallbackHTTPBody, "}") + `,"g_csrf_token":"original.google_csrf!"}`, strings.TrimSuffix(oneTapCallbackHTTPBody, "}") + `,"mode":"redirect"}`, strings.Replace(oneTapCallbackHTTPBody, "opaque-google-credential", strings.Repeat("A", 16385), 1), strings.Replace(oneTapCallbackHTTPBody, "original.google_csrf!", strings.Repeat("A", 1025), 1)} {
		c, p, rate, r, _ := oneTapCallbackHTTPFixture(t)
		// Exercise the selected credential/CSRF field bounds rather than a
		// stricter aggregate envelope masking their independent validation.
		c.Network.Limits.MaximumBodyBytes = 32768
		c.Network.Limits.MaximumDecodedBytes = 32768
		r.Body = io.NopCloser(strings.NewReader(body))
		r.ContentLength = int64(len(body))
		w := oneTapCallbackHTTPServe(t, c, r)
		if w.Code != 400 || p.calls != 0 || len(rate.requests) != 0 {
			t.Fatal("malformed closed JSON reached native", w.Code)
		}
	}
}

func TestOneTapCallbackHTTPFeatureUsesExactSelectedWire(t *testing.T) {
	c, _, _, _, _ := oneTapCallbackHTTPFixture(t)
	feature, err := oauthhttp.NewOneTapCallbackFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	_, document, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "One Tap callback", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(document.JSON(), &wire) != nil || len(wire.Paths) != 1 || wire.Paths["/v1/oauth/onetap-callback"]["post"] == nil {
		t.Fatal("selected callback wire differs from executable selection")
	}
	var operation map[string]json.RawMessage
	if json.Unmarshal(wire.Paths["/v1/oauth/onetap-callback"]["post"], &operation) != nil || !strings.Contains(string(operation["requestBody"]), `"flowId"`) || strings.Contains(string(operation["requestBody"]), `"flowID"`) {
		t.Fatal("wire callback field shape drifted")
	}
}

type oneTapCallbackHTTPIssueExecutor struct{ t *testing.T }

func (e oneTapCallbackHTTPIssueExecutor) ExecuteIssue(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
	command, record, ok := r.OneTapCommand()
	if !ok {
		e.t.Fatal("fixture did not select native One Tap issuance")
	}
	feature, _ := command.Feature()
	return session.IssueExecution{Receipt: identity.CommandResult{Binding: feature.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "transport-fixture-audit", Feature: &identity.FeatureReceipt{Operation: feature.Operation, BeforeVersion: 1, AfterVersion: 2}}, Session: record}, nil
}

func (e oneTapCallbackHTTPIssueExecutor) RecoverIssue(context.Context, session.IssueRequest) (session.IssueExecution, error) {
	e.t.Fatal("transport fixture attempted secret-bearing recovery")
	return session.IssueExecution{}, errors.New("unexpected recovery")
}

func oneTapCallbackHTTPResult(t *testing.T, c oauthhttp.OneTapCallbackConfig, choice session.RememberChoice) oauthhttp.OneTapCallbackHTTPResult {
	t.Helper()
	now := c.Now()
	remember, err := session.ResolveRememberPolicy(choice, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: 2 * time.Hour, IdleTTL: time.Hour, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	bind := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
	authority, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: bind("global"), Tenant: bind("tenant"), User: bind("user"), Identifier: bind("identifier"), Credential: bind("credential"), SessionFamily: bind("family"), Session: bind("session"), Authorization: bind("authorization"), Factor: session.OptionalAuthorityBinding{Present: true, Binding: bind("factor")}})
	if err != nil {
		t.Fatal(err)
	}
	binding := identity.CommandBinding{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: c.TenantID, AnonymousFlowID: "AQEBAQEBAQEBAQEBAQEBAQ", RecordID: "AQEBAQEBAQEBAQEBAQEBAQ", ActorID: "oauth-login", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.oauth.onetap-callback", SchemaID: "oauth-onetap-callback-v1", SchemaVersion: 1, PolicyID: "onetap-policy", PolicyVersion: 1, CorrelationID: "original-correlation"}
	spec := session.SessionSpec{SessionID: "original-session", FamilyID: "original-family", TenantID: binding.TenantID, UserID: "user", Audience: c.Audience, Version: 1, FamilyVersion: 1, Remember: remember, Authority: authority, IssuedAt: now, LastActivityAt: now, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: auth.ProofID(binding.CommandID), Tenant: string(binding.TenantID), Subject: "user", Method: "oauth", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: c.Audience, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "original-provider-account", CredentialVersion: 1}}
	lookup, _ := session.NewDigestKey(1, []byte(strings.Repeat("l", 32)))
	csrfKey, _ := session.NewCSRFKey(2, []byte(strings.Repeat("c", 32)))
	issuer, err := session.NewOneTapSessionIssuerWithCSRF(oneTapCallbackHTTPIssueExecutor{t}, session.IssuerConfig{Clock: &signinDeliveryClock{now: now}, MaximumDuration: time.Second, LookupKey: lookup, TokenSize: 32, Cookie: c.Cookie}, csrfKey)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := issuer.PrepareOneTap(binding, spec)
	if err != nil {
		t.Fatal(err)
	}
	operation := identity.FeatureOperation{Owner: "identity/oauth/onetap", OperationID: binding.OperationID, SchemaID: binding.SchemaID, SchemaVersion: 1, SubjectRequirement: identity.FeatureSubjectAnonymousFlow, RecordRequirement: identity.FeatureRecordRequired}
	command, err := identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: binding, Operation: operation}, auth.NewBearerCredential(strings.Repeat("A", 43)))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err = issuer.BindOneTap(prepared, command)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := issuer.Issue(t.Context(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := prepared.CSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	return oauthhttp.OneTapCallbackHTTPResult{Session: issued, CSRF: csrf}
}

func TestOneTapCallbackHTTPDeliversOnlyFreshOriginalCookies(t *testing.T) {
	for _, choice := range []session.RememberChoice{session.BrowserSession, session.PersistentSession} {
		name := "browser"
		if choice == session.PersistentSession {
			name = "persistent"
		}
		t.Run(name, func(t *testing.T) {
			c, p, _, r, _ := oneTapCallbackHTTPFixture(t)
			p.result, p.err = oneTapCallbackHTTPResult(t, c, choice), nil
			original, _ := p.result.Session.Session.Bindings()
			now := c.Now().Add(10 * time.Second)
			c.Now = func() time.Time { return now }
			w := oneTapCallbackHTTPServe(t, c, r)
			if w.Code != 200 || w.Body.String() != "{\"status\":\"signed_in\"}\n" || w.Header().Get("Location") != "" || p.calls != 1 {
				t.Fatal("fresh accepted callback did not produce minimal success", w.Code, w.Body.String())
			}
			cookies := w.Result().Cookies()
			if len(cookies) != 2 || len(w.Header().Values("Set-Cookie")) != 2 {
				t.Fatal("fresh callback did not deliver two separate cookies")
			}
			for _, cookie := range cookies {
				if cookie.Name != "__Host-identity_session" && cookie.Name != "__Host-identity_csrf" || !cookie.Secure || cookie.Domain != "" || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode || cookie.HttpOnly != (cookie.Name == "__Host-identity_session") || cookie.Value == "" {
					t.Fatal("callback changed cookie roles or host policy")
				}
				if choice == session.PersistentSession {
					if !cookie.Expires.Equal(original.IssuedAt.Add(original.Remember.AbsoluteTTL())) || cookie.MaxAge != int(original.IssuedAt.Add(original.Remember.AbsoluteTTL()).Sub(now).Seconds()) {
						t.Fatal("callback renewed original remember lifetime")
					}
				} else if cookie.MaxAge != 0 || !cookie.Expires.IsZero() {
					t.Fatal("browser cookie became persistent")
				}
				if cookie.Name == "__Host-identity_session" {
					token, err := session.ParseToken(cookie.Value)
					if err != nil {
						t.Fatal("delivered bearer was not canonical")
					}
					lookup, _ := session.NewDigestKey(1, []byte(strings.Repeat("l", 32)))
					digest, err := token.Digest(lookup, string(original.TenantID))
					if err != nil || digest != original.Lookup {
						t.Fatal("transport replaced the originally committed bearer")
					}
				} else {
					token, err := session.ParseCSRFToken(cookie.Value)
					if err != nil {
						t.Fatal("delivered synchronizer was not canonical")
					}
					key, _ := session.NewCSRFKey(2, []byte(strings.Repeat("c", 32)))
					binding := session.CSRFBinding{TenantID: original.TenantID, SessionID: original.SessionID, SessionVersion: original.Version}
					if p.result.Session.Session.CSRFState().Check(binding, token, key) != nil {
						t.Fatal("transport replaced the originally committed synchronizer")
					}
				}
			}
			if _, err := p.result.Session.Token.Reveal(); err == nil {
				t.Fatal("native bearer was not consumed")
			}
			if _, err := p.result.CSRF.Reveal(); err == nil {
				t.Fatal("native synchronizer was not consumed")
			}
			retry := r.Clone(t.Context())
			retry.Body = io.NopCloser(strings.NewReader(oneTapCallbackHTTPBody))
			retry.ContentLength = int64(len(oneTapCallbackHTTPBody))
			w = oneTapCallbackHTTPServe(t, c, retry)
			requireNoSigninCredentials(t, w)
			if w.Code != 503 || p.calls != 2 {
				t.Fatal("copied consumed native result did not fail closed", w.Code)
			}
		})
	}
}

func TestOneTapCallbackHTTPWithholdsNondeliverableNativeResults(t *testing.T) {
	for _, mode := range []string{"replay", "unknown", "missing-session", "wrong-tenant", "wrong-audience", "wrong-command", "zero-deadline", "expired-deadline", "cancelled", "native-error"} {
		t.Run(mode, func(t *testing.T) {
			c, p, _, r, _ := oneTapCallbackHTTPFixture(t)
			p.result, p.err = oneTapCallbackHTTPResult(t, c, session.PersistentSession), nil
			switch mode {
			case "replay":
				p.result.Session.Replayed = true
			case "unknown":
				p.result.Session.CommitOutcome = identity.CommitOutcomeUnknown
			case "missing-session":
				p.result.Session.Session = session.Session{}
			case "wrong-tenant":
				c.TenantID = "foreign"
			case "wrong-audience":
				c.Audience = "foreign"
			case "wrong-command":
				p.result.Session.CommandID = "different-command"
			case "zero-deadline":
				p.result.Session.DeliveryValidUntil = time.Time{}
			case "expired-deadline":
				p.result.Session.DeliveryValidUntil = c.Now()
			case "cancelled":
				ctx, cancel := context.WithCancel(t.Context())
				r = r.WithContext(ctx)
				p.before = cancel
			case "native-error":
				p.err = errors.New("private native detail")
			}
			w := oneTapCallbackHTTPServe(t, c, r)
			requireNoSigninCredentials(t, w)
			if w.Code < 400 || w.Header().Get("Location") != "" || strings.Contains(w.Body.String(), "signed_in") {
				t.Fatal("nondelivery fabricated success", mode, w.Code)
			}
		})
	}
}

type oneTapCallbackHTTPCommitWriter struct {
	http.ResponseWriter
	before func()
}

func (w oneTapCallbackHTTPCommitWriter) WriteHeader(status int) {
	w.before()
	w.ResponseWriter.WriteHeader(status)
}

func TestOneTapCallbackHTTPRechecksOriginalDeadlineAtResponseCommit(t *testing.T) {
	for _, mode := range []string{"deadline", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			c, p, _, r, _ := oneTapCallbackHTTPFixture(t)
			p.result, p.err = oneTapCallbackHTTPResult(t, c, session.PersistentSession), nil
			now := c.Now()
			c.Now = func() time.Time { return now }
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			r = r.WithContext(ctx)
			h, err := oauthhttp.NewOneTapCallbackHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			bound, err := identityhttp.WithOperationMiddleware(h, []identityhttp.MiddlewareDescriptor{{Owner: "identity/reference", Middleware: identityhttp.Middleware{Name: "delay-final-commit", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					next.ServeHTTP(oneTapCallbackHTTPCommitWriter{ResponseWriter: w, before: func() {
						if mode == "deadline" {
							now = p.result.Session.DeliveryValidUntil
						} else {
							cancel()
						}
					}}, r)
				})
			}}}})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			bound.ServeHTTP(w, r)
			if w.Code != 503 || p.calls != 1 || strings.Contains(w.Body.String(), "signed_in") {
				t.Fatal("late response cutoff emitted accepted result", w.Code)
			}
			requireNoSigninCredentials(t, w)
		})
	}
}

func TestOneTapCallbackHTTPMiddlewareCannotCommitUnownedSuccessOrCookies(t *testing.T) {
	for _, channel := range []string{"header", "flush", "read-from"} {
		t.Run(channel, func(t *testing.T) {
			c, p, _, r, _ := oneTapCallbackHTTPFixture(t)
			h, err := oauthhttp.NewOneTapCallbackHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			bound, err := identityhttp.WithOperationMiddleware(h, []identityhttp.MiddlewareDescriptor{{Owner: "identity/reference", Middleware: identityhttp.Middleware{Name: "early-unowned-output", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header()["set-cookie"] = []string{"__Host-identity_session=not-owned; Secure; HttpOnly; Path=/"}
					w.Header()["location"] = []string{"https://foreign.example"}
					w.Header()["authorization"] = []string{"Bearer not-owned"}
					w.Header()["trailer:SeT-CoOkIe"] = []string{"not-owned"}
					switch channel {
					case "header":
						w.WriteHeader(200)
					case "flush":
						w.(http.Flusher).Flush()
					case "read-from":
						_, _ = w.(io.ReaderFrom).ReadFrom(strings.NewReader("not-owned"))
					}
					next.ServeHTTP(w, r)
				})
			}}}})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			bound.ServeHTTP(callbackReadFromWriter{w}, r)
			if w.Code != 503 || p.calls != 0 || strings.Contains(w.Body.String(), "signed_in") {
				t.Fatal("early response reached native or claimed success", w.Code)
			}
			requireNoSigninCredentials(t, w)
			for name := range w.Result().Header {
				if strings.EqualFold(name, "Location") || strings.EqualFold(name, "Trailer") || strings.HasPrefix(strings.ToLower(name), "trailer:") {
					t.Fatal("early response retained unowned redirect/trailer")
				}
			}
		})
	}
}

func TestOneTapCallbackHTTPClientConfirmationAndNativeDeviceScope(t *testing.T) {
	c, p, _, r, _ := oneTapCallbackHTTPFixture(t)
	body := strings.TrimSuffix(oneTapCallbackHTTPBody, "}") + `,"client_id":"trusted-google-client"}`
	r.Body = io.NopCloser(strings.NewReader(body))
	r.ContentLength = int64(len(body))
	w := oneTapCallbackHTTPServe(t, c, r)
	if w.Code != 503 || p.calls != 1 {
		t.Fatal("exact optional client confirmation was rejected", w.Code)
	}
	for _, scope := range []string{"foreign-tenant", "foreign-origin", "forged"} {
		t.Run(scope, func(t *testing.T) {
			c, p, rate, r, _ := oneTapCallbackHTTPFixture(t)
			devices, err := session.NewBrowserDeviceCodec(c.Device)
			if err != nil {
				t.Fatal(err)
			}
			tenant, origin := c.TenantID, string(c.Origin)
			if scope == "foreign-tenant" {
				tenant = "foreign"
			}
			if scope == "foreign-origin" {
				origin = "https://foreign.example"
			}
			device, err := devices.Issue(t.Context(), c.Now(), tenant, origin)
			if err != nil {
				t.Fatal(err)
			}
			response := &http.Response{Header: http.Header{"Set-Cookie": {device.CookieHeader()}}}
			cookie := response.Cookies()[0]
			if scope == "forged" {
				cookie.Value = strings.Repeat("A", 114)
			}
			r.Header.Del("Cookie")
			r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
			r.AddCookie(cookie)
			r.AddCookie(&http.Cookie{Name: "g_csrf_token", Value: "original.google_csrf!"})
			w := oneTapCallbackHTTPServe(t, c, r)
			if w.Code != 403 || p.calls != 0 || len(rate.requests) != 0 {
				t.Fatal("foreign original signed device reached native", w.Code)
			}
		})
	}
}

func TestOneTapCallbackHTTPSharedProviderIPRateDenial(t *testing.T) {
	c, p, rate, r, _ := oneTapCallbackHTTPFixture(t)
	resolver, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := resolver.Resolve(r)
	if err != nil {
		t.Fatal(err)
	}
	for range 30 {
		admitted, err := c.Rate.AdmitProviderIP(t.Context(), facts, "identity.oauth.onetap-callback", c.Provider.ID)
		if err != nil || !admitted.Allowed {
			t.Fatal("could not fill original shared provider/IP budget")
		}
	}
	w := oneTapCallbackHTTPServe(t, c, r)
	if w.Code != 429 || w.Header().Get("Retry-After") != "20" || p.calls != 0 {
		t.Fatal("shared provider/IP denial reached completion or lost retry", w.Code)
	}
	requireNoSigninCredentials(t, w)
	rate.fail = true
	body := oneTapCallbackHTTPBody
	r.Body = io.NopCloser(strings.NewReader(body))
	r.ContentLength = int64(len(body))
	w = oneTapCallbackHTTPServe(t, c, r)
	if w.Code != 503 || w.Header().Get("Retry-After") != "" || p.calls != 0 {
		t.Fatal("rate outage fabricated retry or crossed native", w.Code)
	}
}

func FuzzOneTapCallbackHTTPClosedJSON(f *testing.F) {
	f.Add(oneTapCallbackHTTPBody)
	f.Add(`{"flowId":"AQEBAQEBAQEBAQEBAQEBAQ","credential":null,"g_csrf_token":"original.google_csrf!"}`)
	f.Add(strings.TrimSuffix(oneTapCallbackHTTPBody, "}") + `,"g_csrf_token":"duplicate"}`)
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 16384 {
			return
		}
		c, p, _, r, _ := oneTapCallbackHTTPFixture(t)
		r.Body = io.NopCloser(strings.NewReader(body))
		r.ContentLength = int64(len(body))
		w := oneTapCallbackHTTPServe(t, c, r)
		if w.Code < 400 || p.calls > 1 || w.Header().Get("Location") != "" {
			t.Fatal("unaccepted callback produced success, repeated native work or redirect", w.Code)
		}
		requireNoSigninCredentials(t, w)
		for _, b := range p.last.Callback.Credential.IDToken {
			if b != 0 {
				t.Fatal("borrowed credential survived a fuzzed request")
			}
		}
	})
}

func TestOneTapCallbackHTTPRouterErrorsMatchSelectedWire(t *testing.T) {
	cases := []struct {
		name, media, code string
		status            int
		alter             func(*http.Request)
	}{
		{"foreign-origin", "text/plain", "identity.http.origin_denied\n", 403, func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example") }},
		{"plaintext", "application/json", "https_required", 403, func(r *http.Request) { r.TLS = nil; r.URL.Scheme = "http" }},
		{"unknown-host", "application/json", "misdirected_request", 421, func(r *http.Request) { r.Host = "foreign.example" }},
		{"wrong-method", "application/json", "method_not_allowed", 405, func(r *http.Request) { r.Method = http.MethodGet }},
		{"escaped-path", "application/json", "not_found", 404, func(r *http.Request) {
			r.URL.RawPath = "/v1/oauth/%6Fnetap-callback"
			r.RequestURI = r.URL.RequestURI()
		}},
		{"bad-envelope", "application/json", "invalid_request", 400, func(r *http.Request) { r.Header["content-type"] = []string{"application/json"} }},
		{"cancelled", "application/json", "unavailable", 503, func(r *http.Request) {
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			*r = *r.WithContext(ctx)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, p, rate, r, _ := oneTapCallbackHTTPFixture(t)
			feature, err := oauthhttp.NewOneTapCallbackFeature(c)
			if err != nil {
				t.Fatal(err)
			}
			operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
			if err != nil {
				t.Fatal(err)
			}
			h, document, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: c.Network, HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "One Tap callback", Version: "1"}}, operations, nil)
			if err != nil {
				t.Fatal(err)
			}
			tc.alter(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status || !strings.HasPrefix(w.Header().Get("Content-Type"), tc.media) || p.calls != 0 || len(rate.requests) != 0 {
				t.Fatal("outer denial crossed native/rate boundary or changed response", w.Code, w.Header().Get("Content-Type"))
			}
			requireNoSigninCredentials(t, w)
			var wire struct {
				Paths map[string]map[string]struct {
					Responses map[string]struct {
						Content map[string]struct {
							Schema struct {
								Const      string `json:"const"`
								Properties map[string]struct {
									Const string   `json:"const"`
									Enum  []string `json:"enum"`
								} `json:"properties"`
							} `json:"schema"`
						} `json:"content"`
					} `json:"responses"`
				} `json:"paths"`
			}
			if json.Unmarshal(document.JSON(), &wire) != nil {
				t.Fatal("invalid selected document")
			}
			schema, exists := wire.Paths["/v1/oauth/onetap-callback"]["post"].Responses[fmt.Sprint(tc.status)].Content[tc.media]
			if !exists {
				t.Fatal("selected wire omits actual outer denial media/status", tc.status, tc.media)
			}
			if tc.media == "text/plain" {
				if w.Body.String() != tc.code || schema.Schema.Const != tc.code {
					t.Fatal("fixed outer origin denial differs from selected schema")
				}
			} else {
				var body map[string]string
				if json.Unmarshal(w.Body.Bytes(), &body) != nil || len(body) != 1 || body["error"] != tc.code {
					t.Fatal("outer denial did not retain exact JSON error")
				}
				errorSchema := schema.Schema.Properties["error"]
				if errorSchema.Const != tc.code && !slices.Contains(errorSchema.Enum, tc.code) {
					t.Fatal("selected error schema rejects actual outer denial", tc.code)
				}
			}
		})
	}
}
