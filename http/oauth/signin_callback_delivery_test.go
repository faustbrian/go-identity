package oauthhttp_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	oauthhttp "github.com/faustbrian/go-identity/http/oauth"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
)

// These doubles stop at native execution. They prove transport and one-time
// delivery custody, not provider verification or durable PostgreSQL authority.
type signinDeliveryExecutor struct {
	t       *testing.T
	receipt identity.CommandResult
}

func (e *signinDeliveryExecutor) ExecuteIssue(_ context.Context, request session.IssueRequest) (session.IssueExecution, error) {
	command, record, ok := request.OAuthCommand()
	if !ok {
		e.t.Fatal("prospective issuer lost the OAuth execution profile")
	}
	feature, ok := command.Feature()
	if !ok {
		e.t.Fatal("prospective issuer lost the original command")
	}
	e.receipt = identity.CommandResult{Binding: feature.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "transport-fixture-audit", Feature: &identity.FeatureReceipt{Operation: feature.Operation}}
	return session.IssueExecution{Receipt: e.receipt, Session: record}, nil
}

func (e *signinDeliveryExecutor) RecoverIssue(context.Context, session.IssueRequest) (session.IssueExecution, error) {
	e.t.Fatal("transport attempted secret-bearing native recovery")
	return session.IssueExecution{}, errors.New("unexpected recovery")
}

type signinDeliveryClock struct{ now time.Time }

func (c *signinDeliveryClock) Now() time.Time { return c.now }

type signinDeliveryOwner struct {
	result oauth.SigninCallbackResult
	err    error
	before func()
	calls  int
	last   oauth.SigninCallbackRequest
}

func (o *signinDeliveryOwner) Callback(ctx context.Context, request oauth.SigninCallbackRequest) (oauth.SigninCallbackResult, error) {
	o.calls++
	o.last = request
	if _, ok := ctx.Deadline(); !ok {
		return oauth.SigninCallbackResult{}, errors.New("unbounded callback")
	}
	if o.before != nil {
		o.before()
	}
	return o.result, o.err
}

func signinDeliveryResult(t *testing.T, c oauthhttp.Config, choice session.RememberChoice) (oauth.SigninCallbackResult, identity.CommandResult, time.Time) {
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
	binding := identity.CommandBinding{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant", AnonymousFlowID: "original-flow", ActorID: "oauth-login", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.oauth.callback", SchemaID: "oauth-signin-callback-v1", SchemaVersion: 1, PolicyID: "signin-policy", PolicyVersion: 1, CorrelationID: "original-correlation"}
	spec := session.SessionSpec{SessionID: "original-session", FamilyID: "original-family", TenantID: binding.TenantID, UserID: "user", Audience: c.Signin.Audience, Version: 1, FamilyVersion: 1, Remember: remember, Authority: authority, IssuedAt: now, LastActivityAt: now, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: auth.ProofID(binding.CommandID), Tenant: "tenant", Subject: "user", Method: "oauth", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: c.Signin.Audience, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "original-provider-account", CredentialVersion: 1}}
	lookup, err := session.NewDigestKey(1, []byte(strings.Repeat("l", 32)))
	if err != nil {
		t.Fatal(err)
	}
	csrfKey, err := session.NewCSRFKey(2, []byte(strings.Repeat("c", 32)))
	if err != nil {
		t.Fatal(err)
	}
	executor := &signinDeliveryExecutor{t: t}
	issuer, err := session.NewOAuthSessionIssuerWithCSRF(executor, session.IssuerConfig{Clock: &signinDeliveryClock{now: now}, MaximumDuration: time.Second, LookupKey: lookup, TokenSize: 32, Cookie: c.Cookie}, csrfKey)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := issuer.PrepareOAuth(binding, spec)
	if err != nil {
		t.Fatal("prepare prospective public session", err)
	}
	operation := identity.FeatureOperation{Owner: "identity/oauth", OperationID: binding.OperationID, SchemaID: binding.SchemaID, SchemaVersion: 1, SubjectRequirement: identity.FeatureSubjectAnonymousFlow, RecordRequirement: identity.FeatureRecordOmitted}
	command, err := identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: binding, Operation: operation}, auth.NewBearerCredential(strings.Repeat("B", 42)+"A"))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err = issuer.BindOAuth(prepared, command)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := issuer.Issue(t.Context(), prepared)
	if err != nil {
		t.Fatal("issue through native-execution boundary double", err)
	}
	csrf, err := prepared.CSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	callback, err := oauth.NewValidatedCallbackURL("https://app.example/complete", c.CallbackAllowlist)
	if err != nil {
		t.Fatal(err)
	}
	result, err := oauth.NewSigninCallbackResult(executor.receipt, oauth.IdentityResult{ProviderID: c.Provider.ID, ProviderSubject: "provider-subject", UserID: spec.UserID, AccountID: "AAAAAAAAAAAAAAAAAAAAAQ", RememberPolicy: remember, Outcome: "signin"}, callback, issued, csrf)
	if err != nil {
		t.Fatal("construct typed native delivery", err)
	}
	return result, executor.receipt, spec.Authentication.Proof.ExpiresAt
}

func serveSigninDelivery(t *testing.T, c oauthhttp.Config, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	h, err := oauthhttp.NewCallbackHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func requireNoSigninCredentials(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	for name := range w.Header() {
		if strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "X-CSRF-Token") {
			t.Fatal("nondeliverable callback exposed a credential header")
		}
	}
	if strings.Contains(w.Body.String(), "original-provider-code") || strings.Contains(w.Body.String(), "private native detail") {
		t.Fatal("callback exposed private input or dependency details")
	}
}

func TestSigninCallbackDeliversOriginalCommittedCookiesOnce(t *testing.T) {
	for _, choice := range []session.RememberChoice{session.BrowserSession, session.PersistentSession} {
		name := "browser"
		if choice == session.PersistentSession {
			name = "persistent"
		}
		t.Run(name, func(t *testing.T) {
			c, selector, source, link, r, device := sharedCallbackFixture(t, "identity.oauth.signin-start")
			result, _, _ := signinDeliveryResult(t, c, choice)
			owner := &signinDeliveryOwner{result: result}
			c.Signin.Complete = owner
			original, _ := result.Session.Session.Bindings()
			// Delivery occurs after issuance; it must not restart the lifetime.
			now := c.Now().Add(10 * time.Second)
			c.Now = func() time.Time { return now }
			w := serveSigninDelivery(t, c, r)
			if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "https://app.example/complete" || owner.calls != 1 || selector.calls != 1 || source.sources != 1 || link.callbacks != 0 {
				t.Fatal("fresh signin did not deliver its original callback", w.Code)
			}
			if owner.last.TenantID != "tenant" || owner.last.Device != device.DeviceID() || owner.last.FlowCookie.Token() != strings.Repeat("B", 42)+"A" {
				t.Fatal("signin lost original browser scope")
			}
			response := w.Result()
			defer response.Body.Close()
			cookies := response.Cookies()
			if len(cookies) != 2 || len(response.Header.Values("Set-Cookie")) != 2 {
				t.Fatal("signin did not emit exactly authentication and synchronizer cookies")
			}
			values := make(map[string]string)
			for _, cookie := range cookies {
				values[cookie.Name] = cookie.Value
				if !cookie.Secure || cookie.Domain != "" || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode || cookie.Partitioned || cookie.Value == "" {
					t.Fatal("signin weakened host-only cookie policy")
				}
				if cookie.Name != "__Host-identity_session" && cookie.Name != "__Host-identity_csrf" || cookie.HttpOnly != (cookie.Name == "__Host-identity_session") {
					t.Fatal("authentication and readable synchronizer cookie roles changed")
				}
				if choice == session.PersistentSession {
					if cookie.Expires != original.IssuedAt.Add(original.Remember.AbsoluteTTL()) || cookie.MaxAge != int(original.IssuedAt.Add(original.Remember.AbsoluteTTL()).Sub(now).Seconds()) {
						t.Fatal("persistent delivery renewed original lifetime")
					}
				} else if cookie.MaxAge != 0 || !cookie.Expires.IsZero() {
					t.Fatal("browser Remember choice became persistent")
				}
			}
			authentication, err := session.ParseToken(values["__Host-identity_session"])
			if err != nil {
				t.Fatal("authentication cookie was not a canonical credential")
			}
			lookup, _ := session.NewDigestKey(1, []byte(strings.Repeat("l", 32)))
			digest, err := authentication.Digest(lookup, string(original.TenantID))
			if err != nil || digest != original.Lookup {
				t.Fatal("transport replaced the originally committed authentication credential")
			}
			csrf, err := session.ParseCSRFToken(values["__Host-identity_csrf"])
			if err != nil {
				t.Fatal("synchronizer cookie was not a canonical credential")
			}
			csrfKey, _ := session.NewCSRFKey(2, []byte(strings.Repeat("c", 32)))
			csrfBinding := session.CSRFBinding{TenantID: original.TenantID, SessionID: original.SessionID, SessionVersion: original.Version}
			if result.Session.Session.CSRFState().Check(csrfBinding, csrf, csrfKey) != nil {
				t.Fatal("transport replaced the originally committed session-bound synchronizer")
			}
			if _, err := result.Session.Token.Reveal(); err == nil {
				t.Fatal("original authentication custody was not consumed")
			}
			if _, err := result.CSRFToken.Reveal(); err == nil {
				t.Fatal("original synchronizer custody was not consumed")
			}
			input, ok := selector.last.Input()
			if !ok || input.Use(t.Context(), func(context.Context, []byte, []byte) error { return nil }) == nil {
				t.Fatal("provider callback custody survived response completion")
			}
			w = serveSigninDelivery(t, c, r.Clone(t.Context()))
			requireNoSigninCredentials(t, w)
			if w.Code != http.StatusServiceUnavailable || w.Header().Get("Location") != "" {
				t.Fatal("copied consumed native result delivered again", w.Code)
			}
		})
	}
}

func TestSigninCallbackWithholdsNondeliverableNativeResults(t *testing.T) {
	for _, mode := range []string{"replay", "native-error", "zero-result", "cancelled", "foreign-tenant", "foreign-provider", "foreign-user", "missing-csrf-binding", "wrong-audience", "expired-proof"} {
		t.Run(mode, func(t *testing.T) {
			c, _, _, _, r, _ := sharedCallbackFixture(t, "identity.oauth.signin-start")
			result, receipt, expiry := signinDeliveryResult(t, c, session.PersistentSession)
			owner := &signinDeliveryOwner{result: result}
			c.Signin.Complete = owner
			status := http.StatusServiceUnavailable
			switch mode {
			case "replay":
				owner.result.Session.Replayed = true
				owner.result.Session.Token, owner.result.CSRFToken = session.Token{}, session.CSRFToken{}
				owner.result.Session.Cookie = http.Cookie{}
				status = http.StatusSeeOther
			case "native-error":
				owner.err = errors.New("private native detail")
			case "zero-result":
				owner.result = oauth.SigninCallbackResult{}
			case "cancelled":
				ctx, cancel := context.WithCancel(r.Context())
				defer cancel()
				r = r.WithContext(ctx)
				owner.before = cancel
			case "foreign-provider":
				projection, _ := result.Outcome.Identity()
				projection.ProviderID = "foreign"
				callback, _ := oauth.NewValidatedCallbackURL("https://app.example/complete", c.CallbackAllowlist)
				var err error
				owner.result, err = oauth.NewSigninCallbackResult(receipt, projection, callback, result.Session, result.CSRFToken)
				if err != nil {
					t.Fatal(err)
				}
			case "foreign-tenant", "foreign-user", "missing-csrf-binding", "wrong-audience":
				spec, _ := result.Session.Session.Bindings()
				switch mode {
				case "foreign-tenant":
					spec.TenantID, spec.Authentication.Proof.Tenant = "foreign", "foreign"
				case "foreign-user":
					spec.UserID, spec.Authentication.Proof.Subject = "foreign", "foreign"
				case "wrong-audience":
					spec.Audience, spec.Authentication.Proof.Audience = "foreign", "foreign"
				}
				var err error
				if mode == "missing-csrf-binding" {
					owner.result.Session.Session, err = session.NewSession(spec)
				} else {
					csrfSpec, stateErr := result.Session.Session.CSRFState().Bindings()
					if stateErr != nil {
						t.Fatal(stateErr)
					}
					csrfSpec.Binding.TenantID = spec.TenantID
					csrfState, stateErr := session.NewCSRFState(csrfSpec)
					if stateErr != nil {
						t.Fatal(stateErr)
					}
					owner.result.Session.Session, err = session.NewSessionWithCSRF(spec, csrfState)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "expired-proof":
				c.Now = func() time.Time { return expiry }
			}
			w := serveSigninDelivery(t, c, r)
			requireNoSigninCredentials(t, w)
			if w.Code != status || owner.calls != 1 {
				t.Fatal("wrong nondeliverable callback outcome", w.Code, owner.calls)
			}
			if status != http.StatusSeeOther && w.Header().Get("Location") != "" {
				t.Fatal("failed signin retained successful redirect")
			}
		})
	}
}

func TestSigninCallbackMalformedQueryDoesNotReachNativeDelivery(t *testing.T) {
	c, selector, source, _, r, _ := sharedCallbackFixture(t, "identity.oauth.signin-start")
	result, _, _ := signinDeliveryResult(t, c, session.BrowserSession)
	owner := &signinDeliveryOwner{result: result}
	c.Signin.Complete = owner
	q := r.URL.Query()
	q.Add("state", q.Get("state"))
	r.URL.RawQuery = q.Encode()
	r.RequestURI = r.URL.RequestURI()
	w := serveSigninDelivery(t, c, r)
	requireNoSigninCredentials(t, w)
	if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" || selector.calls != 0 || source.sources != 0 || owner.calls != 0 {
		t.Fatal("ambiguous callback reached credential delivery", w.Code)
	}
}

func TestSigninCallbackProviderDenialRedirectsWithoutCredentials(t *testing.T) {
	c, _, _, _, r, _ := sharedCallbackFixture(t, "identity.oauth.signin-start")
	_, receipt, _ := signinDeliveryResult(t, c, session.BrowserSession)
	receipt.Binding.SchemaID = "identity.oauth.callback.anonymous-denied-v1"
	receipt.Binding.RecordID = "original-transaction"
	receipt.Feature = &identity.FeatureReceipt{Operation: identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.oauth.callback", SchemaID: receipt.Binding.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}, BeforeVersion: 1, AfterVersion: 2}
	callback, _ := oauth.NewValidatedCallbackURL("https://app.example/failed", c.CallbackAllowlist)
	result, err := oauth.NewDeniedSigninCallbackResult(receipt, callback)
	if err != nil {
		t.Fatal(err)
	}
	q := r.URL.Query()
	q.Del("code")
	q.Set("error", "access_denied")
	r.URL.RawQuery, r.RequestURI = q.Encode(), ""
	r.RequestURI = r.URL.RequestURI()
	owner := &signinDeliveryOwner{result: result}
	c.Signin.Complete = owner
	w := serveSigninDelivery(t, c, r)
	requireNoSigninCredentials(t, w)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "https://app.example/failed" || owner.calls != 1 || !owner.last.Callback.Denied() {
		t.Fatal("provider denial lost its original error callback", w.Code)
	}
}

type signinDeliveryWriteBoundary struct {
	http.ResponseWriter
	before func()
}

func (w signinDeliveryWriteBoundary) WriteHeader(status int) {
	if status == http.StatusSeeOther {
		w.before()
	}
	w.ResponseWriter.WriteHeader(status)
}

func TestSigninCallbackRechecksExpiryAtFinalResponseBoundary(t *testing.T) {
	c, _, _, _, r, _ := sharedCallbackFixture(t, "identity.oauth.signin-start")
	result, _, expiry := signinDeliveryResult(t, c, session.PersistentSession)
	owner := &signinDeliveryOwner{result: result}
	c.Signin.Complete = owner
	now := c.Now()
	c.Now = func() time.Time { return now }
	h, err := oauthhttp.NewCallbackHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	h, err = identityhttp.WithOperationMiddleware(h, []identityhttp.MiddlewareDescriptor{{Owner: "identity/reference", Middleware: identityhttp.Middleware{Name: "final-response-expiry", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(signinDeliveryWriteBoundary{ResponseWriter: w, before: func() { now = expiry }}, r)
		})
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	requireNoSigninCredentials(t, w)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Location") != "" || owner.calls != 1 {
		t.Fatal("expired callback credentials crossed final response boundary", w.Code)
	}
}
