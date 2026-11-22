package ssohttp

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
)

type signinCallbackProbe struct {
	flow                 identity.PreAuthTransactionID
	transaction          identity.CommandID
	attributions, calls  int
	attribution, request SigninCallbackRequest
	result               SigninCallbackResult
	provider             string
}

func (p *signinCallbackProbe) CallbackRateSource(_ context.Context, r SigninCallbackRequest) (SigninCallbackRateContext, error) {
	p.attributions++
	p.attribution = r
	provider := p.provider
	if provider == "" {
		provider = "approved-oidc"
	}
	return SigninCallbackRateContext{ProviderID: provider, FlowID: p.flow, TransactionID: string(p.transaction), Lifetime: time.Minute}, nil
}

func (p *signinCallbackProbe) CompleteSSOOIDC(_ context.Context, r SigninCallbackRequest) (SigninCallbackResult, error) {
	p.calls++
	p.request = r
	if p.result.Completion.Outcome == identity.CommitOutcomeCommitted {
		return p.result, nil
	}
	return SigninCallbackResult{}, identity.UnknownCommitError{CommandID: p.transaction}
}

func TestEnterpriseCallbackUsesNativeOriginalFlowAndWithholdsUnresolvedResult(t *testing.T) {
	t.Run("same protocol and installed ID", func(t *testing.T) {
		testEnterpriseCallbackOriginalFlow(t, "approved-oidc")
	})
	t.Run("distinct case-sensitive installed ID", func(t *testing.T) {
		testEnterpriseCallbackOriginalFlow(t, "Enterprise_OIDC-01")
	})
}

func testEnterpriseCallbackOriginalFlow(t *testing.T, installedProvider string) {
	t.Helper()
	discovery, _, _ := discoveryFixture(t)
	flowPolicy, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	discovery.BrowserDevice.Cookie, err = session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	codec, err := session.NewBrowserDeviceCodec(discovery.BrowserDevice)
	if err != nil {
		t.Fatal(err)
	}
	device, err := codec.Issue(context.Background(), discovery.Now(), testTenant, "https://tenant.example")
	if err != nil {
		t.Fatal(err)
	}
	deviceCookie, err := http.ParseSetCookie(device.CookieHeader())
	if err != nil {
		t.Fatal(err)
	}
	sessionCookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	csrfCookie, err := session.NewCSRFCookiePolicy(session.CookieConfig{Name: "__Host-identity_csrf", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	flow, err := identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	probe := &signinCallbackProbe{flow: flow, transaction: transaction, provider: installedProvider}
	config := SigninCallbackConfig{
		Browser:           SigninBrowserConfig{Network: discovery.Network, TenantID: testTenant, Origin: "https://tenant.example", FlowCookie: flowPolicy, Device: discovery.BrowserDevice, Rate: discovery.Rate, Now: discovery.Now, MaximumDuration: time.Second},
		Provider:          oauth.ProviderProfile{ID: "approved-oidc", Version: 1, Issuer: "https://provider.example", AuthorizationEndpoint: "https://provider.example/authorize", TokenEndpoint: "https://provider.example/token", RedirectURI: "https://tenant.example/sso/oidc/callback", ClientID: "transport-client", ClientAuthentication: oauth.ClientSecretBasic, Scopes: []string{"openid"}, Algorithms: []string{"ES256"}, ResponseMode: "query", PKCEMethod: "S256", NonceRequired: true, StateBytes: 32, NonceBytes: 32, Timeout: time.Second, ClockSkew: time.Second, MaxResponseBytes: 4096, MaxTokenBytes: 1024, MaxCodeBytes: 512},
		CallbackAllowlist: []string{"https://tenant.example/ok"}, Audience: "enterprise-app", Cookie: sessionCookie, CSRFCookie: csrfCookie, Callback: probe,
	}
	var feature identityhttp.Feature
	if installedProvider == config.Provider.ID {
		feature, err = NewSigninCallbackFeature(config)
	} else {
		feature, err = NewSigninCallbackFeatureForProvider(installedProvider, config)
	}
	if err != nil {
		t.Fatal(err)
	}
	operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	stopWithoutWriting := false
	middleware := []identityhttp.MiddlewareDescriptor{{Owner: "sso/oidc", Middleware: identityhttp.Middleware{Name: "enterprise-observation", Phase: identityhttp.MiddlewareBeforeAuth, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Fixture-Middleware", "executed")
			w.Header().Set("Location", "https://fixture.example/ignored")
			w.Header().Set("Set-Cookie", "fixture=ignored")
			if stopWithoutWriting {
				return
			}
			next.ServeHTTP(w, r)
		})
	}}}}
	router, _, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: config.Browser.Network, HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}}, operations, middleware)
	if err != nil {
		t.Fatal(err)
	}
	query := url.Values{"code": {"fixture-authorization-code"}, "state": {base64.RawURLEncoding.EncodeToString(make([]byte, 32))}, "iss": {"https://provider.example"}}.Encode()
	serve := func(query, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "https://tenant.example/sso/oidc/callback?"+query, nil)
		r.RequestURI, r.RemoteAddr = r.URL.RequestURI(), "192.0.2.17:32000"
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
		r.AddCookie(deviceCookie)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	t.Run("no delivery on middleware return without a response write", func(t *testing.T) {
		stopWithoutWriting = true
		defer func() { stopWithoutWriting = false }()
		response := serve(query, "").Result()
		defer response.Body.Close()
		if response.Header.Get("X-Fixture-Middleware") != "executed" || probe.attributions != 0 || probe.calls != 0 {
			t.Fatal("middleware did not stop before native callback")
		}
		if response.Header.Get("Set-Cookie") != "" || response.Header.Get("Location") != "" {
			t.Fatal("implicit response retained middleware-supplied delivery headers")
		}
	})
	if w := serve(query+"&code=duplicate", ""); w.Code != http.StatusBadRequest || probe.attributions != 0 {
		t.Fatal("malformed query reached native callback", w.Code)
	}
	if w := serve(query, "https://other.example"); w.Code != http.StatusForbidden || probe.attributions != 0 {
		t.Fatal("foreign Origin reached native callback", w.Code)
	}
	w := serve(query+"&flowID=untrusted-ignored-hint", "")
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("X-Fixture-Middleware") != "executed" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" ||
		probe.attributions != 1 || probe.calls != 1 || probe.attribution.Browser.FlowID != "" || probe.request.Browser.FlowID != flow ||
		probe.request.TenantID != testTenant || probe.request.ReceivedRedirectURI != "https://tenant.example/sso/oidc/callback" {
		t.Fatal("callback substituted browser scope or disclosed unresolved issuance", w.Code)
	}
	if err := probe.request.Input.Use(context.Background(), func(context.Context, []byte, []byte) error {
		t.Fatal("callback input survived the request")
		return nil
	}); err == nil {
		t.Fatal("native callback input must be destroyed after HTTP request")
	}
	probe.result = enterpriseIssueFixture(t, config, flow, transaction)
	w = serve(query, "")
	cookies := w.Result().Cookies()
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "https://tenant.example/ok" || w.Body.Len() != 0 || len(cookies) != 2 {
		t.Fatal("acknowledged completion did not deliver exactly the intended redirect and cookies", w.Code)
	}
	if cookies[0].Name != "__Host-identity_session" || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[1].Name != "__Host-identity_csrf" || cookies[1].HttpOnly || !cookies[1].Secure {
		t.Fatal("enterprise callback did not preserve separate cookie custody")
	}
	probe.result.Issuance.Replayed = true
	w = serve(query, "")
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Location") != "" {
		t.Fatal("historical completion disclosed original issuance", w.Code)
	}
	probe.provider = "other-oidc"
	before := probe.calls
	w = serve(query, "")
	if w.Code != http.StatusForbidden || probe.calls != before || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Location") != "" {
		t.Fatal("foreign native attribution reached callback completion", w.Code)
	}
	probe.provider = installedProvider
	probe.result = enterpriseIssueFixture(t, config, flow, transaction)
	probe.result.RedirectURI = "https://fixture.example/wrong"
	w = serve(query, "")
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Location") != "" {
		t.Fatal("committed result outside delivery scope disclosed credentials", w.Code)
	}
	probe.result = SigninCallbackResult{}
	transactionDenied := false
	for range 5 {
		before := probe.calls
		w = serve(query, "")
		if w.Code == http.StatusTooManyRequests {
			transactionDenied = probe.calls == before && w.Header().Get("Retry-After") != "" && w.Header().Get("Set-Cookie") == "" && w.Header().Get("Location") == ""
			break
		}
	}
	if !transactionDenied {
		t.Fatal("callback transaction quota did not deny before completion")
	}
	ipDenied := false
	for range 30 {
		probe.transaction, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		before, attributions := probe.calls, probe.attributions
		w = serve(query, "")
		if w.Code == http.StatusTooManyRequests {
			ipDenied = probe.calls == before && probe.attributions == attributions && w.Header().Get("Retry-After") != "" && w.Header().Get("Set-Cookie") == "" && w.Header().Get("Location") == ""
			break
		}
	}
	if !ipDenied {
		t.Fatal("provider IP quota did not deny before native attribution")
	}
}

func enterpriseIssueFixture(t *testing.T, c SigninCallbackConfig, flow identity.PreAuthTransactionID, command identity.CommandID) SigninCallbackResult {
	t.Helper()
	start, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	op := identity.FeatureOperation{Owner: "sso/oidc", OperationID: "identity.sso.oidc-callback", SchemaID: "sso-enterprise-oidc-callback-v1", SchemaVersion: 1, SubjectRequirement: identity.FeatureSubjectAnonymousFlow, RecordRequirement: identity.FeatureRecordRequired}
	binding := identity.CommandBinding{CommandID: command, TenantID: c.Browser.TenantID, AnonymousFlowID: string(flow), ActorID: "sso-login", ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "signin-policy", PolicyVersion: 1, CorrelationID: string(command), RecordID: string(start)}
	receipt := identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "callback-audit", Feature: &identity.FeatureReceipt{Operation: op, BeforeVersion: 1, AfterVersion: 2}}
	if err := receipt.Validate(); err != nil {
		t.Fatal(err)
	}
	now := c.Browser.Now()
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 15 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	scope := func(id string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: id, Version: 1} }
	authority, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: scope("global"), Tenant: scope("tenant"), User: scope("user"), Identifier: scope("identifier"), Credential: scope("credential"), SessionFamily: scope("family"), Session: scope("session"), Authorization: scope("authorization"), ActiveOrganizationID: "enterprise", Organization: session.OptionalAuthorityBinding{Present: true, Binding: scope("organization")}, Factor: session.OptionalAuthorityBinding{Present: true, Binding: scope("factor")}})
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	key, err := session.NewDigestKey(1, []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := token.Digest(key, string(binding.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	csrfKey, err := session.NewCSRFKey(1, []byte(strings.Repeat("c", 32)))
	if err != nil {
		t.Fatal(err)
	}
	csrfState, err := csrf.Digest(csrfKey, session.CSRFBinding{TenantID: binding.TenantID, SessionID: "session", SessionVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	proof := authentication.Proof{ID: authentication.ProofID(command), Tenant: string(binding.TenantID), Subject: "member", Method: "sso-oidc", Assurance: authentication.AssuranceSingleFactor, Purpose: "session-issue", Audience: c.Audience, IssuedAt: now, ExpiresAt: now.Add(10 * time.Second)}
	metadata := session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: proof, ProofVersion: 1, CredentialID: "enterprise-provider", CredentialVersion: 1}
	record, err := session.NewSessionWithCSRF(session.SessionSpec{SessionID: "session", FamilyID: "family", TenantID: binding.TenantID, UserID: "member", Audience: c.Audience, Version: 1, FamilyVersion: 1, Remember: remember, Authority: authority, Lookup: digest, IssuedAt: now, LastActivityAt: now, Authentication: metadata}, csrfState)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := c.Cookie.Attributes(remember, now, now.Add(remember.AbsoluteTTL()))
	if err != nil {
		t.Fatal(err)
	}
	return SigninCallbackResult{Completion: receipt, Issuance: session.IssueResult{CommandID: command, CommitOutcome: identity.CommitOutcomeCommitted, Session: record, Token: token, Cookie: cookie}, CSRF: csrf, RedirectURI: c.CallbackAllowlist[0]}
}
