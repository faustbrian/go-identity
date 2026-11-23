package ssohttp

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
)

type samlTestClock func() time.Time

func (f samlTestClock) Now() time.Time { return f() }

type samlPreAuthProbe struct {
	exec func(session.PreAuthIssueCommand) (session.PreAuthIssueExecution, error)
}

func (p samlPreAuthProbe) ExecutePreAuthIssuance(_ context.Context, c session.PreAuthIssueCommand) (session.PreAuthIssueExecution, error) {
	return p.exec(c)
}
func (samlPreAuthProbe) RecoverPreAuthIssue(context.Context, identity.RecoveryQuery) (identity.CommandResult, error) {
	return identity.CommandResult{}, identity.UnavailableError{}
}

type samlHTTPProbe struct {
	start    func(SAMLSigninStartRequest) (sso.SigninStartResult, error)
	source   func(SAMLSigninCallbackRequest) (SigninCallbackRateContext, error)
	complete func(SAMLSigninCallbackRequest) (SigninCallbackResult, error)
}

func (p samlHTTPProbe) StartSSOSAML(_ context.Context, r SAMLSigninStartRequest) (sso.SigninStartResult, error) {
	return p.start(r)
}
func (p samlHTTPProbe) SAMLCallbackRateSource(_ context.Context, r SAMLSigninCallbackRequest) (SigninCallbackRateContext, error) {
	return p.source(r)
}
func (p samlHTTPProbe) CompleteSSOSAML(_ context.Context, r SAMLSigninCallbackRequest) (SigninCallbackResult, error) {
	return p.complete(r)
}

func TestSAMLHTTPSelectedFlowUsesOnlyExactFrontchannelAndNativeReceipt(t *testing.T) {
	const spOrigin = "https://tenant.example"
	const idpOrigin = "https://idp.example"
	const provider = "-installed"
	const startPath = "/saml2/" + provider + "/login"
	const acsPath = "/saml2/" + provider + "/acs"
	const finish = spOrigin + "/signed-in"
	discovery, _, normalDevice := discoveryFixture(t)
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	signal, _ := session.NewDigestKey(2, []byte(strings.Repeat("x", 32)))
	var stored session.PreAuthTransactionSpec
	preauth := samlPreAuthProbe{exec: func(c session.PreAuthIssueCommand) (session.PreAuthIssueExecution, error) {
		stored, _ = c.Record.Bindings()
		op := session.PreAuthIssueOperation()
		binding := identity.CommandBinding{CommandID: c.CommandID, TenantID: testTenant, AnonymousFlowID: string(stored.Binding.ID),
			ActorID: "sso-login", ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID,
			RecordID: string(stored.Binding.ID), PolicyID: "signin-policy", PolicyVersion: 1, SchemaID: op.SchemaID,
			SchemaVersion: 1, CorrelationID: c.CorrelationID}
		return session.PreAuthIssueExecution{Receipt: identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeCommitted,
			AuditEventID: "issued-flow", Feature: &identity.FeatureReceipt{Operation: op, AfterVersion: 1}}}, nil
	}}
	issuer, err := session.NewSAMLFrontchannelIssuer(preauth, session.PreAuthIssuerConfig{ActorID: "sso-login", Action: "identity.sso.saml-acs",
		Origin: spOrigin, CallbackURL: spOrigin + acsPath, PolicyID: "signin-policy", PolicyVersion: 1,
		Clock: samlTestClock(discovery.Now), MaximumDuration: time.Second, FlowTTL: 5 * time.Minute, LookupKey: key, TokenSize: 32, Purpose: session.PreAuthSessionIssuance})
	if err != nil {
		t.Fatal("select actual frontchannel cookie issuer", err)
	}
	auth, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	csrf, _ := session.NewCSRFCookiePolicy(session.CookieConfig{Name: "__Host-identity_csrf", SameSite: http.SameSiteLaxMode})
	lifetime := session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}
	config := SAMLSigninConfig{Network: discovery.Network, TenantID: testTenant, Origin: spOrigin, IdentityProviderOrigin: idpOrigin,
		ProviderID: provider, AuthorizationEndpoint: idpOrigin + "/login", SuccessCallback: finish, ErrorCallback: finish,
		CallbackAllowlist: []string{finish}, Audience: "enterprise-app", Cookie: auth, CSRFCookie: csrf, Frontchannel: issuer,
		FlowSignalKey: signal, Lifetime: lifetime, Rate: discovery.Rate, Now: discovery.Now, MaximumDuration: time.Second}
	startOp := identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.saml-start", SchemaID: "identity.sso.saml-start.v1", SchemaVersion: 1,
		SubjectRequirement: identity.FeatureSubjectAnonymousFlow, RecordRequirement: identity.FeatureRecordRequired}
	acsOp := identity.FeatureOperation{Owner: "sso/saml", OperationID: "identity.sso.saml-acs", SchemaID: "sso-enterprise-saml-acs-v1", SchemaVersion: 1,
		SubjectRequirement: identity.FeatureSubjectAnonymousFlow, RecordRequirement: identity.FeatureRecordRequired}
	command, _ := identity.NewCommandID()
	state := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	assertion := base64.StdEncoding.EncodeToString([]byte("<signed-by-native-test-owner/>"))
	var started, sourceCalls, completeCalls int
	var initialBrowser SigninBrowser
	var allowSource = true
	probe := samlHTTPProbe{
		start: func(r SAMLSigninStartRequest) (sso.SigninStartResult, error) {
			started++
			initialBrowser = r.Browser
			if r.ProviderID != provider || r.TenantID != testTenant || r.Browser.FlowID != stored.Binding.ID || stored.Binding.Intent.CallbackURL != spOrigin+acsPath || r.SuccessCallback.String() != finish {
				t.Fatal("SAML start did not carry original configured flow")
			}
			actual, err := session.ParseToken(r.Browser.FlowCookie.Token())
			if digest, digestErr := actual.PreAuthDigest(key, stored.Binding); err != nil || digestErr != nil || digest != stored.Cookie {
				t.Fatal("native start did not receive the bearer for the actual committed flow")
			}
			id, _ := identity.NewCommandID()
			b := identity.CommandBinding{CommandID: id, TenantID: testTenant, AnonymousFlowID: string(stored.Binding.ID), ActorID: "sso-login", ActorKind: authorization.SubjectServiceAccount,
				OperationID: startOp.OperationID, SchemaID: startOp.SchemaID, SchemaVersion: 1, PolicyID: "signin-policy", PolicyVersion: 1, CorrelationID: "start", RecordID: string(id)}
			u, _ := url.Parse(idpOrigin + "/login?SAMLRequest=YQ%3D%3D&RelayState=" + state + "&SigAlg=fixture&Signature=YQ%3D%3D")
			return sso.SigninStartResult{ProviderID: provider, Protocol: "saml", TransactionID: string(id), RedirectURI: *u,
				Completion: identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "start", Feature: &identity.FeatureReceipt{Operation: startOp, AfterVersion: 1}}}, nil
		},
		source: func(r SAMLSigninCallbackRequest) (SigninCallbackRateContext, error) {
			sourceCalls++
			if r.TenantID != testTenant || r.ProviderID != provider || r.Browser.FlowID != "" || r.Browser.FlowCookie.Token() != initialBrowser.FlowCookie.Token() ||
				r.Browser.Device != initialBrowser.Device || r.RelayState != state || r.ReceivedAssertionConsumerURL != spOrigin+acsPath || r.SAMLResponse != "" {
				t.Fatal("callback did not retain exact original transport custody")
			}
			if !allowSource {
				return SigninCallbackRateContext{}, identity.ForbiddenError{}
			}
			return SigninCallbackRateContext{ProviderID: provider, FlowID: stored.Binding.ID, TransactionID: string(command), Lifetime: 5 * time.Minute}, nil
		},
		complete: func(r SAMLSigninCallbackRequest) (SigninCallbackResult, error) {
			completeCalls++
			if r.Browser.FlowID != stored.Binding.ID || r.SAMLResponse != assertion {
				t.Fatal("callback did not receive original native flow and untouched form member")
			}
			return enterpriseIssueFixtureForOperation(t, SigninCallbackConfig{Browser: SigninBrowserConfig{TenantID: testTenant, Now: discovery.Now}, Audience: config.Audience, Cookie: auth, CSRFCookie: csrf, CallbackAllowlist: []string{finish}}, stored.Binding.ID, command, acsOp, "sso-saml"), nil
		},
	}
	config.Start, config.Callback = probe, probe
	feature, err := NewSAMLSigninFeature(config)
	if err != nil {
		t.Fatal("construct selected SAML browser feature", err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	transport := identityhttp.TransportPolicy{Network: config.Network, HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}}
	transport.CORS = []identityhttp.CORSRoutePolicy{config.ACSNavigationPolicy()}
	wrongMode := transport
	acsPolicy := config.ACSNavigationPolicy()
	acsPolicy.Credentials = identityhttp.CORSCookieCredentials
	wrongMode.CORS = []identityhttp.CORSRoutePolicy{acsPolicy}
	if _, _, err := identityhttp.NewRouter(wrongMode, ops, nil); err == nil {
		t.Fatal("selected SAML ACS allowed a CORS grant mode")
	}
	router, docs, err := identityhttp.NewRouter(transport, ops, nil)
	if err != nil {
		t.Fatal("construct documented selected SAML routes", err)
	}
	if !strings.Contains(string(docs.JSON()), "/saml2/{provider_id}/acs") || !strings.Contains(string(docs.JSON()), "/saml2/{provider_id}/login") {
		t.Fatal("selected live paths missing from OpenAPI")
	}
	serve := func(method, path, origin, payload string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		var body io.Reader
		if payload != "" {
			body = strings.NewReader(payload)
		}
		r := httptest.NewRequest(method, spOrigin+path, body)
		r.RequestURI = r.URL.RequestURI()
		r.RemoteAddr = "192.0.2.17:32000"
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if method == http.MethodPost {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	navigate := func(site string, origin string, duplicateSite bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, spOrigin+startPath, nil)
		r.RequestURI = r.URL.RequestURI()
		r.RemoteAddr = "192.0.2.17:32000"
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if site != "" {
			r.Header.Set("Sec-Fetch-Site", site)
		}
		if duplicateSite {
			r.Header.Add("Sec-Fetch-Site", site)
		}
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Sec-Fetch-Dest", "document")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct {
		site, origin string
		duplicate    bool
	}{{"", "", false}, {"same-site", "", false}, {"cross-site", "", false}, {"none", "", false}, {"same-origin", "null", false}, {"same-origin", "", true}} {
		w := navigate(tc.site, tc.origin, tc.duplicate)
		if w.Code != 403 || w.Header().Get("Location") != "" || len(w.Result().Cookies()) != 0 {
			t.Fatalf("unproven browser navigation reached SAML start: site %q, status %d", tc.site, w.Code)
		}
	}
	login := navigate("same-origin", "", false)
	cookies := login.Result().Cookies()
	if login.Code != 303 || started != 1 || !strings.HasPrefix(login.Header().Get("Location"), idpOrigin+"/login?") || len(cookies) != 1 ||
		cookies[0].Name != "__Secure-identity_frontchannel" || cookies[0].Path != acsPath || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteNoneMode || cookies[0].MaxAge > 300 {
		t.Fatal("successful start did not emit only exact path-scoped correlation", login.Code)
	}
	payload := url.Values{"RelayState": {state}, "SAMLResponse": {assertion}}.Encode()
	deny := func(w *httptest.ResponseRecorder, status int) {
		t.Helper()
		if w.Code != status || w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Access-Control-Allow-Origin") != "" || strings.Contains(w.Body.String(), assertion) {
			t.Fatalf("denied SAML operation disclosed custody or returned %d instead of %d", w.Code, status)
		}
	}
	preflight := httptest.NewRequest(http.MethodOptions, spOrigin+acsPath, nil)
	preflight.RequestURI = preflight.URL.RequestURI()
	preflight.RemoteAddr = "192.0.2.17:32000"
	preflight.Header.Set("Origin", idpOrigin)
	preflight.Header.Set("Access-Control-Request-Method", "POST")
	preflightResult := httptest.NewRecorder()
	router.ServeHTTP(preflightResult, preflight)
	deny(preflightResult, 403)
	deny(serve(http.MethodPost, acsPath, idpOrigin, payload, normalDevice), 403)
	deny(serve(http.MethodPost, acsPath, "https://foreign.example", payload, cookies[0]), 403)
	deny(serve(http.MethodPost, acsPath, "", payload, cookies[0]), 403)
	deny(serve(http.MethodPost, acsPath+"?RelayState="+state, idpOrigin, payload, cookies[0]), 400)
	deny(serve(http.MethodPost, acsPath, idpOrigin, payload+"&relaystate="+state, cookies[0]), 400)
	deny(serve(http.MethodPost, acsPath, idpOrigin, payload+"&FlowID=foreign", cookies[0]), 400)
	deny(serve(http.MethodPost, acsPath, idpOrigin, payload, cookies[0], cookies[0]), 403)
	if sourceCalls != 0 || completeCalls != 0 {
		t.Fatal("untrusted origin, form or cookie reached the native locator")
	}
	callback := serve(http.MethodPost, acsPath, idpOrigin, payload, cookies[0])
	issued := callback.Result().Cookies()
	if callback.Code != 303 || callback.Header().Get("Location") != finish || callback.Header().Get("Access-Control-Allow-Origin") != "" || callback.Header().Get("Access-Control-Allow-Credentials") != "" || len(issued) != 3 ||
		issued[0].Name != "__Host-identity_session" || issued[0].SameSite != http.SameSiteLaxMode || issued[0].Value == "" ||
		issued[1].Name != "__Host-identity_csrf" || issued[1].Value == "" || issued[2].Name != cookies[0].Name || issued[2].Path != acsPath || issued[2].MaxAge >= 0 ||
		sourceCalls != 1 || completeCalls != 1 {
		t.Fatal("fresh native callback did not deliver session and remove only original correlation", callback.Code)
	}
	allowSource = false
	deny(serve(http.MethodPost, acsPath, idpOrigin, payload, cookies[0]), 403)
	if completeCalls != 1 {
		t.Fatal("terminal callback ran protected completion")
	}
}
