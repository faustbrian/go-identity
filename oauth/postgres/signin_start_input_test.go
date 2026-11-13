package postgres

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
)

func signinBrowserFixture(t *testing.T) (oauth.SigninStartRequest, session.PreAuthTransaction, session.DigestKey, time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	remember, err := session.ResolveRememberPolicy(session.PersistentSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	key, err := session.NewDigestKey(1, bytes.Repeat([]byte{83}, 32))
	if err != nil {
		t.Fatal(err)
	}
	tokenWire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{84}, 32))
	token, err := session.ParseToken(tokenWire)
	if err != nil {
		t.Fatal(err)
	}
	binding := session.PreAuthBinding{ID: "AAAAAAAAAAAAAAAAAAAAAQ", Intent: session.PreAuthIntent{TenantID: "tenant", Action: "identity.oauth.callback", Origin: "https://app.example", CallbackURL: "https://app.example/complete", Nonce: [32]byte{1}, Remember: remember, PolicyID: "login", PolicyVersion: 1}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	digest, err := token.PreAuthDigest(key, binding)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: binding, Cookie: digest, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	callback, err := oauth.NewValidatedCallbackURL(binding.Intent.CallbackURL, []string{binding.Intent.CallbackURL})
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := oauth.NewScopeSet([]string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	requestKey, err := identity.NewIdempotencyKey([]byte("original-signin-key"))
	if err != nil {
		t.Fatal(err)
	}
	request := oauth.SigninStartRequest{TenantID: "tenant", Provider: "provider", Callback: callback, ErrorCallback: callback, Scopes: scopes, SignupDisabled: true, IdempotencyKey: requestKey, FlowID: binding.ID, FlowCookie: auth.NewBearerCredential(tokenWire), Remember: remember, Origin: binding.Intent.Origin, Network: "192.0.2.9", Device: "original-browser-device", Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: "tenant", Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "oauth-login"}, Action: "identity.oauth.signin-start", Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(binding.ID)}}}}
	return request, flow, key, now
}

func TestSigninStartAuthenticatesOriginalCallbackBrowser(t *testing.T) {
	r, flow, key, now := signinBrowserFixture(t)
	if err := checkSigninBrowser(r, flow, []session.DigestKey{key}, "login", 1, now); err != nil {
		t.Fatal("original callback-bound browser denied", err)
	}
	for name, change := range map[string]func(*oauth.SigninStartRequest){
		"other flow": func(r *oauth.SigninStartRequest) {
			r.FlowID = "another-flow"
			r.Caller.Request.Resource.ID = "another-flow"
		},
		"other tenant": func(r *oauth.SigninStartRequest) { r.TenantID = "other"; r.Caller.Request.Tenant = "other" },
		"other browser": func(r *oauth.SigninStartRequest) {
			r.FlowCookie = auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE")
		},
		"other remember": func(r *oauth.SigninStartRequest) {
			r.Remember, _ = session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
		},
		"other callback": func(r *oauth.SigninStartRequest) {
			r.Callback, _ = oauth.NewValidatedCallbackURL("https://app.example/other", []string{"https://app.example/other"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			change(&changed)
			if checkSigninBrowser(changed, flow, []session.DigestKey{key}, "login", 1, now) == nil {
				t.Fatal("changed original intent or possession admitted")
			}
		})
	}
	for _, at := range []time.Time{now.Add(-time.Nanosecond), now.Add(5 * time.Minute)} {
		if checkSigninBrowser(r, flow, []session.DigestKey{key}, "login", 1, at) == nil {
			t.Fatal("original exclusive browser lifetime was renewed")
		}
	}
	if checkSigninBrowser(r, flow, nil, "login", 1, now) == nil || checkSigninBrowser(r, flow, []session.DigestKey{key}, "other", 1, now) == nil || checkSigninBrowser(r, flow, []session.DigestKey{key}, "login", 2, now) == nil {
		t.Fatal("missing retained key or changed policy admitted")
	}
}
