package oauth_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
)

func signinStartRequest(t *testing.T) oauth.SigninStartRequest {
	t.Helper()
	link := linkStartRequest(t)
	remember, err := session.ResolveRememberPolicy(session.PersistentSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return oauth.SigninStartRequest{TenantID: link.TenantID, Provider: link.Provider, Callback: link.Callback, ErrorCallback: link.ErrorCallback, Scopes: link.Scopes, SignupDisabled: true, IdempotencyKey: link.IdempotencyKey, FlowID: "AAAAAAAAAAAAAAAAAAAAAQ", FlowCookie: link.Session, Remember: remember,
		Origin: link.Origin, Network: link.Network, Device: "original-browser-device",
		Caller: authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: "tenant-a", Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "oauth-login"}, Action: "identity.oauth.signin-start", Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: "AAAAAAAAAAAAAAAAAAAAAQ"}}},
	}
}

func TestSigninStartRequiresOriginalFlowAndResolvedRemember(t *testing.T) {
	original := signinStartRequest(t)
	if err := original.Validate(); err != nil {
		t.Fatal("complete existing-account signin request denied", err)
	}
	for name, change := range map[string]func(*oauth.SigninStartRequest){
		"missing original flow": func(r *oauth.SigninStartRequest) { r.FlowID = "" },
		"changed flow":          func(r *oauth.SigninStartRequest) { r.FlowID = "another-flow" },
		"noncanonical flow": func(r *oauth.SigninStartRequest) {
			r.FlowID = "original-flow"
			r.Caller.Request.Resource.ID = "original-flow"
		},
		"human subject":            func(r *oauth.SigninStartRequest) { r.Caller.Request.Subject.Kind = authorization.SubjectUser },
		"selected user resource":   func(r *oauth.SigninStartRequest) { r.Caller.Request.Resource.Type = "identity.user" },
		"foreign tenant":           func(r *oauth.SigninStartRequest) { r.TenantID = "another-tenant" },
		"link initiation":          func(r *oauth.SigninStartRequest) { r.Caller.Request.Action = "identity.account.link-start" },
		"no policy revision":       func(r *oauth.SigninStartRequest) { r.Caller.PolicyRevision = 0 },
		"no remember policy":       func(r *oauth.SigninStartRequest) { r.Remember = session.RememberPolicy{} },
		"implicit signup":          func(r *oauth.SigninStartRequest) { r.SignupDisabled = false },
		"no browser cookie":        func(r *oauth.SigninStartRequest) { r.FlowCookie = auth.BearerCredential{} },
		"no browser device":        func(r *oauth.SigninStartRequest) { r.Device = "" },
		"unbounded browser device": func(r *oauth.SigninStartRequest) { r.Device = strings.Repeat("d", 129) },
		"padded browser cookie":    func(r *oauth.SigninStartRequest) { r.FlowCookie = auth.NewBearerCredential(r.FlowCookie.Token() + "=") },
		"no request custody":       func(r *oauth.SigninStartRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		"omitted scopes":           func(r *oauth.SigninStartRequest) { r.Scopes = oauth.ScopeSet{} },
		"omitted callback":         func(r *oauth.SigninStartRequest) { r.Callback = oauth.ValidatedCallbackURL{} },
		"omitted error callback":   func(r *oauth.SigninStartRequest) { r.ErrorCallback = oauth.ValidatedCallbackURL{} },
		"origin path":              func(r *oauth.SigninStartRequest) { r.Origin += "/" },
		"origin query":             func(r *oauth.SigninStartRequest) { r.Origin += "?changed=1" },
		"network port":             func(r *oauth.SigninStartRequest) { r.Network += ":443" },
		"network zone":             func(r *oauth.SigninStartRequest) { r.Network = "fe80::1%en0" },
	} {
		t.Run(name, func(t *testing.T) {
			request := original
			change(&request)
			if request.Validate() == nil {
				t.Fatal("ambiguous or unselected signin admitted")
			}
		})
	}
}

func TestSigninStartDoesNotDiscloseBorrowedCustody(t *testing.T) {
	request := signinStartRequest(t)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
		text := fmt.Sprintf(verb, request)
		if strings.Contains(text, request.FlowCookie.Token()) || strings.Contains(text, string(request.TenantID)) || strings.Contains(text, string(request.FlowID)) {
			t.Fatal("signin input escaped diagnostic redaction")
		}
	}
	if wire, err := json.Marshal(request); err == nil || len(wire) != 0 {
		t.Fatal("signin input serialized original flow custody")
	}
}
