package oauth_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
)

func linkStartRequest(t *testing.T) oauth.LinkStartRequest {
	t.Helper()
	callback, err := oauth.NewValidatedCallbackURL("https://app.example/linked", []string{"https://app.example/linked"})
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.ParseCSRFToken(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("original-link-attempt"))
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := oauth.NewScopeSet([]string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	return oauth.LinkStartRequest{
		TenantID: "tenant-a", Provider: "generic", Callback: callback, ErrorCallback: callback,
		Scopes: scopes, SignupDisabled: true, IdempotencyKey: key,
		Session: auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))), CSRFToken: csrf,
		Caller: authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{
			Tenant: "tenant-a", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user-a"},
			Action: "identity.account.link-start", Resource: authorization.Resource{Type: "identity.user", ID: "user-a"},
		}}, Origin: "https://app.example", Network: "192.0.2.12",
	}
}

func TestLinkStartRejectsCrossSubjectAndAmbiguousTransport(t *testing.T) {
	original := linkStartRequest(t)
	if err := original.Validate(); err != nil {
		t.Fatal("complete explicit-self request rejected", err)
	}
	for name, mutate := range map[string]func(*oauth.LinkStartRequest){
		"tenant":                 func(r *oauth.LinkStartRequest) { r.TenantID = "tenant-b" },
		"subject":                func(r *oauth.LinkStartRequest) { r.Caller.Request.Subject.ID = "user-b" },
		"resource":               func(r *oauth.LinkStartRequest) { r.Caller.Request.Resource.ID = "user-b" },
		"service actor":          func(r *oauth.LinkStartRequest) { r.Caller.Request.Subject.Kind = authorization.SubjectServiceAccount },
		"operation":              func(r *oauth.LinkStartRequest) { r.Caller.Request.Action = "identity.oauth.signin-start" },
		"resource kind":          func(r *oauth.LinkStartRequest) { r.Caller.Request.Resource.Type = "identity.account" },
		"revision":               func(r *oauth.LinkStartRequest) { r.Caller.PolicyRevision = 0 },
		"missing retry key":      func(r *oauth.LinkStartRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		"missing synchronizer":   func(r *oauth.LinkStartRequest) { r.CSRFToken = session.CSRFToken{} },
		"missing session":        func(r *oauth.LinkStartRequest) { r.Session = auth.BearerCredential{} },
		"padded session":         func(r *oauth.LinkStartRequest) { r.Session = auth.NewBearerCredential(r.Session.Token() + "=") },
		"origin path":            func(r *oauth.LinkStartRequest) { r.Origin += "/" },
		"origin query":           func(r *oauth.LinkStartRequest) { r.Origin += "?other=1" },
		"origin downgrade":       func(r *oauth.LinkStartRequest) { r.Origin = "http://app.example" },
		"signup selection":       func(r *oauth.LinkStartRequest) { r.SignupDisabled = false },
		"omitted scopes":         func(r *oauth.LinkStartRequest) { r.Scopes = oauth.ScopeSet{} },
		"omitted callback":       func(r *oauth.LinkStartRequest) { r.Callback = oauth.ValidatedCallbackURL{} },
		"omitted error callback": func(r *oauth.LinkStartRequest) { r.ErrorCallback = oauth.ValidatedCallbackURL{} },
		"network port":           func(r *oauth.LinkStartRequest) { r.Network += ":1234" },
		"network zone":           func(r *oauth.LinkStartRequest) { r.Network = "fe80::1%en0" },
		"network noncanonical":   func(r *oauth.LinkStartRequest) { r.Network = "2001:0db8::1" },
		"network unspecified":    func(r *oauth.LinkStartRequest) { r.Network = "0.0.0.0" },
		"network multicast":      func(r *oauth.LinkStartRequest) { r.Network = "ff02::1" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := original
			mutate(&changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("unsupported request entered the linking profile")
			}
		})
	}
	for _, address := range []string{"192.0.2.12", "2001:db8::12"} {
		r := original
		r.Network = address
		if err := r.Validate(); err != nil {
			t.Fatal("canonical client address rejected", err)
		}
	}
	for _, value := range []any{original, oauth.LinkStartResult{RedirectURI: original.Callback.URL()}} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("correlated linking input or redirect serialized implicitly")
		}
		if text := fmt.Sprintf("%#v %s %v", value, value, value); strings.Contains(text, original.Session.Token()) || strings.Contains(text, "app.example") {
			t.Fatal("linking diagnostics exposed browser correlation")
		}
	}
}

func TestLinkCallbackURLsAreExactAllowlistedValues(t *testing.T) {
	allowed := []string{"https://app.example/linked", "https://app.example/link-error?reason=provider"}
	for _, raw := range allowed {
		callback, err := oauth.NewValidatedCallbackURL(raw, allowed)
		value := callback.URL()
		if err != nil || value.String() != raw {
			t.Fatal("exact registered callback changed", err)
		}
		if _, err := json.Marshal(callback); err == nil || strings.Contains(fmt.Sprintf("%#v", callback), "app.example") {
			t.Fatal("callback correlation escaped diagnostic boundary")
		}
	}
	for _, raw := range []string{"", "http://app.example/linked", "https://app.example/linked#fragment", "https://actor@app.example/linked", "https://app.example/linked/", "https://APP.example/linked", "//app.example/linked", "https://app.example\\@evil.example/linked", "https://app.example/linked\n"} {
		if _, err := oauth.NewValidatedCallbackURL(raw, allowed); err == nil {
			t.Fatal("callback accepted an unregistered or unsafe URL")
		}
	}
	if _, err := oauth.NewValidatedCallbackURL(allowed[0], nil); err == nil {
		t.Fatal("empty allowlist permitted redirect")
	}
	zero := (oauth.ValidatedCallbackURL{}).URL()
	if zero.String() != "" {
		t.Fatal("zero callback produced a redirect")
	}
}

func TestLinkScopesPreserveExplicitEmptyAndDefendOwnedValues(t *testing.T) {
	input := []string{"openid", "profile"}
	scopes, err := oauth.NewScopeSet(input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = "admin"
	output := scopes.Values()
	output[0] = "admin"
	if strings.Join(scopes.Values(), " ") != "openid profile" {
		t.Fatal("scope aliases rewrote caller intent")
	}
	empty, err := oauth.NewScopeSet(nil)
	if err != nil || !empty.Valid() || empty.Values() == nil || (oauth.ScopeSet{}).Valid() {
		t.Fatal("explicit empty scope set was conflated with omitted input")
	}
	for _, input := range [][]string{{"openid", "openid"}, {""}, {"open id"}, {"openid\n"}, {"openid\\admin"}, {strings.Repeat("x", 129)}, make([]string, 65)} {
		if _, err := oauth.NewScopeSet(input); err == nil {
			t.Fatal("malformed or duplicate scope set accepted")
		}
	}
}
