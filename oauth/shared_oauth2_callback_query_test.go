package oauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-identity/oauth"
)

func sharedOAuth2QueryProfile() oauth.ProviderProfile {
	p := queryProfile()
	p.ClientAuthentication = oauth.ClientSecretPost
	p.Scopes = []string{"profile", "email"}
	p.Algorithms = nil
	p.NonceRequired = false
	p.NonceBytes = 0
	return p
}

func requireSharedOAuth2QueryError(t *testing.T, raw, redirect string, profile oauth.ProviderProfile) {
	t.Helper()
	parsed, err := oauth.ParseSharedOAuth2QueryCallback(context.Background(), raw, redirect, profile)
	defer parsed.Destroy()
	var classified *oauth.Error
	if !errors.As(err, &classified) || classified.Kind() != oauth.InvalidInput {
		t.Fatal("invalid shared callback did not return typed invalid input")
	}
	if _, success := parsed.Input(); success || parsed.Denied() || !reflect.DeepEqual(parsed.Profile(), oauth.ProviderProfile{}) {
		t.Fatal("invalid shared callback retained custody or provenance")
	}
}

func TestSharedOAuth2QueryCallbackRetainsExactCustodyAndProfile(t *testing.T) {
	ctx := context.Background()
	code := " exact +/=:; code "
	for _, member := range []string{"code=" + url.QueryEscape(code), "error=access_denied&error_description=private-description&error_uri=%2Fprivate-error"} {
		t.Run(strings.Split(member, "=")[0], func(t *testing.T) {
			profile := sharedOAuth2QueryProfile()
			want := profile
			want.Scopes = slices.Clone(profile.Scopes)
			parsed, err := oauth.ParseSharedOAuth2QueryCallback(ctx, queryResponse(member), profile.RedirectURI, profile)
			if err != nil {
				t.Fatal(err)
			}
			defer parsed.Destroy()
			alias := parsed
			profile.Scopes[0] = "changed"
			projection := parsed.Profile()
			projection.Scopes[0] = "changed-again"
			if !reflect.DeepEqual(parsed.Profile(), want) {
				t.Fatal("shared callback lost immutable exact profile provenance")
			}
			if _, selected := parsed.OAuth2Details(); selected || parsed.OAuth2TokenPolicy() != "" {
				t.Fatal("shared transport invented distinct-route exchange facts")
			}
			var borrowedCode, borrowedState []byte
			input, success := parsed.Input()
			if success {
				if parsed.Denied() {
					t.Fatal("shared callback variants overlap")
				}
				err = input.Use(ctx, func(_ context.Context, gotCode, state []byte) error {
					borrowedCode, borrowedState = gotCode, state
					if string(gotCode) != code || string(state) != testNonce || cap(gotCode) != len(gotCode) || cap(state) != len(state) {
						t.Fatal("shared success changed original bounded code/state bytes")
					}
					return nil
				})
			} else {
				if !parsed.Denied() {
					t.Fatal("shared provider refusal lost denial variant")
				}
				err = parsed.UseDeniedState(ctx, func(_ context.Context, state []byte) error {
					borrowedState = state
					if string(state) != testNonce || cap(state) != len(state) {
						t.Fatal("shared denial changed original bounded state bytes")
					}
					return nil
				})
			}
			if err != nil {
				t.Fatal("shared callback original custody unavailable", err)
			}
			for _, borrowed := range [][]byte{borrowedCode, borrowedState} {
				for _, b := range borrowed {
					if b != 0 {
						t.Fatal("shared callback borrow survived cleanup")
					}
				}
			}
			for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
				diagnostic := fmt.Sprintf(verb, parsed)
				for _, secret := range []string{code, testNonce, "private-description", "private-error"} {
					if strings.Contains(diagnostic, secret) {
						t.Fatal("shared callback diagnostic disclosed custody or error details")
					}
				}
			}
			if _, err := json.Marshal(parsed); err == nil {
				t.Fatal("shared callback serialized")
			}
			if _, err := parsed.MarshalText(); err == nil {
				t.Fatal("shared callback text serialized")
			}
			alias.Destroy()
			if success {
				err = input.Use(ctx, func(context.Context, []byte, []byte) error {
					t.Fatal("destroyed shared success admitted a borrow")
					return nil
				})
			} else {
				err = parsed.UseDeniedState(ctx, func(context.Context, []byte) error {
					t.Fatal("destroyed shared denial admitted a borrow")
					return nil
				})
			}
			if err == nil || !reflect.DeepEqual(parsed.Profile(), want) {
				t.Fatal("shared destruction did not clear aliases while retaining safe provenance")
			}
		})
	}
}

func TestSharedOAuth2QueryCallbackRequiresExactIssuerOnSuccessAndDenial(t *testing.T) {
	profile := sharedOAuth2QueryProfile()
	for _, member := range []string{"code=exact", "error=access_denied"} {
		base := member + "&state=" + testNonce
		for name, issuer := range map[string]string{
			"missing": "", "empty": "&iss=", "wrong": "&iss=https%3A%2F%2Fother.example",
			"host case": "&iss=https%3A%2F%2FISSUER.example", "trailing slash": "&iss=https%3A%2F%2Fissuer.example%2F",
			"invalid escape": "&iss=%", "invalid utf8": "&iss=%FF", "control": "&iss=https%3A%2F%2Fissuer.example%00",
			"duplicate":         "&iss=https%3A%2F%2Fissuer.example&iss=https%3A%2F%2Fissuer.example",
			"encoded duplicate": "&iss=https%3A%2F%2Fissuer.example&%69ss=https%3A%2F%2Fissuer.example",
		} {
			t.Run(strings.Split(member, "=")[0]+"/"+name, func(t *testing.T) {
				requireSharedOAuth2QueryError(t, base+issuer, profile.RedirectURI, profile)
			})
		}
		parsed, err := oauth.ParseSharedOAuth2QueryCallback(context.Background(), base+"&%69ss=%68ttps%3a%2f%2fissuer.example", profile.RedirectURI, profile)
		parsed.Destroy()
		if err != nil {
			t.Fatal("issuer was not compared after exactly one form decode", err)
		}
	}
}

func TestSharedOAuth2QueryCallbackRejectsOtherRoutesAndProfiles(t *testing.T) {
	profile := sharedOAuth2QueryProfile()
	for _, member := range []string{"code=exact", "error=access_denied"} {
		for _, redirect := range []string{"", profile.RedirectURI + "/", profile.RedirectURI + "?code=exact", "https://APP.example/callback", "https://other.example/callback"} {
			requireSharedOAuth2QueryError(t, queryResponse(member), redirect, profile)
		}
	}
	for name, change := range map[string]func(*oauth.ProviderProfile){
		"oidc":             func(p *oauth.ProviderProfile) { *p = queryProfile() },
		"zero":             func(p *oauth.ProviderProfile) { *p = oauth.ProviderProfile{} },
		"nonce":            func(p *oauth.ProviderProfile) { p.NonceRequired = true },
		"nonce bytes":      func(p *oauth.ProviderProfile) { p.NonceBytes = 32 },
		"openid":           func(p *oauth.ProviderProfile) { p.Scopes = []string{"openid"} },
		"algorithm":        func(p *oauth.ProviderProfile) { p.Algorithms = []string{"ES256"} },
		"response mode":    func(p *oauth.ProviderProfile) { p.ResponseMode = "form_post" },
		"pkce":             func(p *oauth.ProviderProfile) { p.PKCEMethod = "plain" },
		"foreign endpoint": func(p *oauth.ProviderProfile) { p.TokenEndpoint = "https://other.example/token" },
		"unbounded code":   func(p *oauth.ProviderProfile) { p.MaxCodeBytes = 65537 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := sharedOAuth2QueryProfile()
			change(&changed)
			requireSharedOAuth2QueryError(t, queryResponse("code=exact"), changed.RedirectURI, changed)
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, context := range []context.Context{nil, ctx} {
		parsed, err := oauth.ParseSharedOAuth2QueryCallback(context, queryResponse("code=exact"), profile.RedirectURI, profile)
		parsed.Destroy()
		var classified *oauth.Error
		if !errors.As(err, &classified) {
			t.Fatal("invalid context did not produce a typed error")
		}
		if context == nil && classified.Kind() != oauth.InvalidInput {
			t.Fatal("nil context was not invalid input")
		}
		if context != nil && (classified.Kind() != oauth.Unavailable || !errors.Is(err, context.Err())) {
			t.Fatal("shared callback lost cancellation classification")
		}
	}
}

func TestSharedOAuth2QueryCallbackRetainsParserBoundsAndVariantRules(t *testing.T) {
	profile := sharedOAuth2QueryProfile()
	profile.MaxCodeBytes = 1
	good := queryResponse("code=%20")
	parsed, err := oauth.ParseSharedOAuth2QueryCallback(context.Background(), good+"&extension=%E2%98%83", profile.RedirectURI, profile)
	parsed.Destroy()
	if err != nil {
		t.Fatal("bounded extension or exact code limit rejected", err)
	}
	for _, raw := range []string{
		"", "?" + good, good + "#fragment", queryResponse("code=%20%20"), queryResponse("code=%00"),
		good + "&%63ode=x", good + "&error=access_denied", good + "&error_description=conflict",
		good + "&state=" + testNonce, strings.Replace(good, testNonce, "not-canonical", 1),
		good + "&extension=%FF", good + "&extension=" + strings.Repeat("x", 4097),
		good + "&" + strings.Repeat("x", 65) + "=v", good + strings.Repeat("&x=v", 30),
		queryResponse("error="), queryResponse("error=access_denied&error_uri=%2Fbad%7Cpath"),
		good + "&extension=" + strings.Repeat("x", 3*profile.MaxCodeBytes+16*1024),
	} {
		requireSharedOAuth2QueryError(t, raw, profile.RedirectURI, profile)
	}
	for _, name := range []string{"access_token", "id_token", "token_type", "expires_in", "response"} {
		requireSharedOAuth2QueryError(t, good+"&"+name+"=unexpected", profile.RedirectURI, profile)
	}
}

func TestSharedOAuth2QueryCallbackCannotEnterExistingSocialOrOIDCFlows(t *testing.T) {
	profile := sharedOAuth2QueryProfile()
	distinct := oauth.OAuth2UserInfoProfile{Profile: profile, Details: oauth.OAuth2UserInfoDetails{
		UserInfoEndpoint: profile.Issuer + "/userinfo", SubjectClaim: "id", SubjectEncoding: oauth.OAuth2PositiveIntegerSubject, ProofLifetime: time.Second,
	}}
	start := linkStartRequest(t)
	signin := signinStartRequest(t)
	for _, member := range []string{"code=exact", "error=access_denied"} {
		parsed, err := oauth.ParseSharedOAuth2QueryCallback(context.Background(), queryResponse(member), profile.RedirectURI, profile)
		if err != nil {
			t.Fatal(err)
		}
		defer parsed.Destroy()
		link := oauth.CallbackRequest{Callback: parsed, TenantID: start.TenantID, Session: start.Session, Origin: start.Origin, Network: start.Network}
		login := oauth.SigninCallbackRequest{Callback: parsed, TenantID: signin.TenantID, FlowCookie: signin.FlowCookie, Origin: signin.Origin, Network: signin.Network, Device: signin.Device}
		if link.Validate() == nil || login.Validate() == nil {
			t.Fatal("shared transport callback entered a distinct social callback owner")
		}
		if result, err := oauth.ParseOAuth2QueryCallback(context.Background(), queryResponse(member), profile.RedirectURI, distinct); err == nil {
			result.Destroy()
			t.Fatal("distinct-route parser accepted the shared issuer profile")
		}
		if result, err := oauth.ParseQueryCallback(context.Background(), queryResponse(member), profile); err == nil {
			result.Destroy()
			t.Fatal("strict OIDC parser accepted nonce-free OAuth2 profile")
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	provider, err := oauth.NewOIDCProvider(providerConfig(t, server.URL, server.Client(), key))
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	parsed, err := oauth.ParseSharedOAuth2QueryCallback(context.Background(), queryResponse("code=exact"), profile.RedirectURI, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Destroy()
	input, _ := parsed.Input()
	result, err := provider.Exchange(context.Background(), input, verifier(t), "")
	defer result.Tokens.Destroy()
	var classified *oauth.Error
	if !errors.As(err, &classified) || classified.Kind() != oauth.InvalidInput || calls.Load() != 0 {
		t.Fatal("nonce-free shared transport was treated as an OIDC exchange")
	}
}

func FuzzSharedOAuth2QueryCallback(f *testing.F) {
	for _, raw := range []string{queryResponse("code=exact"), queryResponse("error=access_denied"), queryResponse("code=%FF"), queryResponse("code=exact") + "&%69ss=duplicate", "code=%"} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		profile := sharedOAuth2QueryProfile()
		profile.MaxCodeBytes = 128
		parsed, err := oauth.ParseSharedOAuth2QueryCallback(context.Background(), raw, profile.RedirectURI, profile)
		defer parsed.Destroy()
		input, success := parsed.Input()
		if err != nil {
			if success || parsed.Denied() {
				t.Fatal("invalid shared callback produced a variant")
			}
			return
		}
		if success == parsed.Denied() {
			t.Fatal("shared callback variant is ambiguous")
		}
		values := make(url.Values)
		for _, member := range strings.Split(raw, "&") {
			nameRaw, valueRaw, _ := strings.Cut(member, "=")
			name, nameErr := url.QueryUnescape(nameRaw)
			value, valueErr := url.QueryUnescape(valueRaw)
			if nameErr != nil || valueErr != nil {
				t.Fatal("shared callback admitted malformed form encoding")
			}
			values.Add(name, value)
		}
		if len(values["iss"]) != 1 || values.Get("iss") != profile.Issuer {
			t.Fatal("shared callback admitted an unbound issuer")
		}
		if _, selected := parsed.OAuth2Details(); selected {
			t.Fatal("shared parser minted distinct-route exchange facts")
		}
		if success {
			err = input.Use(context.Background(), func(_ context.Context, code, state []byte) error {
				if len(code) == 0 || len(code) > profile.MaxCodeBytes || string(code) != values.Get("code") || string(state) != values.Get("state") || len(state) != 43 {
					t.Fatal("shared success lost exact bounded custody")
				}
				return nil
			})
		} else {
			err = parsed.UseDeniedState(context.Background(), func(_ context.Context, state []byte) error {
				if string(state) != values.Get("state") || len(state) != 43 {
					t.Fatal("shared denial lost exact bounded state")
				}
				return nil
			})
		}
		if err != nil {
			t.Fatal("shared callback custody unavailable", err)
		}
	})
}
