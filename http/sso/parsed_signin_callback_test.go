package ssohttp

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
)

type parsedCallbackObservation struct {
	t       *testing.T
	profile oauth.ProviderProfile
	parsed  oauth.QueryCallback
	request SigninCallbackRequest
	calls   int
	err     error
}

func (p *parsedCallbackObservation) observe(ctx context.Context, request SigninCallbackRequest, parsed oauth.QueryCallback) {
	p.t.Helper()
	p.calls++
	p.parsed, p.request = parsed, request
	input, success := parsed.Input()
	if !success || parsed.Denied() || parsed.Profile().ClientID != p.profile.ClientID || parsed.Profile().Issuer != p.profile.Issuer {
		p.t.Fatal("typed owner did not receive the admitted parser profile and success variant")
	}
	err := input.Use(ctx, func(ctx context.Context, code, state []byte) error {
		if string(code) != "fixture-code+/%" || string(state) != parsedCallbackState() {
			p.t.Error("typed owner did not receive exact decoded callback bytes")
		}
		if err := request.Input.Use(ctx, func(context.Context, []byte, []byte) error { return nil }); !errors.Is(err, identity.ErrInvalidOAuthCallbackInput) {
			p.t.Error("typed callback and transport request did not share original custody")
		}
		return nil
	})
	if err != nil {
		p.t.Fatal("callback custody was not live during completion", err)
	}
	if err := request.Input.Use(ctx, func(context.Context, []byte, []byte) error { return nil }); err != nil {
		p.t.Fatal("transport request custody was not live after the parsed borrow", err)
	}
}

type parsedSigninCallbackProbe struct {
	*signinCallbackProbe
	observation *parsedCallbackObservation
}

func (p *parsedSigninCallbackProbe) CompleteParsedSSOOIDC(ctx context.Context, request SigninCallbackRequest, parsed oauth.QueryCallback) (SigninCallbackResult, error) {
	p.observation.observe(ctx, request, parsed)
	return p.result, p.observation.err
}

type parsedMemberCallbackProbe struct {
	*memberCallbackProbe
	observation *parsedCallbackObservation
}

func (p *parsedMemberCallbackProbe) CompleteParsedSSOOIDCLink(ctx context.Context, request SigninCallbackRequest, cookie authentication.BearerCredential, parsed oauth.QueryCallback) (MemberLinkCallbackResult, error) {
	p.observation.observe(ctx, request, parsed)
	if cookie.Token() != strings.Repeat("A", 43) || request.Browser.FlowID != "" {
		p.observation.t.Error("typed member completion lost its admitted member credential or selected sign-in")
	}
	return MemberLinkCallbackResult{CommandID: p.command, RedirectURI: "https://tenant.example/ok"}, p.observation.err
}

func TestParsedSigninCallbackDispatchAndCustody(t *testing.T) {
	for _, mode := range []string{"signin", "shared signin", "member link"} {
		for _, completion := range []string{"parsed success", "parsed error", "legacy"} {
			t.Run(mode+"/"+completion, func(t *testing.T) {
				browser, authCookie, device := memberLinkTransportFixture(t)
				csrf, err := session.NewCSRFCookiePolicy(session.CookieConfig{Name: "__Host-identity_csrf", SameSite: http.SameSiteLaxMode})
				if err != nil {
					t.Fatal(err)
				}
				command, err := identity.NewCommandID()
				if err != nil {
					t.Fatal(err)
				}
				var flow identity.PreAuthTransactionID
				if mode != "member link" {
					flow, err = identity.NewPreAuthTransactionID()
					if err != nil {
						t.Fatal(err)
					}
				}
				legacy := &signinCallbackProbe{flow: flow, transaction: command}
				member := &memberCallbackProbe{command: command, flow: flow}
				config := SigninCallbackConfig{
					Browser: browser, Cookie: authCookie, CSRFCookie: csrf, Audience: "enterprise-app", Callback: legacy,
					CallbackAllowlist: []string{"https://tenant.example/ok"},
					Provider: oauth.ProviderProfile{ID: "approved-oidc", Version: 1, Issuer: "https://provider.example",
						AuthorizationEndpoint: "https://provider.example/authorize", TokenEndpoint: "https://provider.example/token",
						RedirectURI: "https://tenant.example/sso/oidc/callback", ClientID: "parsed-transport-client",
						ClientAuthentication: oauth.ClientSecretBasic, Scopes: []string{"openid"}, Algorithms: []string{"ES256"},
						ResponseMode: "query", PKCEMethod: "S256", NonceRequired: true, StateBytes: 32, NonceBytes: 32,
						Timeout: time.Second, ClockSkew: time.Second, MaxResponseBytes: 4096, MaxTokenBytes: 1024, MaxCodeBytes: 512},
				}
				if mode != "member link" {
					legacy.result = enterpriseIssueFixture(t, config, flow, command)
				}
				observation := &parsedCallbackObservation{t: t, profile: config.Provider}
				if completion == "parsed error" {
					observation.err = identity.ForbiddenError{}
				}
				var link MemberLinkCallbackOwner = member
				if completion != "legacy" {
					config.Callback = &parsedSigninCallbackProbe{signinCallbackProbe: legacy, observation: observation}
					link = &parsedMemberCallbackProbe{memberCallbackProbe: member, observation: observation}
				}
				var feature identityhttp.Feature
				if mode == "signin" {
					feature, err = NewSigninCallbackFeature(config)
				} else {
					feature, err = NewSigninCallbackFeatureWithLink("approved-oidc", config, link)
				}
				if err != nil {
					t.Fatal(err)
				}
				router := memberLinkHandler(t, browser, feature)
				query := url.Values{"code": {"fixture-code+/%"}, "state": {parsedCallbackState()}, "iss": {config.Provider.Issuer}}.Encode()
				r := httptest.NewRequest(http.MethodGet, config.Provider.RedirectURI+"?"+query, nil)
				r.RequestURI, r.RemoteAddr = r.URL.RequestURI(), "192.0.2.17:32000"
				if flow != "" {
					r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
				}
				// Both cookies on shared sign-in must not select member linking.
				if mode != "signin" {
					r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: strings.Repeat("A", 43)})
				}
				r.AddCookie(device)
				w := httptest.NewRecorder()
				router.ServeHTTP(w, r)
				if completion == "parsed error" {
					if w.Code != http.StatusForbidden || w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" {
						t.Fatalf("typed error changed denial or delivered credentials: status=%d", w.Code)
					}
				} else {
					cookies := 2
					if mode == "member link" {
						cookies = 0
					}
					if w.Code != http.StatusSeeOther || w.Header().Get("Location") != config.CallbackAllowlist[0] || len(w.Result().Cookies()) != cookies || w.Body.Len() != 0 {
						t.Fatalf("completion changed scoped delivery: status=%d", w.Code)
					}
				}
				if completion == "legacy" {
					wantSignin, wantMember := 1, 0
					if mode == "member link" {
						wantSignin, wantMember = 0, 1
					}
					if observation.calls != 0 || legacy.calls != wantSignin || member.calls != wantMember {
						t.Fatal("owner without the optional interface did not use exactly its legacy completion")
					}
				} else {
					if observation.calls != 1 || legacy.calls != 0 || member.calls != 0 {
						t.Fatalf("typed completion was omitted or fell back: typed=%d signin=%d member=%d", observation.calls, legacy.calls, member.calls)
					}
					if observation.request.TenantID != testTenant || observation.request.Browser.FlowID != flow || observation.request.ReceivedRedirectURI != config.Provider.RedirectURI {
						t.Fatal("typed owner did not receive the original admitted transport scope")
					}
					input, _ := observation.parsed.Input()
					if err := input.Use(t.Context(), func(context.Context, []byte, []byte) error { return nil }); !errors.Is(err, identity.ErrInvalidOAuthCallbackInput) {
						t.Fatal("parsed callback survived handler return")
					}
					if err := observation.request.Input.Use(t.Context(), func(context.Context, []byte, []byte) error { return nil }); !errors.Is(err, identity.ErrInvalidOAuthCallbackInput) {
						t.Fatal("request callback alias survived handler return")
					}
				}
			})
		}
	}
}

func parsedCallbackState() string {
	return base64.RawURLEncoding.EncodeToString(make([]byte, 32))
}
