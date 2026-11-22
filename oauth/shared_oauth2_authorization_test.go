package oauth_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-identity/oauth"
)

func sharedOAuth2AuthorizationProfile() oauth.OAuth2UserInfoProfile {
	return oauth.OAuth2UserInfoProfile{
		Profile: sharedOAuth2QueryProfile(),
		Details: oauth.OAuth2UserInfoDetails{
			UserInfoEndpoint: "https://issuer.example/userinfo", SubjectClaim: "sub",
			SubjectEncoding: oauth.OAuth2StringSubject, ProofLifetime: 10 * time.Second,
		},
	}
}

func TestSharedOAuth2AuthorizationRendersExactSecretFreeFacts(t *testing.T) {
	parameters := oauth.AuthorizationParameters{State: testNonce, PKCEChallenge: strings.Repeat("B", 42) + "A"}
	for _, encoding := range []oauth.OAuth2SubjectEncoding{oauth.OAuth2StringSubject, oauth.OAuth2PositiveIntegerSubject} {
		t.Run(string(encoding), func(t *testing.T) {
			profile := sharedOAuth2AuthorizationProfile()
			profile.Details.SubjectEncoding = encoding
			profile.Profile.ClientID = "client:+ value"
			profile.Profile.RedirectURI = "https://app.example/shared/callback"
			request, err := oauth.SharedOAuth2Authorization(t.Context(), profile, parameters)
			if err != nil {
				t.Fatal(err)
			}
			want := "https://issuer.example/authorize?client_id=client%3A%2B+value&code_challenge=" + parameters.PKCEChallenge + "&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fapp.example%2Fshared%2Fcallback&response_mode=query&response_type=code&scope=profile+email&state=" + testNonce
			if request.URL() != want {
				t.Fatal("authorization did not retain the exact code/query/S256 wire request")
			}
		})
	}
}

func TestSharedOAuth2AuthorizationUsesCurrentProfileAndParameters(t *testing.T) {
	profile := sharedOAuth2AuthorizationProfile()
	parameters := oauth.AuthorizationParameters{State: testNonce, PKCEChallenge: testNonce}
	first, err := oauth.SharedOAuth2Authorization(t.Context(), profile, parameters)
	if err != nil {
		t.Fatal(err)
	}
	profile.Profile.Issuer = "https://replacement.example"
	profile.Profile.AuthorizationEndpoint = "https://replacement.example/signin"
	profile.Profile.TokenEndpoint = "https://replacement.example/token"
	profile.Details.UserInfoEndpoint = "https://replacement.example/identity"
	profile.Profile.ClientID = "replacement-client"
	profile.Profile.RedirectURI = "https://app.example/other-callback"
	profile.Profile.Scopes[0] = "replacement-scope"
	parameters.State = strings.Repeat("B", 42) + "A"
	parameters.PKCEChallenge = strings.Repeat("C", 42) + "A"
	second, err := oauth.SharedOAuth2Authorization(t.Context(), profile, parameters)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(second.URL())
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != profile.Profile.AuthorizationEndpoint || query.Get("client_id") != profile.Profile.ClientID || query.Get("redirect_uri") != profile.Profile.RedirectURI || query.Get("scope") != "replacement-scope email" || query.Get("state") != parameters.State || query.Get("code_challenge") != parameters.PKCEChallenge || len(query) != 8 {
		t.Fatal("authorization substituted or retained facts from an earlier request")
	}
	if strings.Contains(first.URL(), "replacement") || !strings.Contains(first.URL(), "scope=profile+email") {
		t.Fatal("later caller mutation changed the earlier authorization request")
	}
}

func requireSharedOAuth2AuthorizationError(t *testing.T, ctx context.Context, profile oauth.OAuth2UserInfoProfile, parameters oauth.AuthorizationParameters, kind oauth.ErrorKind) error {
	t.Helper()
	request, err := oauth.SharedOAuth2Authorization(ctx, profile, parameters)
	var classified *oauth.Error
	if !errors.As(err, &classified) || classified.Kind() != kind || request.URL() != "" {
		t.Fatal("rejected authorization retained a URL or lost its error classification")
	}
	return err
}

func TestSharedOAuth2AuthorizationRejectsUnsupportedFactsAndParameters(t *testing.T) {
	parameters := oauth.AuthorizationParameters{State: testNonce, PKCEChallenge: testNonce}
	for name, change := range map[string]func(*oauth.OAuth2UserInfoProfile){
		"zero profile":    func(p *oauth.OAuth2UserInfoProfile) { *p = oauth.OAuth2UserInfoProfile{} },
		"missing version": func(p *oauth.OAuth2UserInfoProfile) { p.Profile.Version = 0 },
		"foreign authorization": func(p *oauth.OAuth2UserInfoProfile) {
			p.Profile.AuthorizationEndpoint = "https://other.example/authorize"
		},
		"foreign token":          func(p *oauth.OAuth2UserInfoProfile) { p.Profile.TokenEndpoint = "https://other.example/token" },
		"foreign identity":       func(p *oauth.OAuth2UserInfoProfile) { p.Details.UserInfoEndpoint = "https://other.example/userinfo" },
		"authorization query":    func(p *oauth.OAuth2UserInfoProfile) { p.Profile.AuthorizationEndpoint += "?extra=1" },
		"insecure redirect":      func(p *oauth.OAuth2UserInfoProfile) { p.Profile.RedirectURI = "http://app.example/callback" },
		"missing client":         func(p *oauth.OAuth2UserInfoProfile) { p.Profile.ClientID = "" },
		"public client":          func(p *oauth.OAuth2UserInfoProfile) { p.Profile.ClientAuthentication = oauth.PublicClient },
		"openid scope":           func(p *oauth.OAuth2UserInfoProfile) { p.Profile.Scopes = []string{"openid"} },
		"duplicate scope":        func(p *oauth.OAuth2UserInfoProfile) { p.Profile.Scopes = []string{"profile", "profile"} },
		"nonce profile":          func(p *oauth.OAuth2UserInfoProfile) { p.Profile.NonceRequired = true },
		"wrong response mode":    func(p *oauth.OAuth2UserInfoProfile) { p.Profile.ResponseMode = "fragment" },
		"plain PKCE":             func(p *oauth.OAuth2UserInfoProfile) { p.Profile.PKCEMethod = "plain" },
		"credential claim":       func(p *oauth.OAuth2UserInfoProfile) { p.Details.SubjectClaim = "access_token" },
		"missing subject claim":  func(p *oauth.OAuth2UserInfoProfile) { p.Details.SubjectClaim = "" },
		"unknown subject kind":   func(p *oauth.OAuth2UserInfoProfile) { p.Details.SubjectEncoding = "unknown" },
		"unbounded proof":        func(p *oauth.OAuth2UserInfoProfile) { p.Details.ProofLifetime = 21 * time.Second },
		"missing proof lifetime": func(p *oauth.OAuth2UserInfoProfile) { p.Details.ProofLifetime = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			profile := sharedOAuth2AuthorizationProfile()
			change(&profile)
			requireSharedOAuth2AuthorizationError(t, t.Context(), profile, parameters, oauth.InvalidInput)
		})
	}
	for name, invalid := range map[string]oauth.AuthorizationParameters{
		"nonce":              {State: testNonce, PKCEChallenge: testNonce, Nonce: testNonce},
		"missing state":      {PKCEChallenge: testNonce},
		"padded state":       {State: testNonce + "=", PKCEChallenge: testNonce},
		"noncanonical state": {State: strings.Repeat("B", 43), PKCEChallenge: testNonce},
		"missing challenge":  {State: testNonce},
		"padded challenge":   {State: testNonce, PKCEChallenge: testNonce + "="},
		"noncanonical S256":  {State: testNonce, PKCEChallenge: strings.Repeat("B", 43)},
	} {
		t.Run(name, func(t *testing.T) {
			requireSharedOAuth2AuthorizationError(t, t.Context(), sharedOAuth2AuthorizationProfile(), invalid, oauth.InvalidInput)
		})
	}
}

func TestSharedOAuth2AuthorizationCancellationAndNilContext(t *testing.T) {
	profile := sharedOAuth2AuthorizationProfile()
	parameters := oauth.AuthorizationParameters{State: testNonce, PKCEChallenge: testNonce}
	requireSharedOAuth2AuthorizationError(t, nil, profile, parameters, oauth.InvalidInput)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	err := requireSharedOAuth2AuthorizationError(t, cancelled, profile, parameters, oauth.Unavailable)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("authorization lost cancellation cause")
	}
	expired, expire := context.WithDeadline(t.Context(), time.Unix(1, 0))
	defer expire()
	err = requireSharedOAuth2AuthorizationError(t, expired, profile, parameters, oauth.Unavailable)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("authorization lost deadline cause")
	}
}

func TestSharedOAuth2AuthorizationPreservesExistingInstanceBehavior(t *testing.T) {
	profile := sharedOAuth2AuthorizationProfile()
	parameters := oauth.AuthorizationParameters{State: testNonce, PKCEChallenge: testNonce}
	config := oauth.OAuth2UserInfoConfig{
		ID: profile.Profile.ID, Version: profile.Profile.Version, Issuer: profile.Profile.Issuer,
		AuthorizationEndpoint: profile.Profile.AuthorizationEndpoint, TokenEndpoint: profile.Profile.TokenEndpoint,
		UserInfoEndpoint: profile.Details.UserInfoEndpoint, RedirectURI: profile.Profile.RedirectURI,
		ClientID: profile.Profile.ClientID, ClientSecret: []byte("test-only-client-secret"),
		ClientAuthentication: oauth.ClientSecretPost, Scopes: profile.Profile.Scopes,
		SubjectClaim: profile.Details.SubjectClaim, SubjectEncoding: oauth.OAuth2StringSubject,
		ProofLifetime: profile.Details.ProofLifetime, Timeout: profile.Profile.Timeout,
	}
	shared, err := oauth.NewSharedOAuth2UserInfoProvider(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(shared.Close)
	if social, err := oauth.NewOAuth2UserInfoProvider(config); err == nil || social != nil {
		if social != nil {
			social.Close()
		}
		t.Fatal("shared string-subject facts broadened distinct social behavior")
	}
	config.SubjectEncoding = oauth.OAuth2PositiveIntegerSubject
	social, err := oauth.NewOAuth2UserInfoProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(social.Close)
	want, err := oauth.SharedOAuth2Authorization(t.Context(), profile, parameters)
	if err != nil {
		t.Fatal(err)
	}
	for name, instance := range map[string]interface {
		Authorization(context.Context, oauth.AuthorizationParameters) (oauth.AuthorizationRequest, error)
		Close()
	}{"shared": shared, "social": social} {
		t.Run(name, func(t *testing.T) {
			got, err := instance.Authorization(t.Context(), parameters)
			if err != nil || got.URL() != want.URL() {
				t.Fatal("existing instance changed authorization output")
			}
			instance.Close()
			got, err = instance.Authorization(t.Context(), parameters)
			var classified *oauth.Error
			if !errors.As(err, &classified) || classified.Kind() != oauth.InvalidInput || got.URL() != "" {
				t.Fatal("closed instance retained authorization capability")
			}
		})
	}
}
