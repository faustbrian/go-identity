package oauth_test

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-identity/oauth"
)

func oidcAuthorizationParameters() oauth.AuthorizationParameters {
	return oauth.AuthorizationParameters{
		State: strings.Repeat("A", 43), Nonce: strings.Repeat("B", 42) + "A",
		PKCEChallenge: strings.Repeat("C", 42) + "A",
	}
}

func TestOIDCAuthorizationRendersExactOriginalFacts(t *testing.T) {
	profile := queryProfile()
	profile.ClientID = "client:+ value"
	profile.Scopes = []string{"email", "openid", "profile"}
	parameters := oidcAuthorizationParameters()
	request, err := oauth.OIDCAuthorization(t.Context(), profile, parameters)
	if err != nil {
		t.Fatal(err)
	}
	want := "https://issuer.example/authorize?client_id=client%3A%2B+value&code_challenge=" + parameters.PKCEChallenge + "&code_challenge_method=S256&nonce=" + parameters.Nonce + "&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&response_mode=query&response_type=code&scope=email+openid+profile&state=" + parameters.State
	if request.URL() != want {
		t.Fatal("authorization changed the exact code/query/S256 wire request")
	}

	profile.AuthorizationEndpoint = "https://other.example/signin"
	profile.ClientID = "replacement-client"
	profile.RedirectURI = "https://app.example/other-callback"
	profile.Scopes[0] = "replacement-scope"
	parameters.State, parameters.Nonce = parameters.Nonce, parameters.State
	parameters.PKCEChallenge = strings.Repeat("D", 42) + "A"
	next, err := oauth.OIDCAuthorization(t.Context(), profile, parameters)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(next.URL())
	if err != nil {
		t.Fatal(err)
	}
	expected := url.Values{
		"client_id": {"replacement-client"}, "redirect_uri": {"https://app.example/other-callback"},
		"response_type": {"code"}, "response_mode": {"query"}, "scope": {"replacement-scope openid profile"},
		"state": {parameters.State}, "nonce": {parameters.Nonce},
		"code_challenge": {parameters.PKCEChallenge}, "code_challenge_method": {"S256"},
	}
	if parsed.Scheme != "https" || parsed.Host != "other.example" || parsed.Path != "/signin" || parsed.Fragment != "" || !reflect.DeepEqual(parsed.Query(), expected) {
		t.Fatal("authorization substituted or retained earlier facts")
	}
	if request.URL() != want {
		t.Fatal("later caller mutation changed the first authorization URL")
	}
}

func requireOIDCAuthorizationError(t *testing.T, ctx context.Context, profile oauth.ProviderProfile, parameters oauth.AuthorizationParameters, kind oauth.ErrorKind) error {
	t.Helper()
	request, err := oauth.OIDCAuthorization(ctx, profile, parameters)
	var classified *oauth.Error
	if !errors.As(err, &classified) || classified.Kind() != kind || request.URL() != "" {
		t.Fatal("rejected authorization retained a URL or lost its error classification")
	}
	return err
}

func TestOIDCAuthorizationRejectsUnsupportedProfile(t *testing.T) {
	for name, change := range map[string]func(*oauth.ProviderProfile){
		"zero":                   func(p *oauth.ProviderProfile) { *p = oauth.ProviderProfile{} },
		"missing ID":             func(p *oauth.ProviderProfile) { p.ID = "" },
		"noncanonical ID":        func(p *oauth.ProviderProfile) { p.ID = "Enterprise" },
		"missing version":        func(p *oauth.ProviderProfile) { p.Version = 0 },
		"insecure issuer":        func(p *oauth.ProviderProfile) { p.Issuer = "http://issuer.example" },
		"issuer alias":           func(p *oauth.ProviderProfile) { p.Issuer = "accounts.google.com" },
		"authorization query":    func(p *oauth.ProviderProfile) { p.AuthorizationEndpoint += "?extra=1" },
		"authorization user":     func(p *oauth.ProviderProfile) { p.AuthorizationEndpoint = "https://user@issuer.example/authorize" },
		"authorization fragment": func(p *oauth.ProviderProfile) { p.AuthorizationEndpoint += "#fragment" },
		"token query":            func(p *oauth.ProviderProfile) { p.TokenEndpoint += "?extra=1" },
		"redirect fragment":      func(p *oauth.ProviderProfile) { p.RedirectURI += "#fragment" },
		"missing client":         func(p *oauth.ProviderProfile) { p.ClientID = "" },
		"control in client":      func(p *oauth.ProviderProfile) { p.ClientID = "client\n" },
		"client too long":        func(p *oauth.ProviderProfile) { p.ClientID = strings.Repeat("x", 1025) },
		"unknown authentication": func(p *oauth.ProviderProfile) { p.ClientAuthentication = "unknown" },
		"missing openid":         func(p *oauth.ProviderProfile) { p.Scopes = []string{"profile"} },
		"duplicate scopes":       func(p *oauth.ProviderProfile) { p.Scopes = []string{"openid", "openid"} },
		"invalid scope":          func(p *oauth.ProviderProfile) { p.Scopes = []string{"openid", "two scopes"} },
		"missing algorithms":     func(p *oauth.ProviderProfile) { p.Algorithms = nil },
		"unsupported algorithm":  func(p *oauth.ProviderProfile) { p.Algorithms = []string{"HS256"} },
		"duplicate algorithms":   func(p *oauth.ProviderProfile) { p.Algorithms = []string{"ES256", "ES256"} },
		"fragment response":      func(p *oauth.ProviderProfile) { p.ResponseMode = "fragment" },
		"form post response":     func(p *oauth.ProviderProfile) { p.ResponseMode = "form_post" },
		"plain PKCE":             func(p *oauth.ProviderProfile) { p.PKCEMethod = "plain" },
		"nonce disabled":         func(p *oauth.ProviderProfile) { p.NonceRequired = false },
		"state size":             func(p *oauth.ProviderProfile) { p.StateBytes = 31 },
		"nonce size":             func(p *oauth.ProviderProfile) { p.NonceBytes = 33 },
		"default timeout":        func(p *oauth.ProviderProfile) { p.Timeout = 0 },
		"timeout too short":      func(p *oauth.ProviderProfile) { p.Timeout = time.Second - 1 },
		"timeout too long":       func(p *oauth.ProviderProfile) { p.Timeout = 30*time.Second + 1 },
		"default skew":           func(p *oauth.ProviderProfile) { p.ClockSkew = 0 },
		"skew too long":          func(p *oauth.ProviderProfile) { p.ClockSkew = 5*time.Minute + 1 },
		"response too short":     func(p *oauth.ProviderProfile) { p.MaxResponseBytes = 1023 },
		"response too long":      func(p *oauth.ProviderProfile) { p.MaxResponseBytes = 1<<20 + 1 },
		"token too short":        func(p *oauth.ProviderProfile) { p.MaxTokenBytes = 255 },
		"token too long":         func(p *oauth.ProviderProfile) { p.MaxTokenBytes = 16<<10 + 1 },
		"default code limit":     func(p *oauth.ProviderProfile) { p.MaxCodeBytes = 0 },
		"code too long":          func(p *oauth.ProviderProfile) { p.MaxCodeBytes = 64<<10 + 1 },
		"Google variant":         func(p *oauth.ProviderProfile) { p.Issuer, p.GoogleAccounts = googleIssuer, true },
	} {
		t.Run(name, func(t *testing.T) {
			profile := queryProfile()
			change(&profile)
			requireOIDCAuthorizationError(t, t.Context(), profile, oidcAuthorizationParameters(), oauth.InvalidInput)
		})
	}
}

func TestOIDCAuthorizationAcceptsNormalizedProfileBoundaries(t *testing.T) {
	for _, method := range []oauth.ClientAuthentication{oauth.PublicClient, oauth.ClientSecretBasic, oauth.ClientSecretPost} {
		for _, upper := range []bool{false, true} {
			profile := queryProfile()
			profile.ClientAuthentication = method
			profile.ClockSkew, profile.MaxResponseBytes, profile.MaxTokenBytes, profile.MaxCodeBytes = time.Nanosecond, 1024, 256, 1
			if upper {
				profile.Timeout, profile.ClockSkew = 30*time.Second, 5*time.Minute
				profile.MaxResponseBytes, profile.MaxTokenBytes, profile.MaxCodeBytes = 1<<20, 16<<10, 64<<10
				profile.Algorithms = []string{"RS256", "ES256"}
			}
			if request, err := oauth.OIDCAuthorization(t.Context(), profile, oidcAuthorizationParameters()); err != nil || request.URL() == "" {
				t.Fatal("normalized supported profile boundary was rejected", err)
			}
		}
	}
}

func TestOIDCAuthorizationRejectsMalformedParameters(t *testing.T) {
	for _, field := range []string{"state", "nonce", "challenge"} {
		for name, value := range map[string]string{
			"missing": "", "padded": testNonce + "=", "short": strings.Repeat("A", 42),
			"noncanonical": strings.Repeat("B", 43), "invalid alphabet": strings.Repeat("+", 43),
		} {
			t.Run(field+"/"+name, func(t *testing.T) {
				parameters := oidcAuthorizationParameters()
				switch field {
				case "state":
					parameters.State = value
				case "nonce":
					parameters.Nonce = value
				case "challenge":
					parameters.PKCEChallenge = value
				}
				requireOIDCAuthorizationError(t, t.Context(), queryProfile(), parameters, oauth.InvalidInput)
			})
		}
	}
}

func TestOIDCAuthorizationCancellationAndNilContext(t *testing.T) {
	profile, parameters := queryProfile(), oidcAuthorizationParameters()
	requireOIDCAuthorizationError(t, nil, profile, parameters, oauth.InvalidInput)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	err := requireOIDCAuthorizationError(t, cancelled, profile, parameters, oauth.Unavailable)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("authorization lost cancellation cause")
	}
	expired, expire := context.WithDeadline(t.Context(), time.Unix(1, 0))
	defer expire()
	err = requireOIDCAuthorizationError(t, expired, profile, parameters, oauth.Unavailable)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("authorization lost deadline cause")
	}
	requireOIDCAuthorizationError(t, cancelled, oauth.ProviderProfile{}, parameters, oauth.InvalidInput)
	requireOIDCAuthorizationError(t, cancelled, profile, oauth.AuthorizationParameters{}, oauth.InvalidInput)
}

func TestOIDCAuthorizationPreservesInstanceVariantsAndLifecycle(t *testing.T) {
	for name, create := range map[string]func(oauth.OIDCConfig) (*oauth.OIDCProvider, error){
		"strict": oauth.NewOIDCProvider, "Google": oauth.NewGoogleAccountsProvider,
	} {
		t.Run(name, func(t *testing.T) {
			profile := queryProfile()
			if name == "Google" {
				profile.Issuer = googleIssuer
			}
			instance, err := create(oauth.OIDCConfig{
				ID: profile.ID, Version: profile.Version, Issuer: profile.Issuer,
				ClientID: profile.ClientID, AuthorizationEndpoint: profile.AuthorizationEndpoint,
				TokenEndpoint: profile.TokenEndpoint, RedirectURI: profile.RedirectURI,
				ClientAuthentication: oauth.PublicClient, Scopes: profile.Scopes, Algorithms: profile.Algorithms,
				KeySet: panickingKeySet{},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(instance.Close)
			parameters := oidcAuthorizationParameters()
			want, err := oauth.OIDCAuthorization(t.Context(), instance.Profile(), parameters)
			if name == "Google" {
				requireOIDCAuthorizationError(t, t.Context(), instance.Profile(), parameters, oauth.InvalidInput)
				want, err = oauth.OIDCAuthorization(t.Context(), profile, parameters)
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := instance.Authorization(t.Context(), parameters)
			if err != nil || got.URL() != want.URL() {
				t.Fatal("existing provider changed authorization URL", err)
			}
			cancelled, cancel := context.WithCancel(t.Context())
			cancel()
			instance.Close()
			for _, ctx := range []context.Context{nil, t.Context(), cancelled} {
				got, err := instance.Authorization(ctx, parameters)
				var classified *oauth.Error
				wantKind := oauth.InvalidInput
				if ctx == cancelled {
					wantKind = oauth.Unavailable
				}
				if !errors.As(err, &classified) || classified.Kind() != wantKind || got.URL() != "" {
					t.Fatal("instance lifecycle validation order changed")
				}
			}
		})
	}
}
