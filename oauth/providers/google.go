package providers

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/faustbrian/go-identity/oauth"
)

// ErrGoogleConfiguration rejects unsupported or invalid trusted startup
// configuration without retaining credentials, URLs or collaborator diagnostics.
var ErrGoogleConfiguration = errors.New("providers: invalid Google configuration")

// GoogleConfig supplies deployment-specific inputs for the fixed Google browser
// profile. Version is positive native-owned configuration identity. ClientSecret
// and Scopes are copied by the existing OAuth owner; callers clear their source
// secret and must not mutate configuration concurrently with construction.
// KeySet, Clock and the source HTTP transport remain borrowed, concurrent-safe
// collaborators. Nil Clock/HTTPClient and zero resource limits select the OAuth
// owner's defaults. There is no endpoint, issuer, algorithm or auth-method override.
type GoogleConfig struct {
	Version                     uint64
	ClientID, RedirectURI       string
	ClientSecret                []byte
	Scopes                      []string
	KeySet                      oauth.SigningKeySet
	Clock                       oauth.Clock
	HTTPClient                  *http.Client
	Timeout, ClockSkew          time.Duration
	MaxResponseBytes            int64
	MaxTokenBytes, MaxCodeBytes int
}

// Format redacts configuration, including enclosing/pointer diagnostics.
func (GoogleConfig) Format(s fmt.State, _ rune) { redact(s) }

// MarshalJSON refuses accidental credential serialization.
func (GoogleConfig) MarshalJSON() ([]byte, error) { return nil, ErrGoogleConfiguration }

// MarshalText refuses accidental credential serialization, including map keys.
func (GoogleConfig) MarshalText() ([]byte, error) { return nil, ErrGoogleConfiguration }

// NewGoogle constructs the built-in code/query/S256/nonce/RS256 Google profile
// without network, discovery, clock reads or key fetches. The reviewed official
// metadata and local catalog select POST client authentication and these exact
// endpoints; see docs/google-sources.md. Nil scopes select openid,email,profile.
// An explicit unique subset must contain openid; all unlisted scopes deny.
//
// Successful construction returns the existing OAuth owner, not a wrapper or new
// authentication/workflow authority. Its defensive Profile binds Google-only
// signed-issuer normalization; raw callback iss stays exactly canonical. The
// caller closes the provider after admitted operations finish and retains all
// native state/account/session admission requirements. Invalid configuration
// returns nil,ErrGoogleConfiguration with no underlying input diagnostics.
func NewGoogle(c GoogleConfig) (*oauth.OIDCProvider, error) {
	scopes := c.Scopes
	if scopes == nil {
		scopes = []string{"openid", "email", "profile"}
	}
	if len(scopes) < 1 || len(scopes) > 3 {
		return nil, ErrGoogleConfiguration
	}
	seen := make(map[string]bool, 3)
	for _, scope := range scopes {
		if scope != "openid" && scope != "email" && scope != "profile" || seen[scope] {
			return nil, ErrGoogleConfiguration
		}
		seen[scope] = true
	}
	if !seen["openid"] {
		return nil, ErrGoogleConfiguration
	}
	provider, err := oauth.NewGoogleAccountsProvider(oauth.OIDCConfig{
		ID: "google", Version: c.Version,
		Issuer:                "https://accounts.google.com",
		AuthorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenEndpoint:         "https://oauth2.googleapis.com/token",
		ClientID:              c.ClientID, ClientSecret: c.ClientSecret,
		ClientAuthentication: oauth.ClientSecretPost,
		RedirectURI:          c.RedirectURI, Scopes: scopes, Algorithms: []string{"RS256"},
		KeySet: c.KeySet, Clock: c.Clock, HTTPClient: c.HTTPClient,
		Timeout: c.Timeout, ClockSkew: c.ClockSkew,
		MaxResponseBytes: c.MaxResponseBytes, MaxTokenBytes: c.MaxTokenBytes, MaxCodeBytes: c.MaxCodeBytes,
	})
	if err != nil {
		return nil, ErrGoogleConfiguration
	}
	return provider, nil
}
