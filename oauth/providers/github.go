package providers

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/faustbrian/go-identity/oauth"
)

// ErrGitHubConfiguration rejects startup configuration without exposing secret
// material, endpoint values or collaborator diagnostics.
var ErrGitHubConfiguration = errors.New("providers: invalid GitHub configuration")

// GitHubConfig selects the ordinary GitHub.com OAuth-app browser profile.
// Endpoints, token policy and identity scopes are closed, not caller-overridable.
// Version changes with configuration. RedirectURI must be registered exclusively
// for this provider. ClientSecret is copied; the caller clears its source.
// Clock/HTTPClient remain borrowed concurrent-safe collaborators; the provider
// owns a transport clone and starts no background work. Zero limits select the
// root OAuth2 owner's bounded defaults.
type GitHubConfig struct {
	Version                     uint64
	ClientID, RedirectURI       string
	ClientSecret                []byte
	Clock                       oauth.Clock
	HTTPClient                  *http.Client
	Timeout                     time.Duration
	MaxResponseBytes            int64
	MaxTokenBytes, MaxCodeBytes int
}

// Format prevents credential disclosure, including through enclosing values.
func (GitHubConfig) Format(s fmt.State, _ rune) { redact(s) }

// MarshalJSON refuses implicit credential serialization.
func (GitHubConfig) MarshalJSON() ([]byte, error) { return nil, ErrGitHubConfiguration }

// MarshalText refuses implicit serialization, including map-key export.
func (GitHubConfig) MarshalText() ([]byte, error) { return nil, ErrGitHubConfiguration }

// NewGitHub constructs the existing native-consumable OAuth2 owner without IO.
// It selects GitHub.com code/query/S256, POST client authentication, read:user
// and user:email, and bearer-bound api.github.com/user positive integer ID.
// Ordinary responses honestly retain absent token expiry; original UserInfo
// evidence remains bounded to twenty seconds, never the token's lifetime.
// Native callers must apply TokenVaultOptionalExpiryMigrationSource first and
// bind the selected policy with ParseOAuth2QueryCallbackWithPolicy at the exact
// registered distinct callback route. No OIDC/nonce/authentication-age claim,
// email linking, signup, direct token, refresh or remote logout is added.
// Close after admitted concurrent operations have completed.
func NewGitHub(c GitHubConfig) (*oauth.OAuth2UserInfoProvider, error) {
	p, err := oauth.NewOAuth2UserInfoProviderWithPolicy(oauth.OAuth2UserInfoConfig{
		ID: "github", Version: c.Version, Issuer: "https://github.com", ClientID: c.ClientID,
		AuthorizationEndpoint: "https://github.com/login/oauth/authorize", TokenEndpoint: "https://github.com/login/oauth/access_token",
		UserInfoEndpoint: "https://api.github.com/user", RedirectURI: c.RedirectURI,
		ClientAuthentication: oauth.ClientSecretPost, ClientSecret: c.ClientSecret,
		Scopes: []string{"read:user", "user:email"}, SubjectClaim: "id", SubjectEncoding: oauth.OAuth2PositiveIntegerSubject,
		Clock: c.Clock, HTTPClient: c.HTTPClient, Timeout: c.Timeout, MaxResponseBytes: c.MaxResponseBytes, MaxTokenBytes: c.MaxTokenBytes, MaxCodeBytes: c.MaxCodeBytes,
	}, oauth.OAuth2GitHubOAuthAppPolicy)
	if err != nil {
		return nil, ErrGitHubConfiguration
	}
	return p, nil
}
