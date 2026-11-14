package providers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/faustbrian/go-identity/oauth"
)

// ErrGitLabConfiguration rejects startup configuration without disclosing
// credentials, URLs or collaborator diagnostics.
var ErrGitLabConfiguration = errors.New("providers: invalid GitLab configuration")

// GitLabConfig selects the existing-account OAuth2/read_user browser profile.
// Empty Issuer selects https://gitlab.com; a self-managed issuer is an exact
// HTTPS deployment base without a trailing slash, query, fragment or userinfo.
// Version must change when configuration changes. The registered RedirectURI
// must be unique to this issuer, not a shared multi-provider callback route.
// ClientSecret is copied; caller clears the original. Clock/HTTPClient and
// resource limits have OAuth2UserInfoConfig's ownership and defaults.
type GitLabConfig struct {
	Version                       uint64
	Issuer, ClientID, RedirectURI string
	ClientSecret                  []byte
	Clock                         oauth.Clock
	HTTPClient                    *http.Client
	Timeout                       time.Duration
	MaxResponseBytes              int64
	MaxTokenBytes, MaxCodeBytes   int
}

// Format prevents implicit disclosure, including through enclosing values.
func (GitLabConfig) Format(s fmt.State, _ rune) { redact(s) }

// MarshalJSON refuses implicit credential serialization.
func (GitLabConfig) MarshalJSON() ([]byte, error) { return nil, ErrGitLabConfiguration }

// MarshalText refuses implicit credential serialization or map-key export.
func (GitLabConfig) MarshalText() ([]byte, error) { return nil, ErrGitLabConfiguration }

// NewGitLab constructs the existing OAuth2 protocol owner without IO. It selects
// stable ID gitlab, code/query/S256, client_secret_post, exactly read_user and
// bearer HTTPS /api/v4/user with positive integer id as canonical decimal.
// There are no invented ID-token, nonce, email-linking or authentication-age
// claims. ParseOAuth2QueryCallback must receive the actual configured route;
// native state/link/signin/session owners remain mandatory.
//
// This profile excludes signup, implicit linking, direct native tokens, refresh,
// enterprise routing and remote logout. Close after admitted calls complete.
func NewGitLab(c GitLabConfig) (*oauth.OAuth2UserInfoProvider, error) {
	issuer := c.Issuer
	if issuer == "" {
		issuer = "https://gitlab.com"
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || strings.HasSuffix(issuer, "/") || strings.Contains(u.Path, "//") || strings.Contains(u.Path, "/../") || strings.HasSuffix(u.Path, "/..") || strings.Contains(u.Path, "/./") || strings.HasSuffix(u.Path, "/.") {
		return nil, ErrGitLabConfiguration
	}
	p, err := oauth.NewOAuth2UserInfoProvider(oauth.OAuth2UserInfoConfig{
		ID: "gitlab", Version: c.Version, Issuer: issuer, ClientID: c.ClientID,
		AuthorizationEndpoint: issuer + "/oauth/authorize", TokenEndpoint: issuer + "/oauth/token",
		UserInfoEndpoint: issuer + "/api/v4/user", RedirectURI: c.RedirectURI,
		ClientAuthentication: oauth.ClientSecretPost, ClientSecret: c.ClientSecret,
		Scopes: []string{"read_user"}, SubjectClaim: "id", SubjectEncoding: oauth.OAuth2PositiveIntegerSubject,
		Clock: c.Clock, HTTPClient: c.HTTPClient, Timeout: c.Timeout,
		MaxResponseBytes: c.MaxResponseBytes, MaxTokenBytes: c.MaxTokenBytes, MaxCodeBytes: c.MaxCodeBytes,
	})
	if err != nil {
		return nil, ErrGitLabConfiguration
	}
	return p, nil
}
