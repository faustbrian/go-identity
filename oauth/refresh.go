package oauth

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"time"
)

// RefreshGrantRejected means a coherent RFC6749 invalid_grant response rejected
// the submitted refresh token. Invalid, expired, revoked and wrong-client grants
// share this classification; it does not establish a particular revocation cause.
const RefreshGrantRejected ErrorKind = "refresh_grant_rejected"

// RefreshRotation distinguishes a returned replacement from an omitted token.
// Zero is invalid and accompanies no successful refresh.
type RefreshRotation string

const (
	// RotatedRefreshToken requires replacing the predecessor with the returned
	// refresh bytes. It does not prove whether the provider revoked the old token.
	RotatedRefreshToken RefreshRotation = "rotated"
	// RetainOriginalRefreshToken means no refresh bytes were returned. The native
	// owner retains the safe stored predecessor; no original bytes are re-exposed.
	RetainOriginalRefreshToken RefreshRotation = "retain_original"
)

// RefreshResult owns provider-token custody only, with no identity or session
// proof. Destroy Tokens after bounded encryption/use, including native failure.
// RequestedScopes preserves original refresh-grant scopes; GrantedScopes applies
// to the new access token and may be narrower without changing refresh authority.
type RefreshResult struct {
	Tokens   TokenSet
	Rotation RefreshRotation
}

// Format redacts provider tokens and implicit diagnostics.
func (RefreshResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.RefreshResult(redacted)"))
}

// MarshalJSON refuses accidental provider-token persistence.
func (RefreshResult) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText refuses accidental provider-token persistence.
func (RefreshResult) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// OAuth2RefreshProvider explicitly selects the token-endpoint refresh
// capability without extending Provider or enabling existing provider defaults.
// It borrows the immutable provider and its lifetime; keep that provider open
// until admitted calls finish. Distinct admitted custody may be used concurrently.
// Native storage owns per-grant single-flight, generation checks and recovery.
type OAuth2RefreshProvider struct{ provider *OAuth2UserInfoProvider }

// NewOAuth2RefreshProvider selects only the existing ordinary zero-policy OAuth2
// profile: exact configured same-origin HTTPS token endpoint, POST client
// credentials, space-delimited scopes and required positive bounded expiry.
// GitHub/OIDC/catalog profiles and other authentication methods are not inferred.
// Construction performs no I/O or credential copy and does not own Close.
func NewOAuth2RefreshProvider(provider *OAuth2UserInfoProvider) (*OAuth2RefreshProvider, error) {
	if provider == nil || provider.client == nil || provider.policy != "" || provider.profile.Validate() != nil {
		return nil, failure(InvalidInput, nil)
	}
	provider.mu.Lock()
	closed := provider.closed
	provider.mu.Unlock()
	if closed {
		return nil, failure(InvalidInput, nil)
	}
	return &OAuth2RefreshProvider{provider: provider}, nil
}

// NewSharedOAuth2RefreshProvider selects the same scoped refresh capability for
// an existing shared-redirect issuer-bound OAuth2 provider, including its string-
// subject profile. It preserves that provider's exact original profile and
// borrows its credentials, transport and lifetime without I/O or a secret copy.
// Native grant admission, storage and recovery remain the caller's responsibility.
func NewSharedOAuth2RefreshProvider(provider *SharedOAuth2UserInfoProvider) (*OAuth2RefreshProvider, error) {
	if provider == nil || provider.provider == nil {
		return nil, failure(InvalidInput, nil)
	}
	borrowed := provider.provider
	if borrowed.client == nil || borrowed.policy != "" || !sharedOAuth2UserInfoProfileValid(borrowed.profile) {
		return nil, failure(InvalidInput, nil)
	}
	borrowed.mu.Lock()
	closed := borrowed.closed
	borrowed.mu.Unlock()
	if closed {
		return nil, failure(InvalidInput, nil)
	}
	return &OAuth2RefreshProvider{provider: borrowed}, nil
}

// Format redacts the borrowed provider and configuration.
func (*OAuth2RefreshProvider) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.OAuth2RefreshProvider(redacted)"))
}

// Refresh performs at most one bounded HTTPS POST after native grant admission.
// It never requests UserInfo, retries, follows redirects, issues identity/session
// proof, or mutates storage. InvalidInput/Unavailable deny before attempt;
// RefreshGrantRejected is definitive invalid_grant, Refused another coherent
// refusal, and Unknown preserves any possible rotation after an ambiguous attempt.
// No error authorizes automatic retry. Nil context/adapter/custody is invalid.
func (p *OAuth2RefreshProvider) Refresh(ctx context.Context, input RefreshToken) (result RefreshResult, err error) {
	if ctx == nil || p == nil || p.provider == nil || input.owner == nil {
		return result, failure(InvalidInput, ctx)
	}
	if ctx.Err() != nil {
		return result, failure(Unavailable, ctx)
	}
	provider := p.provider
	if !reflect.DeepEqual(input.profile, provider.Profile()) {
		return result, failure(InvalidInput, ctx)
	}
	provider.mu.Lock()
	if provider.closed {
		provider.mu.Unlock()
		return result, failure(InvalidInput, ctx)
	}
	secret := bytes.Clone(provider.secret)
	provider.mu.Unlock()
	defer clear(secret)
	ctx, cancel := context.WithTimeout(ctx, provider.config.Timeout)
	defer cancel()
	attempted := false
	defer func() {
		if recover() != nil {
			result.Tokens.Destroy()
			result = RefreshResult{}
			kind := InvalidInput
			if attempted {
				kind = Unknown
			}
			err = failure(kind, ctx)
		}
	}()
	err = input.use(ctx, func(token []byte) error {
		result, err = provider.refreshTokens(ctx, token, secret, input.scopes, &attempted)
		return err
	})
	return result, err
}

func (p *OAuth2UserInfoProvider) refreshTokens(ctx context.Context, token, secret []byte, scopes []string, attempted *bool) (RefreshResult, error) {
	c := p.config
	// RFC6749 section6: omitting scope means the original grant, never current
	// configured scopes. The response parser must use that same upper bound.
	c.Scopes = scopes
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {string(token)}, "client_id": {c.ClientID}, "client_secret": {string(secret)}}
	body := newTokenRequestBody([]byte(form.Encode()))
	defer body.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenEndpoint, body)
	if err != nil {
		return RefreshResult{}, failure(InvalidInput, ctx)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	if ctx.Err() != nil {
		return RefreshResult{}, failure(Unavailable, ctx)
	}
	*attempted = true
	response, err := p.client.Do(request)
	if err != nil {
		return RefreshResult{}, failure(Unknown, ctx)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, c.MaxResponseBytes+1))
	defer clear(raw)
	if err != nil || int64(len(raw)) > c.MaxResponseBytes {
		return RefreshResult{}, failure(Unknown, ctx)
	}
	received := c.Clock.Now()
	parsed, kind := parseTokenResponse(response.StatusCode, response.Header.Get("Content-Type"), raw, c, false, false)
	if kind == Refused {
		kind = refreshRefusal(response.StatusCode, raw)
	}
	if kind != "" {
		return RefreshResult{}, failure(kind, ctx)
	}
	defer parsed.clear()
	if received.IsZero() {
		return RefreshResult{}, failure(Unknown, ctx)
	}
	owner := &tokenOwner{access: bytes.Clone(parsed.access), refresh: bytes.Clone(parsed.refresh)}
	tokens := TokenSet{owner: func() *tokenOwner { return owner }, receivedAt: received, expiresAt: received.Add(time.Duration(parsed.expires) * time.Second), requested: slices.Clone(scopes), granted: slices.Clone(parsed.scopes), scopeReported: parsed.scopeReported}
	rotation := RetainOriginalRefreshToken
	if len(parsed.refresh) > 0 {
		rotation = RotatedRefreshToken
	}
	return RefreshResult{Tokens: tokens, Rotation: rotation}, nil
}
