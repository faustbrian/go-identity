package oauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	identity "github.com/faustbrian/go-identity"
)

// OIDCProxyExchange delegates an admitted code exchange to one configured OIDC
// provider and returns only verified identity, never provider token custody.
// It borrows the provider's client, credentials and lifetime; keep the provider
// open until calls finish. Distinct admitted callback custody is concurrency-safe.
// Native owners still authenticate/reserve state and reconcile Unknown outcomes.
type OIDCProxyExchange struct {
	provider *OIDCProvider
	endpoint string
}

// NewOIDCProxyExchange selects an exact trusted same-issuer-origin HTTPS RFC7009
// endpoint, with no query, fragment, userinfo, discovery or request-selected URL.
// Empty permits providers without configured revocation, but a returned refresh
// token then yields Unknown, never accepted identity. Configuration must select
// a supported endpoint and the provider's existing client-authentication method;
// this constructor proves neither provider support nor actual invalidation.
// Construction performs no I/O and does not acquire ownership of Close.
func NewOIDCProxyExchange(provider *OIDCProvider, revocationEndpoint string) (*OIDCProxyExchange, error) {
	if !provider.ready() || revocationEndpoint != "" && !sameOAuth2Origin(provider.config.Issuer, revocationEndpoint) {
		return nil, failure(InvalidInput, nil)
	}
	if revocationEndpoint != "" {
		endpoint, _ := url.Parse(revocationEndpoint)
		if tls := provider.transport.TLSClientConfig; tls != nil && tls.ServerName != "" && tls.ServerName != endpoint.Hostname() {
			return nil, failure(InvalidInput, nil)
		}
	}
	provider.mu.Lock()
	closed := provider.closed
	provider.mu.Unlock()
	if closed {
		return nil, failure(InvalidInput, nil)
	}
	return &OIDCProxyExchange{provider: provider, endpoint: revocationEndpoint}, nil
}

// Profile returns the original provider's immutable facts with cloned slices.
// Nil and zero adapters expose an empty profile and no exchange capability.
func (p *OIDCProxyExchange) Profile() ProviderProfile {
	if p == nil {
		return ProviderProfile{}
	}
	return p.provider.Profile()
}

// Exchange borrows original callback/PKCE custody after native state admission.
// It sends the code once, verifies the existing strict OIDC proof, and clears
// response/token buffers without creating or returning TokenSet custody. Any
// parsed refresh token is revoked once before return, even on invalid proof.
// Only an HTTP200 acknowledgement establishes disposal (RFC7009 section2.2),
// not when invalidation occurred or any access-token/related-grant effect.
// Missing endpoint, refused/failed disposal and ambiguous token responses return
// Unknown for reconciliation, never success; no automatic retry is authorized.
// Before-send errors and coherent token-endpoint refusals preserve the ordinary
// provider's classification. No redirects, persistence or local identity/session
// writes occur. The caller retains callback/PKCE destruction and native recovery.
func (p *OIDCProxyExchange) Exchange(ctx context.Context, input identity.OAuthCallbackInput, verifier PKCEVerifier, nonce string) (ProviderIdentity, error) {
	if p == nil || p.provider == nil {
		return ProviderIdentity{}, failure(InvalidInput, ctx)
	}
	result, err := p.provider.exchangeCode(ctx, input, verifier, nonce, p.disposeRefresh)
	if err != nil {
		return ProviderIdentity{}, err
	}
	return result.Identity, nil
}

// Format redacts the borrowed provider, endpoint and credentials.
func (*OIDCProxyExchange) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.OIDCProxyExchange(redacted)"))
}

// MarshalJSON refuses implicit provider/configuration persistence.
func (*OIDCProxyExchange) MarshalJSON() ([]byte, error) {
	return nil, failure(InvalidInput, nil)
}

// MarshalText refuses implicit provider/configuration persistence.
func (*OIDCProxyExchange) MarshalText() ([]byte, error) {
	return nil, failure(InvalidInput, nil)
}

// A valid refresh credential remains our cleanup responsibility when an
// unrelated successful token-response field is invalid. Never salvage from
// ambiguous framing, error-bearing responses or a non-success HTTP status.
func parseProxyOIDCResponse(status int, contentType string, body []byte, c OIDCConfig, googleAccounts bool) (tokenResponse, ErrorKind) {
	fields, ok := decodeTokenResponse(contentType, body, c)
	if !ok {
		return tokenResponse{}, Unknown
	}
	parsed, kind := parseTokenResponseFields(status, fields, c, googleAccounts, true, "")
	if kind == "" || status != http.StatusOK {
		return parsed, kind
	}
	for _, name := range []string{"error", "error_description", "error_uri"} {
		if _, present := fields[name]; present {
			return tokenResponse{}, kind
		}
	}
	refresh, ok := fields["refresh_token"].(string)
	if !ok || !visible(refresh, 1, c.MaxTokenBytes) {
		return tokenResponse{}, kind
	}
	return tokenResponse{refresh: []byte(refresh)}, Unknown
}

func (p *OIDCProxyExchange) disposeRefresh(ctx context.Context, token, secret []byte) error {
	if p.endpoint == "" {
		return failure(Unknown, ctx)
	}
	provider := p.provider
	form := url.Values{"token": {string(token)}, "token_type_hint": {"refresh_token"}}
	if provider.config.ClientAuthentication != ClientSecretBasic {
		form.Set("client_id", provider.config.ClientID)
	}
	if provider.config.ClientAuthentication == ClientSecretPost {
		form.Set("client_secret", string(secret))
	}
	encoded := []byte(form.Encode())
	body := newTokenRequestBody(encoded)
	defer body.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, body)
	if err != nil {
		return failure(Unknown, ctx)
	}
	request.ContentLength = int64(len(encoded))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	if provider.config.ClientAuthentication == ClientSecretBasic {
		request.SetBasicAuth(url.QueryEscape(provider.config.ClientID), url.QueryEscape(string(secret)))
	}
	if ctx.Err() != nil {
		return failure(Unknown, ctx)
	}
	response, err := provider.client.Do(request)
	if err != nil {
		return failure(Unknown, ctx)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusOK {
		return nil
	}
	if response.StatusCode != http.StatusBadRequest && response.StatusCode != http.StatusUnauthorized {
		return failure(Unknown, ctx)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, provider.config.MaxResponseBytes+1))
	defer clear(raw)
	if err != nil || int64(len(raw)) > provider.config.MaxResponseBytes {
		return failure(Unknown, ctx)
	}
	return failure(refreshRevocationRefusal(response.StatusCode, response.Header.Get("Content-Type"), raw), ctx)
}
