package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"unicode/utf8"
)

// OAuth2RefreshRevocationProvider explicitly selects RFC7009 refresh-token
// revocation for one ordinary OAuth2 provider and trusted configured endpoint.
// It borrows the provider's credentials, client and lifetime; keep the provider
// open until admitted calls finish. Distinct custody may be used concurrently.
// Native storage owns grant admission, generation checks, persistence and recovery.
type OAuth2RefreshRevocationProvider struct {
	provider *OAuth2UserInfoProvider
	endpoint string
}

// NewOAuth2RefreshRevocationProvider selects the existing zero-policy ordinary
// OAuth2 provider and an exact same-origin HTTPS revocation endpoint. Endpoint
// discovery, query parameters, userinfo, fragments and vendor policies are not
// inferred or admitted. Construction performs no I/O and does not own Close.
// The trusted endpoint and selected client_secret_post authentication must be
// configured for this provider; constructor validation does not prove support.
func NewOAuth2RefreshRevocationProvider(provider *OAuth2UserInfoProvider, endpoint string) (*OAuth2RefreshRevocationProvider, error) {
	if provider == nil || provider.profile.Validate() != nil {
		return nil, failure(InvalidInput, nil)
	}
	return newOAuth2RefreshRevocationProvider(provider, endpoint)
}

// NewSharedOAuth2RefreshRevocationProvider selects the same transport capability
// for an existing shared-redirect issuer-bound OAuth2 provider, including its
// string-subject profile. It preserves that provider's exact original profile;
// no distinct-route identity profile or new issuer is synthesized. Endpoint,
// authentication and borrowed lifetime requirements match the ordinary constructor.
func NewSharedOAuth2RefreshRevocationProvider(provider *SharedOAuth2UserInfoProvider, endpoint string) (*OAuth2RefreshRevocationProvider, error) {
	if provider == nil || provider.provider == nil || !sharedOAuth2UserInfoProfileValid(provider.provider.profile) {
		return nil, failure(InvalidInput, nil)
	}
	return newOAuth2RefreshRevocationProvider(provider.provider, endpoint)
}

func newOAuth2RefreshRevocationProvider(provider *OAuth2UserInfoProvider, endpoint string) (*OAuth2RefreshRevocationProvider, error) {
	if provider.client == nil || provider.policy != "" || !sameOAuth2Origin(provider.profile.Profile.Issuer, endpoint) {
		return nil, failure(InvalidInput, nil)
	}
	provider.mu.Lock()
	closed := provider.closed
	provider.mu.Unlock()
	if closed {
		return nil, failure(InvalidInput, nil)
	}
	return &OAuth2RefreshRevocationProvider{provider: provider, endpoint: endpoint}, nil
}

// Format redacts the borrowed provider, endpoint and credentials.
func (*OAuth2RefreshRevocationProvider) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.OAuth2RefreshRevocationProvider(redacted)"))
}

// MarshalJSON refuses implicit provider/configuration persistence.
func (*OAuth2RefreshRevocationProvider) MarshalJSON() ([]byte, error) {
	return nil, failure(InvalidInput, nil)
}

// MarshalText refuses implicit provider/configuration persistence.
func (*OAuth2RefreshRevocationProvider) MarshalText() ([]byte, error) {
	return nil, failure(InvalidInput, nil)
}

// Revoke makes at most one bounded form POST for the original profile-bound
// refresh token after native admission. Nil means an HTTP200 acknowledgement,
// including an already invalid token, not proof of when invalidation happened.
// RFC7009 section2.2 requires ignoring the success body. No access-token,
// related-grant, identity or session outcome is inferred or returned.
// InvalidInput/Unavailable deny before attempt; Refused is a coherent OAuth
// refusal; Unknown includes post-attempt transport failures, redirects, malformed
// responses and HTTP503. A 503 does not acknowledge revocation: RFC7009 requires
// assuming the token still exists. Nothing here retries or authorizes retry.
// This borrows but does not destroy input; the native owner must destroy it and
// must not reuse a token after acknowledgement (RFC7009 section2.1).
func (p *OAuth2RefreshRevocationProvider) Revoke(ctx context.Context, input RefreshToken) (err error) {
	if ctx == nil || p == nil || p.provider == nil || input.owner == nil {
		return failure(InvalidInput, ctx)
	}
	if ctx.Err() != nil {
		return failure(Unavailable, ctx)
	}
	provider := p.provider
	if !reflect.DeepEqual(input.profile, provider.Profile()) {
		return failure(InvalidInput, ctx)
	}
	provider.mu.Lock()
	if provider.closed {
		provider.mu.Unlock()
		return failure(InvalidInput, ctx)
	}
	secret := bytes.Clone(provider.secret)
	provider.mu.Unlock()
	defer clear(secret)
	ctx, cancel := context.WithTimeout(ctx, provider.config.Timeout)
	defer cancel()
	attempted := false
	defer func() {
		if recover() != nil {
			kind := InvalidInput
			if attempted {
				kind = Unknown
			}
			err = failure(kind, ctx)
		}
	}()
	return input.use(ctx, func(token []byte) error {
		return p.revoke(ctx, token, secret, &attempted)
	})
}

func (p *OAuth2RefreshRevocationProvider) revoke(ctx context.Context, token, secret []byte, attempted *bool) error {
	provider := p.provider
	form := url.Values{"token": {string(token)}, "token_type_hint": {"refresh_token"}, "client_id": {provider.config.ClientID}, "client_secret": {string(secret)}}
	body := newTokenRequestBody([]byte(form.Encode()))
	defer body.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, body)
	if err != nil {
		return failure(InvalidInput, ctx)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	if ctx.Err() != nil {
		return failure(Unavailable, ctx)
	}
	*attempted = true
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

// RFC7009 section2.2.1 uses RFC6749 section5.2 error presentation and adds
// unsupported_token_type. Reuse the bounded duplicate-rejecting wire reader,
// but do not interpret a refusal as refresh rotation or token-invalid proof.
func refreshRevocationRefusal(status int, contentType string, raw []byte) ErrorKind {
	media, _, err := mime.ParseMediaType(contentType)
	if err != nil || media != "application/json" || !utf8.Valid(raw) {
		return Unknown
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	budget := 0
	value, err := readJSON(decoder, 0, &budget)
	if err != nil {
		return Unknown
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return Unknown
	}
	fields, ok := value.(map[string]any)
	if !ok {
		return Unknown
	}
	code, ok := fields["error"].(string)
	if !ok || !slices.Contains([]string{"invalid_request", "invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type", "invalid_scope", "unsupported_token_type"}, code) {
		return Unknown
	}
	if status != http.StatusBadRequest && (status != http.StatusUnauthorized || code != "invalid_client") {
		return Unknown
	}
	for _, name := range []string{"access_token", "refresh_token", "id_token", "token_type", "expires_in", "scope"} {
		if _, present := fields[name]; present {
			return Unknown
		}
	}
	for _, name := range []string{"error_description", "error_uri"} {
		value, present := fields[name]
		if !present {
			continue
		}
		text, ok := value.(string)
		if !ok {
			return Unknown
		}
		if text == "" {
			continue
		}
		if name == "error_description" {
			if !queryErrorText([]byte(text)) {
				return Unknown
			}
		} else if !queryErrorURI([]byte(text)) {
			return Unknown
		}
	}
	return Refused
}
