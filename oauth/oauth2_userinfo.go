package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
)

// OAuth2SubjectEncoding identifies an explicitly selected UserInfo ID contract.
type OAuth2SubjectEncoding string

// OAuth2PositiveIntegerSubject selects a positive int64 JSON integer projected
// to exact canonical decimal. Strings, floats, exponents, zero and negatives deny.
const OAuth2PositiveIntegerSubject OAuth2SubjectEncoding = "positive_integer"

// OAuth2UserInfoDetails are immutable additional protocol facts. They are kept
// outside ProviderProfile so existing public struct literals remain compatible.
// ProofLifetime bounds original UserInfo observation validity, not authentication
// age or an invented JWT timestamp. It is positive and at most twenty seconds.
type OAuth2UserInfoDetails struct {
	UserInfoEndpoint, SubjectClaim string
	SubjectEncoding                OAuth2SubjectEncoding
	ProofLifetime                  time.Duration
}

// OAuth2UserInfoProfile is the full immutable OAuth2 browser profile. Native
// owners bind Details together with the unchanged base profile in encrypted
// transaction state. The distinct callback route is its mix-up defense.
type OAuth2UserInfoProfile struct {
	Profile ProviderProfile
	Details OAuth2UserInfoDetails
}

// OAuth2UserInfoFacts is an optional capability on Provider, not a replacement
// provider registry/workflow. Implementations must return immutable exact facts.
type OAuth2UserInfoFacts interface{ OAuth2Profile() OAuth2UserInfoProfile }

// OAuth2UserInfoConfig is trusted startup configuration for the code/query/S256
// variant. Every endpoint is exact HTTPS on the configured issuer origin. No
// discovery, JWT, nonce proof, signup or direct-token operation is selected.
// ClientSecret/Scopes are copied; caller clears source secrets and must not
// mutate configuration during construction. Clock and source HTTP transport
// remain borrowed concurrent-safe collaborators; the provider owns its clone.
// Zero limits select the OIDC owner's same resource defaults, not OIDC claims.
type OAuth2UserInfoConfig struct {
	ID, Issuer, AuthorizationEndpoint, TokenEndpoint, UserInfoEndpoint, RedirectURI, ClientID string
	Version                                                                                   uint64
	ClientSecret                                                                              []byte
	ClientAuthentication                                                                      ClientAuthentication
	Scopes                                                                                    []string
	SubjectClaim                                                                              string
	SubjectEncoding                                                                           OAuth2SubjectEncoding
	ProofLifetime                                                                             time.Duration
	Clock                                                                                     Clock
	HTTPClient                                                                                *http.Client
	Timeout                                                                                   time.Duration
	MaxResponseBytes                                                                          int64
	MaxTokenBytes, MaxCodeBytes                                                               int
}

// Format refuses implicit disclosure of credentials or transport configuration.
func (OAuth2UserInfoConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.OAuth2UserInfoConfig(redacted)"))
}

// MarshalJSON refuses implicit credential serialization.
func (OAuth2UserInfoConfig) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText refuses implicit serialization, including map keys.
func (OAuth2UserInfoConfig) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// OAuth2UserInfoProvider exchanges only admitted original code custody, then
// obtains its stable subject from bearer-bound HTTPS UserInfo. It owns no native
// state, account, session, replay or persistent token authority. mu synchronizes
// copied secret/closure only; no IO or callback runs under it. Calls may overlap
// with separate custody. Close after admitted calls finish; no goroutine starts.
type OAuth2UserInfoProvider struct {
	profile   OAuth2UserInfoProfile
	config    OIDCConfig // shared HTTP/token bounds only; never an OIDC validator
	client    *http.Client
	transport *http.Transport
	mu        sync.Mutex
	secret    []byte
	closed    bool
}

// NewOAuth2UserInfoProvider validates/copies configuration without IO. The
// selected named callback strategy is RFC9700 section4.4.2.2: one exact redirect
// URI per authorization server, checked against the actual received route.
// Registry construction rejects route sharing with another provider. Native
// admission must use ParseOAuth2QueryCallback and the full immutable facts.
func NewOAuth2UserInfoProvider(c OAuth2UserInfoConfig) (*OAuth2UserInfoProvider, error) {
	if c.Clock == nil {
		c.Clock = systemClock{}
	}
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
	if c.MaxResponseBytes == 0 {
		c.MaxResponseBytes = 64 << 10
	}
	if c.MaxTokenBytes == 0 {
		c.MaxTokenBytes = 16 << 10
	}
	if c.MaxCodeBytes == 0 {
		c.MaxCodeBytes = 4096
	}
	if c.ProofLifetime == 0 {
		c.ProofLifetime = 20 * time.Second
	}
	p := ProviderProfile{ID: c.ID, Version: c.Version, Issuer: c.Issuer, ClientID: c.ClientID, AuthorizationEndpoint: c.AuthorizationEndpoint, TokenEndpoint: c.TokenEndpoint, RedirectURI: c.RedirectURI, ClientAuthentication: c.ClientAuthentication, Scopes: slices.Clone(c.Scopes), ResponseMode: "query", PKCEMethod: "S256", StateBytes: 32, Timeout: c.Timeout, ClockSkew: time.Minute, MaxResponseBytes: c.MaxResponseBytes, MaxTokenBytes: c.MaxTokenBytes, MaxCodeBytes: c.MaxCodeBytes}
	facts := OAuth2UserInfoProfile{Profile: p, Details: OAuth2UserInfoDetails{c.UserInfoEndpoint, c.SubjectClaim, c.SubjectEncoding, c.ProofLifetime}}
	if facts.Validate() != nil || c.ClientAuthentication != ClientSecretPost || !visible(string(c.ClientSecret), 1, 4096) {
		return nil, failure(InvalidInput, nil)
	}
	shared := OIDCConfig{ID: c.ID, Version: c.Version, Issuer: c.Issuer, ClientID: c.ClientID, AuthorizationEndpoint: c.AuthorizationEndpoint, TokenEndpoint: c.TokenEndpoint, RedirectURI: c.RedirectURI, ClientAuthentication: c.ClientAuthentication, Scopes: slices.Clone(c.Scopes), Clock: c.Clock, HTTPClient: c.HTTPClient, Timeout: c.Timeout, MaxResponseBytes: c.MaxResponseBytes, MaxTokenBytes: c.MaxTokenBytes, MaxCodeBytes: c.MaxCodeBytes}
	transport, err := newProviderTransport(shared)
	if err != nil {
		return nil, err
	}
	shared.HTTPClient = nil
	return &OAuth2UserInfoProvider{profile: facts, config: shared, transport: transport, secret: bytes.Clone(c.ClientSecret), client: &http.Client{Transport: transport, Timeout: c.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Validate checks only profile shape; it grants no provider/native authority.
func (p OAuth2UserInfoProfile) Validate() error {
	b, d := p.Profile, p.Details
	if !oauth2QueryProfileValid(b) || !sameOAuth2Origin(b.Issuer, d.UserInfoEndpoint) || !identifier(d.SubjectClaim) || len(d.SubjectClaim) > 64 || d.SubjectEncoding != OAuth2PositiveIntegerSubject || d.ProofLifetime < time.Second || d.ProofLifetime > 20*time.Second {
		return failure(InvalidInput, nil)
	}
	return nil
}

func oauth2QueryProfileValid(p ProviderProfile) bool {
	return identifier(p.ID) && p.Version > 0 && httpsURL(p.Issuer) && sameOAuth2Origin(p.Issuer, p.AuthorizationEndpoint) && sameOAuth2Origin(p.Issuer, p.TokenEndpoint) && httpsURL(p.RedirectURI) && visible(p.ClientID, 1, 1024) && p.ClientAuthentication == ClientSecretPost && validScopes(p.Scopes) && !slices.Contains(p.Scopes, "openid") && len(p.Algorithms) == 0 && !p.GoogleAccounts && !p.NonceRequired && p.NonceBytes == 0 && p.StateBytes == 32 && p.ResponseMode == "query" && p.PKCEMethod == "S256" && p.Timeout >= time.Second && p.Timeout <= 30*time.Second && p.MaxResponseBytes >= 1024 && p.MaxResponseBytes <= 1<<20 && p.MaxTokenBytes >= 256 && p.MaxTokenBytes <= 16<<10 && p.MaxCodeBytes >= 1 && p.MaxCodeBytes <= 64<<10
}

// ValidateOAuth2Callback validates only this distinct-route OAuth2 base shape.
// Full UserInfo facts must separately validate and bind through the native owner.
func (p ProviderProfile) ValidateOAuth2Callback() error {
	if !oauth2QueryProfileValid(p) {
		return failure(InvalidInput, nil)
	}
	return nil
}

func sameOAuth2Origin(issuer, endpoint string) bool {
	if !httpsURL(endpoint) {
		return false
	}
	a, err := url.Parse(issuer)
	if err != nil {
		return false
	}
	b, _ := url.Parse(endpoint)
	return a.Scheme == b.Scheme && a.Host == b.Host
}

// ID returns the exact configured stable provider ID; nil returns empty.
func (p *OAuth2UserInfoProvider) ID() string {
	if p == nil {
		return ""
	}
	return p.profile.Profile.ID
}

// Profile returns independent secret-free base facts, not native admission.
func (p *OAuth2UserInfoProvider) Profile() ProviderProfile {
	if p == nil {
		return ProviderProfile{}
	}
	return queryProfileSnapshot(p.profile.Profile)
}

// OAuth2Profile returns independent full facts for native state/configuration
// binding and distinct-route callback parsing. It grants no exchange authority.
func (p *OAuth2UserInfoProvider) OAuth2Profile() OAuth2UserInfoProfile {
	if p == nil {
		return OAuth2UserInfoProfile{}
	}
	return OAuth2UserInfoProfile{p.Profile(), p.profile.Details}
}

// Format refuses implicit disclosure of provider configuration or credentials.
func (p *OAuth2UserInfoProvider) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.OAuth2UserInfoProvider(redacted)"))
}

// Close clears the owned credential copy and idle connections; it is idempotent.
// Call only after admitted operations finish. Caller-owned inputs are untouched.
func (p *OAuth2UserInfoProvider) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.closed = true
	clear(p.secret)
	p.secret = nil
	p.mu.Unlock()
	if p.transport != nil {
		p.transport.CloseIdleConnections()
	}
}

// Authorization builds the fixed code/query/S256 URL without IO or clock reads.
// State and PKCEChallenge must be canonical 32-byte encodings. Nonempty Nonce
// is unsupported and rejects rather than suggesting it will be validated.
func (p *OAuth2UserInfoProvider) Authorization(ctx context.Context, a AuthorizationParameters) (AuthorizationRequest, error) {
	if ctx == nil || p == nil || p.client == nil || a.Nonce != "" || !canonical32(a.State) || !canonical32(a.PKCEChallenge) {
		return AuthorizationRequest{}, failure(InvalidInput, ctx)
	}
	if ctx.Err() != nil {
		return AuthorizationRequest{}, failure(Unavailable, ctx)
	}
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return AuthorizationRequest{}, failure(InvalidInput, ctx)
	}
	c := p.config
	q := url.Values{"response_type": {"code"}, "response_mode": {"query"}, "client_id": {c.ClientID}, "redirect_uri": {c.RedirectURI}, "scope": {strings.Join(c.Scopes, " ")}, "state": {a.State}, "code_challenge": {a.PKCEChallenge}, "code_challenge_method": {"S256"}}
	return AuthorizationRequest{c.AuthorizationEndpoint + "?" + q.Encode()}, nil
}

// Exchange makes one token request then one bearer UserInfo request. Callers
// must first reserve native state and verify the distinct received callback
// route before releasing PKCE. Any ambiguous post-send failure remains Unknown;
// no code/UserInfo retry or credential/session effect is performed here.
func (p *OAuth2UserInfoProvider) Exchange(ctx context.Context, input identity.OAuthCallbackInput, verifier PKCEVerifier, nonce string) (result ExchangeResult, err error) {
	if ctx == nil || p == nil || p.client == nil || nonce != "" {
		return result, failure(InvalidInput, ctx)
	}
	if ctx.Err() != nil {
		return result, failure(Unavailable, ctx)
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return result, failure(InvalidInput, ctx)
	}
	secret := bytes.Clone(p.secret)
	p.mu.Unlock()
	defer clear(secret)
	ctx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()
	attempted := false
	defer func() {
		if recover() != nil {
			result.Tokens.Destroy()
			result = ExchangeResult{}
			kind := InvalidInput
			if attempted {
				kind = Unknown
			}
			err = failure(kind, ctx)
		}
	}()
	var exchangeErr error
	borrowErr := input.Use(ctx, func(ctx context.Context, code, _ []byte) error {
		if len(code) > p.config.MaxCodeBytes {
			exchangeErr = failure(InvalidInput, ctx)
			return nil
		}
		exchangeErr = verifier.use(ctx, func(value []byte) error {
			result, err = p.exchangeUserInfo(ctx, code, value, secret, &attempted)
			return err
		})
		return nil
	})
	if borrowErr != nil {
		result.Tokens.Destroy()
		if attempted {
			return ExchangeResult{}, failure(Unknown, ctx)
		}
		if ctx.Err() != nil {
			return ExchangeResult{}, failure(Unavailable, ctx)
		}
		return ExchangeResult{}, failure(InvalidInput, ctx)
	}
	if exchangeErr != nil {
		return ExchangeResult{}, exchangeErr
	}
	return result, nil
}

func (p *OAuth2UserInfoProvider) exchangeUserInfo(ctx context.Context, code, verifier, secret []byte, attempted *bool) (ExchangeResult, error) {
	c := p.config
	q := url.Values{"grant_type": {"authorization_code"}, "code": {string(code)}, "code_verifier": {string(verifier)}, "redirect_uri": {c.RedirectURI}, "client_id": {c.ClientID}, "client_secret": {string(secret)}}
	body := newTokenRequestBody([]byte(q.Encode()))
	defer body.Close()
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenEndpoint, body)
	if err != nil {
		return ExchangeResult{}, failure(InvalidInput, ctx)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "application/json")
	if ctx.Err() != nil {
		return ExchangeResult{}, failure(Unavailable, ctx)
	}
	*attempted = true
	response, err := p.client.Do(r)
	if err != nil {
		return ExchangeResult{}, failure(Unknown, ctx)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, c.MaxResponseBytes+1))
	defer clear(raw)
	if err != nil || int64(len(raw)) > c.MaxResponseBytes {
		return ExchangeResult{}, failure(Unknown, ctx)
	}
	received := c.Clock.Now()
	parsed, kind := parseTokenResponse(response.StatusCode, response.Header.Get("Content-Type"), raw, c, false, false)
	if kind != "" {
		return ExchangeResult{}, failure(kind, ctx)
	}
	defer parsed.clear()
	if received.IsZero() {
		return ExchangeResult{}, failure(Unknown, ctx)
	}
	expires := received.Add(time.Duration(parsed.expires) * time.Second)
	observation := c.Clock.Now()
	if observation.Before(received) || !expires.After(observation) {
		return ExchangeResult{}, failure(InvalidProof, ctx)
	}
	r, err = http.NewRequestWithContext(ctx, http.MethodGet, p.profile.Details.UserInfoEndpoint, nil)
	if err != nil {
		return ExchangeResult{}, failure(Unknown, ctx)
	}
	r.Header.Set("Authorization", "Bearer "+string(parsed.access))
	r.Header.Set("Accept", "application/json")
	user, err := p.client.Do(r)
	if err != nil {
		return ExchangeResult{}, failure(Unknown, ctx)
	}
	defer user.Body.Close()
	data, err := io.ReadAll(io.LimitReader(user.Body, c.MaxResponseBytes+1))
	defer clear(data)
	if err != nil || int64(len(data)) > c.MaxResponseBytes {
		return ExchangeResult{}, failure(Unknown, ctx)
	}
	if user.StatusCode == 401 || user.StatusCode == 403 {
		return ExchangeResult{}, failure(InvalidProof, ctx)
	}
	media, _, mediaErr := mime.ParseMediaType(user.Header.Get("Content-Type"))
	if user.StatusCode != 200 || mediaErr != nil || media != "application/json" || !utf8.Valid(data) {
		return ExchangeResult{}, failure(Unknown, ctx)
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	budget := 0
	value, err := readJSON(d, 0, &budget)
	if err != nil {
		return ExchangeResult{}, failure(InvalidProof, ctx)
	}
	if _, err = d.Token(); err != io.EOF {
		return ExchangeResult{}, failure(InvalidProof, ctx)
	}
	fields, ok := value.(map[string]any)
	if !ok {
		return ExchangeResult{}, failure(InvalidProof, ctx)
	}
	number, ok := fields[p.profile.Details.SubjectClaim].(json.Number)
	if !ok {
		return ExchangeResult{}, failure(InvalidProof, ctx)
	}
	id, err := number.Int64()
	if err != nil || id <= 0 || number.String() != strconv.FormatInt(id, 10) {
		return ExchangeResult{}, failure(InvalidProof, ctx)
	}
	until := observation.Add(p.profile.Details.ProofLifetime)
	if expires.Before(until) {
		until = expires
	}
	if now := c.Clock.Now(); now.Before(observation) || !until.After(now) {
		return ExchangeResult{}, failure(InvalidProof, ctx)
	}
	owner := &tokenOwner{access: bytes.Clone(parsed.access), refresh: bytes.Clone(parsed.refresh)}
	tokens := TokenSet{owner: func() *tokenOwner { return owner }, receivedAt: received, expiresAt: expires, requested: slices.Clone(c.Scopes), granted: slices.Clone(parsed.scopes), scopeReported: parsed.scopeReported}
	return ExchangeResult{Identity: ProviderIdentity{provider: c.ID, issuer: c.Issuer, subject: strconv.FormatInt(id, 10), evidenceExpiresAt: until.UTC()}, Tokens: tokens}, nil
}
