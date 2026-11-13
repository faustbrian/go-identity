package oauth

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	authoidc "github.com/faustbrian/go-authentication/oidc"
	googleoidc "github.com/faustbrian/go-authentication/oidc/v2"
	identity "github.com/faustbrian/go-identity"
)

// ClientAuthentication selects exactly one token-endpoint credential channel.
type ClientAuthentication string

const (
	// PublicClient uses client_id in the form and forbids a secret.
	PublicClient ClientAuthentication = "none"
	// ClientSecretBasic uses RFC6749 section2.3.1 form-escaped Basic credentials.
	ClientSecretBasic ClientAuthentication = "client_secret_basic"
	// ClientSecretPost sends credentials only in the HTTPS token request form.
	// Select it explicitly for providers whose pinned profile requires it;
	// RFC6749 section2.3.1 prefers Basic where that channel is supported.
	ClientSecretPost ClientAuthentication = "client_secret_post"
)

func (method ClientAuthentication) valid() bool {
	return method == PublicClient || method == ClientSecretBasic || method == ClientSecretPost
}

// Clock supplies trusted validation/response-receipt time. It must be safe for
// concurrent use, nonblocking and panic-free. Nil selects the system clock.
type Clock interface{ Now() time.Time }
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// SigningKeySet is the existing strict OIDC validator's signature seam, not a
// token-to-identity bypass. Configure trusted immutable/rotated keys. Implementors
// must verify signatures, honor context and be concurrency-safe. This selected
// profile uses locally available configured keys, not remote-key acquisition.
// No discovery or issuer-selected URL is performed by this client.
type SigningKeySet interface {
	VerifySignature(context.Context, string) ([]byte, error)
}

// OIDCConfig is trusted startup configuration for one finite profile. Every
// endpoint is explicit HTTPS, with no query, fragment, userinfo or normalization.
// Unknown capabilities are not inferred. Query/code/S256/nonce are fixed.
// ClientSecret is copied; the caller owns clearing its source. KeySet and Clock
// remain caller-owned trusted concurrent collaborators. HTTPClient must use a
// standard *http.Transport; the client clones it, rejects insecure TLS, removes
// cookies/redirects/replay and owns its connections. Nil selects fresh defaults.
type OIDCConfig struct {
	ID, Issuer, AuthorizationEndpoint, TokenEndpoint, RedirectURI, ClientID string
	// Version is positive native-owned configuration identity, never callback data.
	Version                     uint64
	ClientSecret                []byte
	ClientAuthentication        ClientAuthentication
	Scopes, Algorithms          []string
	KeySet                      SigningKeySet
	HTTPClient                  *http.Client
	Clock                       Clock
	ClockSkew, Timeout          time.Duration
	MaxResponseBytes            int64
	MaxTokenBytes, MaxCodeBytes int
}

// Format redacts client credentials and configuration diagnostics.
func (OIDCConfig) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("oauth.OIDCConfig(redacted)")) }

// MarshalJSON refuses accidental credential serialization.
func (OIDCConfig) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText refuses accidental credential serialization.
func (OIDCConfig) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// Provider is the protocol boundary consumed after native state admission. It
// cannot reserve state, decrypt persisted PKCE, link identities or issue sessions.
// Exchange is never an idempotency or one-use guarantee: the native owner must
// serialize callbacks and preserve Unknown for authoritative reconciliation.
type Provider interface {
	ID() string
	Profile() ProviderProfile
	Authorization(context.Context, AuthorizationParameters) (AuthorizationRequest, error)
	Exchange(context.Context, identity.OAuthCallbackInput, PKCEVerifier, string) (ExchangeResult, error)
}

// OIDCProvider is immutable apart from its synchronized secret/closed owner.
// It must not be copied. Concurrent calls through its pointer are supported with
// distinct admitted callback/verifier custody.
type OIDCProvider struct {
	config         OIDCConfig
	client         *http.Client
	transport      *http.Transport
	mu             sync.Mutex
	secret         []byte
	closed         bool
	googleAccounts bool
}

// NewOIDCProvider validates configuration without network I/O. Zero limits select
// 64KiB response, 16KiB token, 4KiB code, 10s timeout and 60s skew. Response limits
// are 1KiB..1MiB; tokens 256B..16KiB; codes 1..64KiB; timeout 1..30s; skew 1ns..5m.
// Only ES256/RS256 and 1..32 unique scopes including openid are selected.
func NewOIDCProvider(c OIDCConfig) (*OIDCProvider, error) {
	if c.Clock == nil {
		c.Clock = systemClock{}
	}
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
	if c.ClockSkew == 0 {
		c.ClockSkew = time.Minute
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
	if c.Version == 0 || !identifier(c.ID) || !visible(c.ClientID, 1, 1024) || !httpsURL(c.Issuer) || !httpsURL(c.AuthorizationEndpoint) || !httpsURL(c.TokenEndpoint) || !httpsURL(c.RedirectURI) || c.KeySet == nil || c.Timeout < time.Second || c.Timeout > 30*time.Second || c.ClockSkew <= 0 || c.ClockSkew > 5*time.Minute || c.MaxResponseBytes < 1024 || c.MaxResponseBytes > 1<<20 || c.MaxTokenBytes < 256 || c.MaxTokenBytes > 16<<10 || c.MaxCodeBytes < 1 || c.MaxCodeBytes > 64<<10 {
		return nil, failure(InvalidInput, nil)
	}
	if !c.ClientAuthentication.valid() {
		return nil, failure(InvalidInput, nil)
	}
	if c.ClientAuthentication == PublicClient && len(c.ClientSecret) != 0 {
		return nil, failure(InvalidInput, nil)
	}
	if c.ClientAuthentication != PublicClient && !visible(string(c.ClientSecret), 1, 4096) {
		return nil, failure(InvalidInput, nil)
	}
	if !validScopes(c.Scopes) || !slices.Contains(c.Scopes, "openid") || len(c.Algorithms) == 0 || len(c.Algorithms) > 2 {
		return nil, failure(InvalidInput, nil)
	}
	seen := map[string]bool{}
	for _, alg := range c.Algorithms {
		if alg != "ES256" && alg != "RS256" || seen[alg] {
			return nil, failure(InvalidInput, nil)
		}
		seen[alg] = true
	}
	if _, err := authoidc.NewWithKeySet(validatorConfig(c, nil), c.KeySet); err != nil {
		return nil, failure(InvalidInput, nil)
	}
	var transport *http.Transport
	if c.HTTPClient != nil && c.HTTPClient.Transport != nil {
		original, ok := c.HTTPClient.Transport.(*http.Transport)
		if !ok || original == nil {
			return nil, failure(InvalidInput, nil)
		}
		transport = original.Clone()
	} else {
		transport = &http.Transport{DialContext: (&net.Dialer{Timeout: c.Timeout, KeepAlive: -1}).DialContext, TLSHandshakeTimeout: c.Timeout, ResponseHeaderTimeout: c.Timeout, MaxResponseHeaderBytes: 16 << 10}
	}
	// net/http Transport.DialTLS* assumes its returned connection already passed
	// TLS verification and does not apply TLSClientConfig. Such dialers would
	// bypass this profile's authenticated HTTPS boundary (Go1.27 transport.go).
	//lint:ignore SA1019 The legacy hook still bypasses net/http TLS verification; reject both hooks rather than silently admit the deprecated path.
	hasLegacyTLSDial := transport.DialTLS != nil //nolint:staticcheck // SA1019: The legacy hook still bypasses net/http TLS verification; reject both TLS dial hooks.
	if hasLegacyTLSDial || transport.DialTLSContext != nil || transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		return nil, failure(InvalidInput, nil)
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	tlsConfig := transport.TLSClientConfig
	tokenURL, _ := url.Parse(c.TokenEndpoint)
	if tlsConfig.ServerName != "" && tlsConfig.ServerName != tokenURL.Hostname() || tlsConfig.MinVersion != 0 && (tlsConfig.MinVersion < tls.VersionTLS12 || tlsConfig.MinVersion > tls.VersionTLS13) || tlsConfig.MaxVersion != 0 && (tlsConfig.MaxVersion < tls.VersionTLS12 || tlsConfig.MaxVersion > tls.VersionTLS13) || tlsConfig.MinVersion != 0 && tlsConfig.MaxVersion != 0 && tlsConfig.MinVersion > tlsConfig.MaxVersion {
		return nil, failure(InvalidInput, nil)
	}
	if tlsConfig.MinVersion == 0 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	// Fresh HTTP/1 connections plus a body with no GetBody prevent net/http's
	// transparent retry of reused connections/HTTP2 streams (RFC6749 4.1.2 codes
	// are single-use). Ambient cookies and redirects are intentionally absent.
	transport.DisableKeepAlives = true
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	// Go1.27 Transport.Protocols overrides TLSNextProto/ForceAttemptHTTP2. Both
	// inherited protocol selection and TLS ALPN must honor our one-send HTTP/1
	// profile rather than re-enable a transport with transparent stream retries.
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetHTTP1(true)
	tlsConfig.NextProtos = []string{"http/1.1"}
	c.Scopes = slices.Clone(c.Scopes)
	c.Algorithms = slices.Clone(c.Algorithms)
	secret := bytes.Clone(c.ClientSecret)
	c.ClientSecret = nil
	c.HTTPClient = nil
	p := &OIDCProvider{config: c, secret: secret, transport: transport}
	p.client = &http.Client{Transport: transport, Timeout: c.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return p, nil
}

const googleAccountsIssuer = "https://accounts.google.com"

// NewGoogleAccountsProvider selects Google's two documented signed ID-token
// issuer forms through authentication/oidc/v2's Google-only validator. Issuer
// must be exactly https://accounts.google.com. Both signed forms project that
// canonical issuer and the unchanged subject into one account namespace. Raw
// callback iss, explicit endpoints, trusted keys, claims, nonce, PKCE and hash
// bindings remain strict. Returned Google userinfo.email/profile URI scopes map
// only to equivalent requested email/profile scopes, collapsing equivalents
// without expanding permissions. No discovery, generic aliases or token rewriting occur.
// Configuration, defaults, resource ownership and concurrency are NewOIDCProvider's.
// Construction performs no network IO. Existing NewOIDCProvider stays strict.
func NewGoogleAccountsProvider(c OIDCConfig) (*OIDCProvider, error) {
	if c.Issuer != googleAccountsIssuer {
		return nil, failure(InvalidInput, nil)
	}
	p, err := NewOIDCProvider(c)
	if err != nil {
		return nil, err
	}
	if _, err := googleoidc.NewGoogleAccountsWithKeySet(googleValidatorConfig(p.config, nil), p.config.KeySet); err != nil {
		p.Close()
		return nil, failure(InvalidInput, nil)
	}
	p.googleAccounts = true
	return p, nil
}

func validatorConfig(c OIDCConfig, nonce authoidc.NonceValidator) authoidc.Config {
	return authoidc.Config{Issuer: c.Issuer, ClientID: c.ClientID, Algorithms: c.Algorithms, Clock: c.Clock, ClockSkew: c.ClockSkew, NonceValidator: nonce, MaxTokenBytes: c.MaxTokenBytes, MaxClaims: 128, MaxClaimDepth: 8}
}

func googleValidatorConfig(c OIDCConfig, nonce googleoidc.NonceValidator) googleoidc.Config {
	return googleoidc.Config{Issuer: c.Issuer, ClientID: c.ClientID, Algorithms: c.Algorithms, Clock: c.Clock, ClockSkew: c.ClockSkew, NonceValidator: nonce, MaxTokenBytes: c.MaxTokenBytes, MaxClaims: 128, MaxClaimDepth: 8}
}

// ID returns the configured provider identity, or empty for nil.
func (p *OIDCProvider) ID() string {
	if p == nil {
		return ""
	}
	return p.config.ID
}

// Close clears the owned client secret and closes idle connections. It is
// idempotent; admitted exchanges finish on their private copies. Caller contexts
// own cancellation of active requests. It never closes caller-owned transports.
func (p *OIDCProvider) Close() {
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

// Format redacts the provider and retained configuration.
func (*OIDCProvider) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.OIDCProvider(redacted)"))
}

// AuthorizationParameters carries native-generated state/nonce and S256
// challenge only. It carries no authority: all transaction bindings and one-use
// persistence remain native-owned. State/nonce each encode exactly 32 random
// bytes; challenge encodes exactly 32 digest bytes. Randomness is native-owned.
type AuthorizationParameters struct{ State, Nonce, PKCEChallenge string }

// Format redacts state and nonce.
func (AuthorizationParameters) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.AuthorizationParameters(redacted)"))
}

// MarshalJSON refuses accidental serialization of raw state/nonce.
func (AuthorizationParameters) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText refuses accidental serialization or secret-bearing map keys.
func (AuthorizationParameters) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// AuthorizationRequest is the exact trusted authorization URL. Zero is invalid.
// Deliberate URL access transfers secret-bearing state/nonce to the browser;
// callers must not log, persist or reuse it outside the bound native flow.
type AuthorizationRequest struct{ url string }

// URL returns the exact authorization redirect, or empty for zero values.
func (r AuthorizationRequest) URL() string { return r.url }

// Format redacts authorization state and nonce.
func (AuthorizationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.AuthorizationRequest(redacted)"))
}

// MarshalJSON refuses accidental authorization-state serialization.
func (AuthorizationRequest) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText refuses accidental authorization-state serialization.
func (AuthorizationRequest) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// Authorization builds fixed code/query/S256 parameters with exact configured
// client, redirect and scopes. Caller parameters cannot override configuration.
func (p *OIDCProvider) Authorization(ctx context.Context, a AuthorizationParameters) (AuthorizationRequest, error) {
	if ctx == nil || !p.ready() {
		return AuthorizationRequest{}, failure(InvalidInput, ctx)
	}
	if ctx.Err() != nil {
		return AuthorizationRequest{}, failure(Unavailable, ctx)
	}
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed || !canonical32(a.State) || !canonical32(a.Nonce) || !canonical32(a.PKCEChallenge) {
		return AuthorizationRequest{}, failure(InvalidInput, ctx)
	}
	q := url.Values{"response_type": {"code"}, "response_mode": {"query"}, "client_id": {p.config.ClientID}, "redirect_uri": {p.config.RedirectURI}, "scope": {strings.Join(p.config.Scopes, " ")}, "state": {a.State}, "nonce": {a.Nonce}, "code_challenge": {a.PKCEChallenge}, "code_challenge_method": {"S256"}}
	return AuthorizationRequest{p.config.AuthorizationEndpoint + "?" + q.Encode()}, nil
}

// ProviderIdentity contains only identity admitted by the existing full strict
// OIDC validator. It is not a local identity, account-link or session proof.
// Mutable/unvalidated claim maps and authv1 principal types are not exposed.
type ProviderIdentity struct {
	provider, issuer, subject         string
	authenticatedAt                   time.Time
	hasAuthenticationTime             bool
	idTokenIssuedAt, idTokenExpiresAt time.Time
}

// ProviderID returns the immutable configured provider ID.
func (i ProviderIdentity) ProviderID() string { return i.provider }

// Issuer returns the verified account issuer. Only the explicitly selected
// Google Accounts provider canonicalizes its two documented signed forms.
func (i ProviderIdentity) Issuer() string { return i.issuer }

// Subject returns the verified stable provider subject, or empty for zero.
func (i ProviderIdentity) Subject() string { return i.subject }

// AuthenticationTime returns only an explicitly present validated auth_time.
// Missing auth_time returns zero,false: OIDC token iat is not authentication
// freshness and never replaces native session or reauthentication authority.
func (i ProviderIdentity) AuthenticationTime() (time.Time, bool) {
	return i.authenticatedAt, i.hasAuthenticationTime
}

// IDTokenIssuedAt is the validated ID-token iat, not actual authentication or
// native reauthentication time. It grants no local identity/session authority.
func (i ProviderIdentity) IDTokenIssuedAt() time.Time { return i.idTokenIssuedAt }

// IDTokenExpiresAt is the validated source proof's exp, distinct from the access
// token's expires_in. Derived native proof must not outlive this instant, the
// original flow or relevant local authority; the native owner enforces that cap.
func (i ProviderIdentity) IDTokenExpiresAt() time.Time { return i.idTokenExpiresAt }

// ExchangeResult returns verified provider identity and mandatory secret custody.
// Callers must Destroy Tokens after encryption/use, including later native denial.
type ExchangeResult struct {
	Identity ProviderIdentity
	Tokens   TokenSet
}

// Exchange makes exactly one bounded POST with the original callback code and
// verifier bytes. The caller MUST first authenticate and reserve native state,
// validate issuer/transport/full transaction bindings, then decrypt PKCE. This
// client intentionally cannot establish those authorities. Expected nonce must
// come from that transaction, never from the inbound callback. No retries,
// redirects, UserInfo fallback, refresh, token retention or session issuance occur.
func (p *OIDCProvider) Exchange(ctx context.Context, input identity.OAuthCallbackInput, verifier PKCEVerifier, nonce string) (result ExchangeResult, err error) {
	if ctx == nil || !p.ready() || !canonical32(nonce) {
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
	secret := make([]byte, len(p.secret))
	copy(secret, p.secret)
	p.mu.Unlock()
	defer clear(secret)
	ctx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()
	var exchangeErr error
	attempted := false
	borrowErr := input.Use(ctx, func(ctx context.Context, code, _ []byte) error {
		if len(code) > p.config.MaxCodeBytes {
			exchangeErr = failure(InvalidInput, ctx)
			return nil
		}
		exchangeErr = verifier.use(ctx, func(value []byte) error {
			result, err = p.exchange(ctx, code, value, secret, nonce, &attempted)
			return err
		})
		return nil
	})
	if borrowErr != nil {
		result.Tokens.Destroy()
		// Original callback custody suppresses panics. A trusted collaborator
		// failure after HTTP began must not turn a consumed/ambiguous code into
		// a pre-send local denial and accidentally release native reservation.
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

func (p *OIDCProvider) exchange(ctx context.Context, code, verifier, secret []byte, nonce string, attempted *bool) (ExchangeResult, error) {
	q := url.Values{"grant_type": {"authorization_code"}, "code": {string(code)}, "code_verifier": {string(verifier)}, "redirect_uri": {p.config.RedirectURI}}
	if p.config.ClientAuthentication == PublicClient {
		q.Set("client_id", p.config.ClientID)
	}
	if p.config.ClientAuthentication == ClientSecretPost {
		q.Set("client_id", p.config.ClientID)
		q.Set("client_secret", string(secret))
	}
	encoded := []byte(q.Encode())
	bodyOwner := newTokenRequestBody(encoded)
	defer func() { _ = bodyOwner.Close() }()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.config.TokenEndpoint, bodyOwner)
	if err != nil {
		return ExchangeResult{}, failure(InvalidInput, ctx)
	}
	request.ContentLength = int64(len(encoded))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	if p.config.ClientAuthentication == ClientSecretBasic {
		request.SetBasicAuth(url.QueryEscape(p.config.ClientID), url.QueryEscape(string(secret)))
	}
	if ctx.Err() != nil {
		return ExchangeResult{}, failure(Unavailable, ctx)
	}
	*attempted = true
	response, err := p.client.Do(request)
	if err != nil {
		return ExchangeResult{}, failure(Unknown, ctx)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, p.config.MaxResponseBytes+1))
	defer clear(body)
	if err != nil || int64(len(body)) > p.config.MaxResponseBytes {
		return ExchangeResult{}, failure(Unknown, ctx)
	}
	receivedAt := p.config.Clock.Now()
	parsed, kind := parseResponse(response.StatusCode, response.Header.Get("Content-Type"), body, p.config, p.googleAccounts)
	if kind != "" {
		return ExchangeResult{}, failure(kind, ctx)
	}
	defer parsed.clear()
	nonceCheck := func(_ context.Context, actual string) error {
		if subtle.ConstantTimeCompare([]byte(actual), []byte(nonce)) != 1 {
			return failure(InvalidProof, nil)
		}
		return nil
	}
	// This private getter projection consumes only successful upstream validation.
	// V1 and V2 retain distinct principal/proof types; neither is manufactured or
	// converted into the other's authentication authority.
	var principal interface {
		Issuer() string
		Subject() string
		AuthenticatedAt() time.Time
	}
	var validateBinding func(string, string) error
	if p.googleAccounts {
		validator, createErr := googleoidc.NewGoogleAccountsWithKeySet(googleValidatorConfig(p.config, googleoidc.NonceValidatorFunc(nonceCheck)), p.config.KeySet)
		if createErr != nil {
			return ExchangeResult{}, failure(InvalidProof, ctx)
		}
		principal, err = validator.ValidateBearer(ctx, string(parsed.id))
		validateBinding = func(access, code string) error {
			_, err := validator.ValidateIDToken(ctx, string(parsed.id), googleoidc.TokenBinding{AccessToken: access, AuthorizationCode: code})
			return err
		}
	} else {
		validator, createErr := authoidc.NewWithKeySet(validatorConfig(p.config, authoidc.NonceValidatorFunc(nonceCheck)), p.config.KeySet)
		if createErr != nil {
			return ExchangeResult{}, failure(InvalidProof, ctx)
		}
		principal, err = validator.ValidateBearer(ctx, string(parsed.id))
		validateBinding = func(access, code string) error {
			_, err := validator.ValidateIDToken(ctx, string(parsed.id), authoidc.TokenBinding{AccessToken: access, AuthorizationCode: code})
			return err
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			return ExchangeResult{}, failure(Unknown, ctx)
		}
		return ExchangeResult{}, failure(InvalidProof, ctx)
	}
	// Both selected validators remove registered protocol claims from Principal.Claims
	// and substitute iat when auth_time is absent. Only after full validation do
	// we inspect presence in the same bounded, authenticated payload. Optional
	// at_hash/c_hash remain optional (OIDC Core 3.1.3.6); present hashes are then
	// checked by that existing validator against the original token/code bytes.
	metadata, ok := validatedMetadata(parsed.id)
	if !ok {
		return ExchangeResult{}, failure(InvalidProof, ctx)
	}
	issuedAt, issuedOK := validatedNumericDate(metadata.IssuedAt)
	expiresAt, expiresOK := validatedNumericDate(metadata.ExpiresAt)
	if !issuedOK || !expiresOK {
		return ExchangeResult{}, failure(InvalidProof, ctx)
	}
	var accessBinding, codeBinding string
	if len(metadata.AccessHash) > 0 {
		accessBinding = string(parsed.access)
	}
	if len(metadata.CodeHash) > 0 {
		codeBinding = string(code)
	}
	if accessBinding != "" || codeBinding != "" {
		if err := validateBinding(accessBinding, codeBinding); err != nil {
			if ctx.Err() != nil {
				return ExchangeResult{}, failure(Unknown, ctx)
			}
			return ExchangeResult{}, failure(InvalidProof, ctx)
		}
	}
	identityTime := time.Time{}
	hasTime := len(metadata.AuthenticationTime) > 0
	if hasTime {
		identityTime = principal.AuthenticatedAt()
	}
	owner := &tokenOwner{access: bytes.Clone(parsed.access), refresh: bytes.Clone(parsed.refresh), id: bytes.Clone(parsed.id)}
	tokens := TokenSet{owner: func() *tokenOwner { return owner }, receivedAt: receivedAt, expiresAt: receivedAt.Add(time.Duration(parsed.expires) * time.Second), requested: slices.Clone(p.config.Scopes), granted: slices.Clone(parsed.scopes), scopeReported: parsed.scopeReported}
	return ExchangeResult{Identity: ProviderIdentity{p.ID(), principal.Issuer(), principal.Subject(), identityTime, hasTime, issuedAt, expiresAt}, Tokens: tokens}, nil
}

type validatedTokenMetadata struct {
	AccessHash         json.RawMessage `json:"at_hash"`
	CodeHash           json.RawMessage `json:"c_hash"`
	AuthenticationTime json.RawMessage `json:"auth_time"`
	IssuedAt           json.RawMessage `json:"iat"`
	ExpiresAt          json.RawMessage `json:"exp"`
}

func validatedMetadata(token []byte) (validatedTokenMetadata, bool) {
	var metadata validatedTokenMetadata
	parts := bytes.Split(token, []byte("."))
	if len(parts) != 3 {
		return metadata, false
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(string(parts[1]))
	defer clear(payload)
	if err != nil {
		return metadata, false
	}
	err = json.Unmarshal(payload, &metadata)
	return metadata, err == nil
}

// This is metadata conversion only, after strict OIDC admission. Its exact
// rational truncation and supported year range match oidc/v1.0.1 validator.go's
// numericDate; float conversion would silently change accepted fractional dates.
func validatedNumericDate(raw json.RawMessage) (time.Time, bool) {
	var number json.Number
	if err := json.Unmarshal(raw, &number); err != nil {
		return time.Time{}, false
	}
	seconds, ok := new(big.Rat).SetString(number.String())
	if !ok || seconds.Cmp(new(big.Rat).SetInt64(-62135596800)) < 0 || seconds.Cmp(new(big.Rat).SetInt64(253402300799)) > 0 {
		return time.Time{}, false
	}
	whole := new(big.Int).Quo(seconds.Num(), seconds.Denom())
	product := new(big.Int).Mul(new(big.Int).Set(whole), seconds.Denom())
	remainder := new(big.Int).Sub(seconds.Num(), product)
	nanoseconds := new(big.Int).Quo(new(big.Int).Mul(remainder, big.NewInt(int64(time.Second))), seconds.Denom())
	return time.Unix(whole.Int64(), nanoseconds.Int64()).UTC(), true
}

// ProviderProfile is a defensive secret-free projection of trusted immutable
// configuration, including fixed protocol and effective default limits. Bind its
// exact Version and fields into the native transaction; it is not callback input
// or proof of current provider configuration. Credentials/key handles are absent.
type ProviderProfile struct {
	ID                                                                  string
	Version                                                             uint64
	Issuer, ClientID, AuthorizationEndpoint, TokenEndpoint, RedirectURI string
	ClientAuthentication                                                ClientAuthentication
	Scopes, Algorithms                                                  []string
	ResponseMode, PKCEMethod                                            string
	NonceRequired                                                       bool
	StateBytes, NonceBytes                                              int
	Timeout, ClockSkew                                                  time.Duration
	MaxResponseBytes                                                    int64
	MaxTokenBytes, MaxCodeBytes                                         int
	// GoogleAccounts selects only the documented signed-token issuer policy.
	// Omitted false preserves existing canonical native profile bytes.
	GoogleAccounts bool `json:",omitempty"`
}

// Profile returns a fresh projection with cloned slices. Nil/zero providers
// have an empty profile and expose no protocol capability.
func (p *OIDCProvider) Profile() ProviderProfile {
	if !p.ready() {
		return ProviderProfile{}
	}
	c := p.config
	return ProviderProfile{ID: c.ID, Version: c.Version, Issuer: c.Issuer, ClientID: c.ClientID, AuthorizationEndpoint: c.AuthorizationEndpoint, TokenEndpoint: c.TokenEndpoint, RedirectURI: c.RedirectURI, ClientAuthentication: c.ClientAuthentication, Scopes: slices.Clone(c.Scopes), Algorithms: slices.Clone(c.Algorithms), ResponseMode: "query", PKCEMethod: "S256", NonceRequired: true, StateBytes: 32, NonceBytes: 32, Timeout: c.Timeout, ClockSkew: c.ClockSkew, MaxResponseBytes: c.MaxResponseBytes, MaxTokenBytes: c.MaxTokenBytes, MaxCodeBytes: c.MaxCodeBytes, GoogleAccounts: p.googleAccounts}
}

func (p *OIDCProvider) ready() bool {
	return p != nil && p.client != nil && p.transport != nil && p.config.Version > 0
}

func canonical32(raw string) bool {
	if len(raw) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	defer clear(decoded)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == raw
}
func identifier(raw string) bool {
	if len(raw) < 1 || len(raw) > 128 {
		return false
	}
	for _, b := range []byte(raw) {
		if (b < 'a' || b > 'z') && (b < '0' || b > '9') && b != '-' && b != '_' {
			return false
		}
	}
	return true
}
func visible(raw string, min, max int) bool {
	if len(raw) < min || len(raw) > max {
		return false
	}
	for _, b := range []byte(raw) {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}
func httpsURL(raw string) bool {
	if !visible(raw, 1, 2048) || strings.ContainsAny(raw, "\\#*") {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.Hostname() != "" && u.User == nil && u.Opaque == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.String() == raw
}
func validScopes(scopes []string) bool {
	if len(scopes) < 1 || len(scopes) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, s := range scopes {
		if !visible(s, 1, 128) || strings.ContainsAny(s, " \"\\") || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}

// ProviderRegistry is an immutable exact-ID registry. Construction snapshots the
// list, not the provider's lifecycle; caller-owned providers must remain immutable
// and open while used. Zero registry has no capabilities. It never owns Close.
type ProviderRegistry struct{ providers map[string]Provider }

// NewProviderRegistry rejects nil/duplicate/invalid IDs and more than 64 entries.
func NewProviderRegistry(providers ...Provider) (ProviderRegistry, error) {
	if len(providers) == 0 || len(providers) > 64 {
		return ProviderRegistry{}, failure(InvalidInput, nil)
	}
	registry := ProviderRegistry{providers: make(map[string]Provider, len(providers))}
	for _, p := range providers {
		if p == nil || !identifier(p.ID()) || registry.providers[p.ID()] != nil {
			return ProviderRegistry{}, failure(InvalidInput, nil)
		}
		registry.providers[p.ID()] = p
	}
	return registry, nil
}

// Lookup returns only the exact configured provider; unknown IDs fail closed.
func (r ProviderRegistry) Lookup(id string) (Provider, bool) { p, ok := r.providers[id]; return p, ok }
