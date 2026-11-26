// Package onetap validates the selected Google One Tap callback browser seam.
// Validation is read-only provider evidence, not local authentication or durable
// state admission. See README.md for the deliberately unsupported boundaries.
package onetap

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
)

// ErrorKind is a stable, redacted validation outcome.
type ErrorKind string

const (
	// InvalidInput rejects configuration or malformed bounded callback input.
	InvalidInput ErrorKind = "invalid_input"
	// Denied rejects CSRF, origin or original transaction binding.
	Denied ErrorKind = "denied"
	// InvalidProof rejects the signed Google credential.
	InvalidProof ErrorKind = "invalid_proof"
	// Unavailable preserves only context cancellation or deadline information.
	Unavailable ErrorKind = "unavailable"
)

// Error never retains request, provider, key-set or adapter diagnostics.
type Error struct {
	kind  ErrorKind
	cause error
}

func (e *Error) Error() string { return "onetap: " + string(e.Kind()) }

// Kind returns the stable classification; nil means InvalidInput.
func (e *Error) Kind() ErrorKind {
	if e == nil {
		return InvalidInput
	}
	return e.kind
}

// Is preserves context cancellation/deadline without exposing collaborator errors.
func (e *Error) Is(target error) bool {
	return e != nil && e.cause != nil && errors.Is(e.cause, target)
}
func failure(kind ErrorKind, ctx context.Context) error {
	e := &Error{kind: kind}
	if ctx != nil {
		e.cause = ctx.Err()
	}
	return e
}

// Config freezes one native-owned Google provider and exact tenant/origin/policy.
// Clock must be trusted, nonblocking and concurrency-safe. Provider and its key
// set remain caller-owned; close the provider only after admitted calls finish.
// There are no implicit origins, policy defaults or hosted-domain/email grants.
type Config struct {
	Provider         *oauth.OIDCProvider
	TenantID         identity.TenantID
	Origin, PolicyID string
	PolicyVersion    uint64
	Clock            oauth.Clock
}

// AdapterBinding is trusted server input, never a browser command or proof of
// active/unused state. The adapter supplies the ORIGINAL binding from initiation,
// the digest independently computed from this request's original flow cookie,
// and the initiating provider ID/version/client. It must resolve the same flow
// and originating request; copying the stored digest is not cookie validation.
// The existing PreAuthTransaction.Check owns exact nonce/remember/time agreement.
type AdapterBinding struct {
	Transaction          session.PreAuthTransaction
	Expected             session.PreAuthBinding
	Cookie               session.TokenDigest
	ProviderID, ClientID string
	ProviderVersion      uint64
}

// Callback contains borrowed input from ONE callback-mode request. Adapters must
// preserve every g_csrf_token cookie and body occurrence, including duplicates,
// decoding the transport exactly once. Do not use a first-value/map Get parser.
// Origin is the exact initiating request origin, not a client-config field.
// Redirect must be empty: redirect-mode callbacks are not supported here.
// Credential and slices are synchronous borrowed values; do not mutate during
// Validate, clear credential bytes afterwards, and never log this command.
type Callback struct {
	Origin, Redirect      string
	CSRFCookies, CSRFBody []string
	Credential            oauth.GoogleCredential
}

// Validator freezes one callback policy. It is safe for concurrent distinct
// borrowed commands; no IO, goroutines, credentials or mutable stores are owned.
type Validator struct {
	config  Config
	profile oauth.ProviderProfile
}

// NewValidator validates the selected callback policy without IO or clock reads.
func NewValidator(c Config) (*Validator, error) {
	p := c.Provider.Profile()
	if !googleProfile(p) || !visible(string(c.TenantID), 128) || !visible(c.PolicyID, 128) || c.PolicyVersion == 0 || !canonicalOrigin(c.Origin) || c.Clock == nil {
		return nil, failure(InvalidInput, nil)
	}
	return &Validator{config: c, profile: p}, nil
}

// Result is read-only verified provider evidence and the unchanged ORIGINAL flow
// projection. It is NOT one-use admission, a session/link decision or a command
// receipt. The durable owner must re-read current state and policy, reserve the
// exact version, apply/finalize atomically and recover unknown completion.
type Result struct {
	identity oauth.ProviderIdentity
	original session.PreAuthTransactionSpec
}

// Identity returns only the existing generic OAuth verified provider projection.
func (r Result) Identity() oauth.ProviderIdentity { return r.identity }

// Original returns the original private projection; zero is invalid.
func (r Result) Original() (session.PreAuthTransactionSpec, error) {
	if r.identity.Subject() == "" {
		return session.PreAuthTransactionSpec{}, failure(InvalidInput, nil)
	}
	return r.original, nil
}

// Validate checks CSRF and original context before invoking Google's strict
// signature validator. It consumes no state and cannot prevent replay by itself.
func (v *Validator) Validate(ctx context.Context, b AdapterBinding, c Callback) (Result, error) {
	if ctx == nil || v == nil || v.config.Provider == nil || v.config.Clock == nil {
		return Result{}, failure(InvalidInput, ctx)
	}
	if ctx.Err() != nil {
		return Result{}, failure(Unavailable, ctx)
	}
	// Google requires double-submit validation before ID-token verification:
	// developers.google.com/identity/gsi/web/guides/verify-google-id-token.
	// Hashes have fixed length, so mismatch comparison has no value-dependent
	// early acceptance, including differently sized canonical token values.
	if !v.matchesBrowserContext(c) {
		return Result{}, failure(Denied, ctx)
	}
	if !v.matchesOriginalContext(b) {
		return Result{}, failure(Denied, ctx)
	}
	if err := b.Transaction.Check(v.config.Clock.Now(), b.Expected, b.Cookie); err != nil {
		return Result{}, failure(Denied, ctx)
	}
	verified, err := v.verifyCredential(ctx, c.Credential, b.Expected.Intent.Nonce, nil)
	if err != nil {
		return Result{}, err
	}
	original, err := b.Transaction.Bindings()
	if err != nil {
		return Result{}, failure(Denied, ctx)
	}
	return Result{identity: verified, original: original}, nil
}

func (v *Validator) matchesOriginalContext(b AdapterBinding) bool {
	return v.matchesOriginalIntent(b.Expected.Intent) && b.ProviderID == v.profile.ID && b.ProviderVersion == v.profile.Version && b.ClientID == v.profile.ClientID
}

func (v *Validator) matchesBrowserContext(c Callback) bool {
	return validCSRF(c.CSRFCookies, c.CSRFBody) && c.Origin == v.config.Origin && c.Redirect == ""
}

func (v *Validator) matchesOriginalIntent(i session.PreAuthIntent) bool {
	if i.TenantID != v.config.TenantID || i.Origin != v.config.Origin {
		return false
	}
	if i.PolicyID != v.config.PolicyID || i.PolicyVersion != v.config.PolicyVersion {
		return false
	}
	return i.Action == "identity.oauth.onetap-start" && i.Purpose == session.PreAuthSessionIssuance && i.CallbackURL == ""
}

func (v *Validator) verifyCredential(ctx context.Context, credential oauth.GoogleCredential, nonce [32]byte, domain *oauth.GoogleHostedDomain) (oauth.ProviderIdentity, error) {
	if len(credential.IDToken) == 0 || len(credential.IDToken) > v.profile.MaxTokenBytes {
		return oauth.ProviderIdentity{}, failure(InvalidInput, ctx)
	}
	originalNonce := oauth.GoogleCredentialNonce{OriginalNonce: base64.RawURLEncoding.EncodeToString(nonce[:])}
	var verified oauth.ProviderIdentity
	var err error
	if domain == nil {
		verified, err = v.config.Provider.VerifyGoogleCredential(ctx, credential, originalNonce)
	} else {
		verified, err = v.config.Provider.VerifyGoogleCredentialForHostedDomain(ctx, credential, originalNonce, *domain)
	}
	if err == nil {
		return verified, nil
	}
	if ctx.Err() != nil {
		return oauth.ProviderIdentity{}, failure(Unavailable, ctx)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return oauth.ProviderIdentity{}, &Error{kind: Unavailable, cause: contextCause(err)}
	}
	var rejected *oauth.Error
	if errors.As(err, &rejected) && rejected.Kind() == oauth.InvalidInput {
		return oauth.ProviderIdentity{}, failure(InvalidInput, ctx)
	}
	return oauth.ProviderIdentity{}, failure(InvalidProof, ctx)
}

func contextCause(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	return context.DeadlineExceeded
}

// Google does not specify a g_csrf_token encoding. Treat it as an opaque
// RFC6265 cookie-octet value, not a JWT, URL, number or base64 nonce. The
// selected 1KiB admission bound is local resource policy, not a Google limit.
// Canonical values are compared verbatim; whitespace/quotes/escapes deny rather
// than introducing aliases through trimming or another transport decoding pass.
func csrfValue(raw string) bool {
	if len(raw) == 0 || len(raw) > 1024 {
		return false
	}
	for _, b := range []byte(raw) {
		if b < 0x21 || b > 0x7e || b == '"' || b == ',' || b == ';' || b == '\\' {
			return false
		}
	}
	return true
}
func validCSRF(cookies, body []string) bool {
	if len(cookies) != 1 || len(body) != 1 || !csrfValue(cookies[0]) || !csrfValue(body[0]) {
		return false
	}
	a, b := sha256.Sum256([]byte(cookies[0])), sha256.Sum256([]byte(body[0]))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

func googleProfile(p oauth.ProviderProfile) bool {
	if !p.GoogleAccounts || p.ID != "google" || p.Version == 0 || p.Issuer != "https://accounts.google.com" {
		return false
	}
	if p.AuthorizationEndpoint != "https://accounts.google.com/o/oauth2/v2/auth" || p.TokenEndpoint != "https://oauth2.googleapis.com/token" {
		return false
	}
	if p.ClientAuthentication != oauth.ClientSecretPost || !slices.Equal(p.Algorithms, []string{"RS256"}) || !p.NonceRequired || p.NonceBytes != 32 {
		return false
	}
	if len(p.Scopes) < 1 || len(p.Scopes) > 3 || !slices.Contains(p.Scopes, "openid") {
		return false
	}
	for _, scope := range p.Scopes {
		if scope != "openid" && scope != "email" && scope != "profile" {
			return false
		}
	}
	return true
}

func visible(raw string, max int) bool {
	if len(raw) == 0 || len(raw) > max {
		return false
	}
	for _, b := range []byte(raw) {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}

// Exact canonical HTTPS DNS/IPv4 origins only in this initial callback slice.
// Reject aliases rather than silently rewriting persisted origin/cookie intent.
func canonicalOrigin(raw string) bool {
	if !visible(raw, 2048) {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Host == "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || strings.ContainsAny(raw, "#%") || u.Host != strings.ToLower(u.Host) {
		return false
	}
	host := u.Hostname()
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, b := range []byte(label) {
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
				return false
			}
		}
	}
	// WHATWG's special-host parser routes final decimal/hexadecimal numeric
	// labels to IPv4 parsing (url.spec.whatwg.org/#ends-in-a-number-checker).
	// net/url does not perform that browser normalization. Reject aliases and
	// invalid numeric hosts here, or no real browser Origin can match intent.
	if numericFinalLabel(host) {
		address, err := netip.ParseAddr(host)
		if err != nil || !address.Is4() || address.String() != host {
			return false
		}
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || n == 443 || strconv.Itoa(n) != port {
			return false
		}
	} else if strings.Contains(u.Host, ":") {
		return false
	}
	return true
}

func numericFinalLabel(host string) bool {
	last := host[strings.LastIndexByte(host, '.')+1:]
	if strings.HasPrefix(last, "0x") {
		for _, b := range []byte(last[2:]) {
			if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
				return false
			}
		}
		return true
	}
	for _, b := range []byte(last) {
		if b < '0' || b > '9' {
			return false
		}
	}
	return len(last) > 0
}

func redact(s fmt.State) { _, _ = s.Write([]byte("onetap(redacted)")) }

// Format redacts configuration diagnostics.
func (Config) Format(s fmt.State, _ rune) { redact(s) }

// MarshalJSON denies accidental private configuration export.
func (Config) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText denies accidental private configuration export.
func (Config) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// Format redacts all correlated transaction fields.
func (AdapterBinding) Format(s fmt.State, _ rune) { redact(s) }

// MarshalJSON denies accidental transaction export.
func (AdapterBinding) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText denies accidental transaction export.
func (AdapterBinding) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// Format redacts every callback value.
func (Callback) Format(s fmt.State, _ rune) { redact(s) }

// MarshalJSON denies automatic callback serialization.
func (Callback) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText denies automatic callback serialization.
func (Callback) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// Format redacts validated identity and correlated flow fields.
func (Result) Format(s fmt.State, _ rune) { redact(s) }

// MarshalJSON denies accidental identity/flow export.
func (Result) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText denies accidental identity/flow export.
func (Result) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// Format redacts the frozen policy and provider's configuration.
func (*Validator) Format(s fmt.State, _ rune) { redact(s) }

// MarshalJSON denies accidental validator configuration export.
func (*Validator) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText denies accidental validator configuration export.
func (*Validator) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }
