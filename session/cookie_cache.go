package session

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

// CookieCacheConfig selects an opt-in encrypted companion cookie. Credential
// and Cache are distinct validated host-only policies with identical SameSite.
// MaximumCookieBytes is 512..3800 and bounds the entire emitted Set-Cookie value,
// including name, base64 payload, all attributes and fixed Priority=High.
// The codec's payload maximum age must be 1s..5m. Zero is disabled/unconfigured,
// not an implicit profile. Cache cookies never replace the original credential.
type CookieCacheConfig struct {
	Credential, Cache  CookiePolicy
	MaximumCookieBytes int
}

// CookieCache composes encrypted positive admission and secure browser framing.
// Concurrent calls are safe with concurrent-safe codec dependencies. It owns no
// HTTP handler, store, background work or authority. HTTP must select only its
// configured companion values, reject mixed original credential sources and
// enforce origin/CSRF/no-store rules; this type cannot validate those requests.
// No optional cache error authorizes stale state. Removal is not revocation.
type CookieCache struct {
	codec  *EncryptedCacheCodec
	config CookieCacheConfig
}

// NewCookieCache validates explicit browser cache policy without IO. The
// credential cookie cannot be overwritten or widened by cache configuration.
// This encrypted profile is required because the full projection is private.
func NewCookieCache(codec *EncryptedCacheCodec, config CookieCacheConfig) (*CookieCache, error) {
	if codec == nil || codec.service == nil || codec.crypto == nil || codec.service.reader == nil || issuerNil(codec.service.config.Clock) || codec.config.MaximumAge < time.Second || config.Credential.name == "" || config.Cache.name == "" || config.Credential.name == config.Cache.name || config.Credential.sameSite != config.Cache.sameSite || config.MaximumCookieBytes < 512 || config.MaximumCookieBytes > 3800 {
		return nil, ErrInvalidInput
	}
	return &CookieCache{codec, config}, nil
}

// CacheCookie owns one immutable encrypted Set-Cookie value. Copies are safe
// concurrently. It contains correlated ciphertext, never the original bearer;
// it is not sufficient to authenticate alone. Zero is invalid. Formatting and
// implicit JSON/text export redact or deny. HeaderValue is the explicit HTTP
// delivery boundary; never log its returned value.
type CacheCookie struct{ header string }

// HeaderValue explicitly exports the owned immutable Set-Cookie value for HTTP
// delivery. Repeated export does not renew expiry or authoritative freshness.
func (c CacheCookie) HeaderValue() (string, error) {
	if c.header == "" {
		return "", ErrInvalidInput
	}
	return c.header, nil
}

// Put frames only genuine same-service cookie admission. It preserves the
// resolved remember choice: browser cookies omit Expires/Max-Age; persistent
// cache cookies are bounded by at most five minutes and original session expiry.
// Encryption latency is subtracted, not added to the cookie deadline. Less than
// one remaining second denies rather than becoming an accidental session cookie.
// Exact total size is checked; no truncation, chunking or cookie-attribute
// downgrade occurs. Errors return no header. Cookie persistence never extends
// the payload's original exclusive authoritative validity deadline.
func (c *CookieCache) Put(ctx context.Context, result GetResult) (out CacheCookie, err error) {
	defer func() {
		if recover() != nil {
			out, err = CacheCookie{}, ErrUnavailable
		}
	}()
	if c == nil || c.codec == nil || ctx == nil {
		return out, ErrInvalidInput
	}
	if result.validity == nil || result.validity.owner != c.codec.service || result.validity.transport != CredentialCookie {
		return out, ErrUnauthenticated
	}
	bounded, stop := context.WithTimeout(ctx, c.codec.service.config.MaximumDuration)
	defer stop()
	if bounded.Err() != nil {
		return out, sessionReadFailure(bounded)
	}
	before := c.codec.service.config.Clock.Now()
	if result.ValidateAt(before) != nil {
		return out, ErrUnauthenticated
	}
	spec, _ := result.Session.Bindings()
	lifetime, e := result.Session.Lifetime(before)
	if e != nil {
		return out, ErrUnauthenticated
	}
	expiry := before.Add(c.codec.config.MaximumAge)
	if lifetime.ExpiresAt.Before(expiry) {
		expiry = lifetime.ExpiresAt
	}
	blob, e := c.codec.Seal(bounded, result)
	if e != nil {
		return out, e
	}
	if base64.RawURLEncoding.EncodedLen(len(blob)) > c.config.MaximumCookieBytes {
		return out, ErrInvalidInput
	}
	now := c.codec.service.config.Clock.Now()
	if bounded.Err() != nil {
		return out, sessionReadFailure(bounded)
	}
	if !validTime(now) || now.Before(before) {
		return out, ErrUnavailable
	}
	if result.ValidateAt(now) != nil {
		return out, ErrUnauthenticated
	}
	attributes, e := c.config.Cache.Attributes(spec.Remember, now, expiry)
	if e != nil {
		return out, e
	}
	attributes.Value = base64.RawURLEncoding.EncodeToString(blob)
	out, e = c.frame(attributes)
	if e != nil {
		return CacheCookie{}, e
	}
	final := c.codec.service.config.Clock.Now()
	if bounded.Err() != nil {
		return CacheCookie{}, sessionReadFailure(bounded)
	}
	if !validTime(final) || final.Before(now) {
		return CacheCookie{}, ErrUnavailable
	}
	if result.ValidateAt(final) != nil || !final.Before(expiry) {
		return CacheCookie{}, ErrUnauthenticated
	}
	return out, nil
}

// Get accepts only an explicit original cookie credential and zero or one cache
// values selected by HTTP. Duplicate companion cookies deny before any IO.
// Absent, oversized or noncanonical base64 cache values invoke bounded primary
// validation. A valid envelope still requires the exact tenant/digest/transport
// and original deadline; an outage after expiry never falls back to stale state.
// Caller must not mutate values during the call. No cookies are silently issued
// or renewed: call Put separately on the authenticated result if cache policy
// permits it. Bearer authentication must not read companion cookies.
func (c *CookieCache) Get(ctx context.Context, request GetRequest, values []string) (GetResult, error) {
	if c == nil || c.codec == nil || ctx == nil || request.Credential.kind != CredentialCookie || len(values) > 1 {
		return GetResult{}, ErrInvalidInput
	}
	var blob []byte
	if len(values) == 1 && len(values[0]) <= c.config.MaximumCookieBytes {
		decoded, e := base64.RawURLEncoding.Strict().DecodeString(values[0])
		// Go's base64 decoder deliberately ignores CR/LF, including Strict mode;
		// re-encoding prevents those aliases and every noncanonical representation.
		if e == nil && base64.RawURLEncoding.EncodeToString(decoded) == values[0] {
			blob = decoded
		}
	}
	return c.codec.Get(ctx, request, blob)
}

// Deletion returns the exact companion scope with negative Max-Age, past
// Expires and High priority. It clears only cache; HTTP must separately clear
// the original credential and commit the required durable revocation.
func (c *CookieCache) Deletion() (CacheCookie, error) {
	if c == nil || c.codec == nil {
		return CacheCookie{}, ErrInvalidInput
	}
	attributes, e := c.config.Cache.DeletionAttributes()
	if e != nil {
		return CacheCookie{}, e
	}
	return c.frame(attributes)
}

func (c *CookieCache) frame(attributes http.Cookie) (CacheCookie, error) {
	if attributes.Valid() != nil {
		return CacheCookie{}, ErrInvalidInput
	}
	header := attributes.String() + "; Priority=High"
	if len(header) > c.config.MaximumCookieBytes {
		return CacheCookie{}, ErrInvalidInput
	}
	return CacheCookie{header}, nil
}

// Format redacts correlated ciphertext and deployment cookie names.
func (CacheCookie) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("session.CacheCookie(redacted)"))
}

// MarshalJSON denies implicit response or diagnostic export.
func (CacheCookie) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies implicit map-key and text export.
func (CacheCookie) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts companion policy and deployment configuration.
func (*CookieCache) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("session.CookieCache(redacted)"))
}

// MarshalJSON denies implicit deployment configuration export.
func (*CookieCache) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }
