package session

import (
	"net/http"
	"strings"
	"time"
)

// CookieConfig selects the secure host-only session-cookie profile. Name must
// start with __Host-, contain a suffix and be at most 128 ASCII token bytes.
// SameSite is explicitly Lax or Strict. Cross-site correlation cookies are
// distinct from session cookies and are not supported by this profile.
type CookieConfig struct {
	Name     string
	SameSite http.SameSite
}

// CookiePolicy is an immutable validated host-cookie policy. Zero is invalid.
// It owns attributes only, not session issuance, token custody, CSRF validation
// or writing HTTP responses. Copies may be used concurrently.
type CookiePolicy struct {
	name     string
	sameSite http.SameSite
}

// NewCookiePolicy rejects unsafe or implicit transport policy. The secure,
// HttpOnly, host-only, root-path and unpartitioned attributes cannot be weakened.
func NewCookiePolicy(c CookieConfig) (CookiePolicy, error) {
	if len(c.Name) <= len("__Host-") || len(c.Name) > 128 || !strings.HasPrefix(c.Name, "__Host-") || (c.SameSite != http.SameSiteLaxMode && c.SameSite != http.SameSiteStrictMode) {
		return CookiePolicy{}, ErrInvalidPolicy
	}
	for i := 0; i < len(c.Name); i++ {
		b := c.Name[i]
		if b <= 32 || b >= 127 || strings.ContainsRune("()<>@,;:\\\"/[]?={}", rune(b)) {
			return CookiePolicy{}, ErrInvalidPolicy
		}
	}
	return CookiePolicy{name: c.Name, sameSite: c.SameSite}, nil
}

// Attributes returns a fresh, credential-free standard-library cookie. The
// transport must assign only its issued opaque token to Value and must not log
// that populated cookie. absoluteExpiresAt must be the original authoritative
// absolute expiry, never inferred from client input. Persistent cookies
// use whole remaining seconds capped at seven days, never a refreshed TTL;
// browser cookies omit both Max-Age and Expires. Fractional lifetimes round
// down, and less than one second is denied rather than becoming an accidental
// session cookie. The 15-minute configuration minimum applies to issuance,
// not a lower bound that could extend the remaining session lifetime.
// Cookie attributes alone convey no authentication or revocation guarantee.
func (c CookiePolicy) Attributes(p RememberPolicy, now, absoluteExpiresAt time.Time) (http.Cookie, error) {
	if c.name == "" || !explicit(p.choice) {
		return http.Cookie{}, ErrInvalidPolicy
	}
	if !validTime(now) || !validTime(absoluteExpiresAt) {
		return http.Cookie{}, ErrInvalidTime
	}
	remaining := absoluteExpiresAt.Sub(now)
	if remaining < time.Second {
		return http.Cookie{}, ErrExpired
	}
	if remaining > p.absolute {
		return http.Cookie{}, ErrInvalidTime
	}
	a := c.base()
	if p.choice == PersistentSession {
		seconds := int(min(remaining, 7*24*time.Hour) / time.Second)
		a.MaxAge = seconds
		a.Expires = now.Add(time.Duration(seconds) * time.Second).UTC()
	}
	return a, nil
}

// DeletionAttributes returns an empty host cookie with the exact same scope
// and security attributes, negative Max-Age and a past expiry. HTTP logout must
// revoke server authority independently; deleting a cookie is not revocation.
func (c CookiePolicy) DeletionAttributes() (http.Cookie, error) {
	if c.name == "" {
		return http.Cookie{}, ErrInvalidPolicy
	}
	a := c.base()
	a.MaxAge = -1
	a.Expires = time.Unix(1, 0).UTC()
	return a, nil
}

func (c CookiePolicy) base() http.Cookie {
	return http.Cookie{Name: c.name, Path: "/", Secure: true, HttpOnly: true, SameSite: c.sameSite}
}
