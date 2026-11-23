package session

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	frontchannelCookieName = "__Secure-identity_frontchannel"
	frontchannelCookieTTL  = 5 * time.Minute // Reference frontchannel_post_cookie.
	samlFrontchannelAction = "identity.sso.saml-acs"
	appleFormPostPath      = "/v1/oauth/callback/form-post"
	samlCallbackPrefix     = "/saml2/"
	samlCallbackSuffix     = "/acs"
	samlIDPConfirmSuffix   = "/idp-init"
	maximumSAMLProviderID  = 128
)

func samlFrontchannelPath(origin, callback string) (string, bool) {
	path, sameOrigin := strings.CutPrefix(callback, origin)
	return path, sameOrigin && strings.HasPrefix(origin, "https://") && validSAMLFrontchannelPath(path)
}

// FrontchannelCookiePolicy holds attributes for one exact cross-site POST path.
// It owns no correlation state, session authority or response writing. The
// selected coordinator must issue and atomically consume its original opaque
// correlation, independently of browser cookie expiration or deletion.
// A zero policy is invalid. Valid policies are immutable.
type FrontchannelCookiePolicy struct{ path string }

// NewFrontchannelCookiePolicy selects the registered Apple form POST or
// SP-initiated SAML assertion consumer path. It never treats a route template,
// escaped alias or an inbound request URL as the trusted configured route.
func NewFrontchannelCookiePolicy(callbackPath string) (FrontchannelCookiePolicy, error) {
	if callbackPath != appleFormPostPath && !validSAMLFrontchannelPath(callbackPath) {
		return FrontchannelCookiePolicy{}, ErrInvalidPolicy
	}
	return FrontchannelCookiePolicy{path: callbackPath}, nil
}

// NewSAMLIDPConfirmationCookiePolicy selects only the exact configured
// unsolicited SAML POST path. The cookie is issued after the response arrives;
// it is not an SP pre-authentication cookie or a normal session cookie. The
// native owner still has to check same-browser confirmation and consume it
// before a session may be issued. Disabled profiles must never use this policy.
func NewSAMLIDPConfirmationCookiePolicy(callbackPath string) (FrontchannelCookiePolicy, error) {
	if !validSAMLFrontchannelPathWithSuffix(callbackPath, samlIDPConfirmSuffix) {
		return FrontchannelCookiePolicy{}, ErrInvalidPolicy
	}
	return FrontchannelCookiePolicy{path: callbackPath}, nil
}

func validSAMLFrontchannelPath(path string) bool {
	return validSAMLFrontchannelPathWithSuffix(path, samlCallbackSuffix)
}

func validSAMLFrontchannelPathWithSuffix(path, suffix string) bool {
	if !strings.HasPrefix(path, samlCallbackPrefix) || !strings.HasSuffix(path, suffix) ||
		len(path) <= len(samlCallbackPrefix)+len(suffix) ||
		len(path) > len(samlCallbackPrefix)+maximumSAMLProviderID+len(suffix) {
		return false
	}
	provider := path[len(samlCallbackPrefix) : len(path)-len(suffix)]
	// Match the provider router's exact, unescaped path segment rule. This
	// admits all generated base64url IDs, including leading '-' and '_'.
	// A cookie Path additionally cannot contain a semicolon (RFC 6265 §4.1.1).
	return provider != "." && provider != ".." && !strings.ContainsAny(provider, "/{};") && url.PathEscape(provider) == provider
}

// Attributes returns an empty host-only cookie scoped to the selected path.
// Populate its value only with the original issued correlation. The expiry
// must be the coordinator's original absolute cutoff, no more than five
// minutes away. Fractional remaining seconds round down and less than one
// second is refused, so an expired correlation cannot become a session cookie.
func (p FrontchannelCookiePolicy) Attributes(now, originalExpiresAt time.Time) (http.Cookie, error) {
	if p.path == "" {
		return http.Cookie{}, ErrInvalidPolicy
	}
	if !validTime(now) || !validTime(originalExpiresAt) {
		return http.Cookie{}, ErrInvalidTime
	}
	remaining := originalExpiresAt.Sub(now)
	if remaining < time.Second {
		return http.Cookie{}, ErrExpired
	}
	if remaining > frontchannelCookieTTL {
		return http.Cookie{}, ErrInvalidTime
	}
	cookie := p.base()
	cookie.MaxAge = int(remaining / time.Second)
	cookie.Expires = now.Add(time.Duration(cookie.MaxAge) * time.Second).UTC()
	return cookie, nil
}

// DeletionAttributes clears the same path and never changes session cookies or
// consumes the server-side correlation.
func (p FrontchannelCookiePolicy) DeletionAttributes() (http.Cookie, error) {
	if p.path == "" {
		return http.Cookie{}, ErrInvalidPolicy
	}
	cookie := p.base()
	cookie.MaxAge = -1
	cookie.Expires = time.Unix(1, 0).UTC()
	return cookie, nil
}

func (p FrontchannelCookiePolicy) base() http.Cookie {
	return http.Cookie{
		Name: frontchannelCookieName, Path: p.path, Secure: true,
		HttpOnly: true, SameSite: http.SameSiteNoneMode,
	}
}
