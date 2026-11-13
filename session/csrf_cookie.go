package session

import (
	"net/http"
	"time"
)

// CSRFCookiePolicy explicitly selects a browser-readable synchronizer cookie.
// It retains the secure host-only, root-path, unpartitioned Lax/Strict profile
// and original Remember lifetime, but deliberately omits HttpOnly so same-origin
// code can copy the original CSRF token into the protected request header after
// a provider redirect. It is not a credential, session or CSRF validator.
// CookiePolicy remains HttpOnly; never put session bearer custody in this cookie.
// Copies are immutable and concurrency-safe, with no resource ownership.
type CSRFCookiePolicy struct{ policy CookiePolicy }

// NewCSRFCookiePolicy validates an explicit __Host- name and SameSite selection.
// Transport composition must require a distinct name from authentication, flow
// and device cookies and deliver only the original committed session's CSRF
// token. Construction performs no IO, entropy, issuance or registration.
func NewCSRFCookiePolicy(c CookieConfig) (CSRFCookiePolicy, error) {
	policy, err := NewCookiePolicy(c)
	if err != nil {
		return CSRFCookiePolicy{}, err
	}
	return CSRFCookiePolicy{policy: policy}, nil
}

// Attributes returns credential-free browser-readable cookie attributes with
// the unchanged authoritative absolute expiry and resolved Remember semantics.
// Only the delivery owner may populate Value after the exact new commit; replay,
// failure and unknown outcomes do not authorize redelivery or a new token.
func (c CSRFCookiePolicy) Attributes(p RememberPolicy, now, absoluteExpiresAt time.Time) (http.Cookie, error) {
	attributes, err := c.policy.Attributes(p, now, absoluteExpiresAt)
	if err != nil {
		return http.Cookie{}, err
	}
	attributes.HttpOnly = false
	return attributes, nil
}

// DeletionAttributes clears only this exact readable-cookie scope. Deletion
// does not revoke a session; successful logout must separately revoke native
// authority. No token or previous browser value is retained by the policy.
func (c CSRFCookiePolicy) DeletionAttributes() (http.Cookie, error) {
	attributes, err := c.policy.DeletionAttributes()
	if err != nil {
		return http.Cookie{}, err
	}
	attributes.HttpOnly = false
	return attributes, nil
}
