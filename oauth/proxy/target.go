package oauthproxy

import (
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
)

func (t PreviewTarget) valid() bool {
	if !identifier(t.Deployment) || !identifier(t.Recipient) {
		return false
	}
	origin, redirect := endpoint(t.Origin), endpoint(t.Redirect)
	if origin == nil || redirect == nil || origin.Host != redirect.Host || origin.Path != "" ||
		redirect.Path == "" || redirect.Path == "/" || path.Clean(redirect.Path) != redirect.Path {
		return false
	}
	host := origin.Hostname()
	if host == "" || len(host) > 253 || !strings.Contains(host, ".") || host != strings.ToLower(host) {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if !identifier(label) || len(label) > 63 || strings.Contains(label, "_") || strings.HasPrefix(label, "-") ||
			strings.HasSuffix(label, "-") || strings.HasPrefix(label, "xn--") {
			return false
		}
	}
	top := labels[len(labels)-1][0]
	if top < 'a' || top > 'z' {
		return false // Ambiguous IPv4 forms are not DNS registrations.
	}
	port := origin.Port()
	if port == "" {
		return origin.Host == host
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535 && n != 443 && strconv.Itoa(n) == port
}

func endpoint(raw string) *url.URL {
	if len(raw) == 0 || len(raw) > 2048 || strings.ContainsAny(raw, "\\#*%") {
		return nil
	}
	for _, b := range []byte(raw) {
		if b < 0x21 || b > 0x7e {
			return nil
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.String() != raw {
		return nil
	}
	return u
}

func identifier(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i := range len(s) {
		b := s[i]
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_') {
			return false
		}
	}
	return true
}

func validRecord(b oauth.ProxyOIDCEvidenceBinding) bool {
	if !identifier(string(b.TenantID)) || !identifier(b.ClaimsProfile) || b.ClaimsVersion == 0 || b.RequestFingerprint == ([32]byte{}) ||
		b.IssuedAt.IsZero() || b.IssuedAt.Year() < 1 || b.ExpiresAt.Year() > 9999 || !b.ExpiresAt.After(b.IssuedAt) || b.ExpiresAt.Sub(b.IssuedAt) > 5*time.Minute {
		return false
	}
	_, command := identity.ParseCommandID(string(b.CommandID))
	_, transaction := identity.ParsePreAuthTransactionID(string(b.TransactionID))
	_, remember := b.Remember.Bindings()
	return command == nil && transaction == nil && remember == nil
}
