package identityhttp

import (
	"net/http"
	"net/url"
	"strings"
)

// Origin is a canonical HTTPS origin, not a URL or a CSRF token. In this
// profile it has a lowercase ASCII/IDNA host, no default port, path, query,
// fragment or userinfo. Conversion alone does not validate an Origin.
type Origin string

// OriginError classifies malformed, missing, ambiguous or untrusted origin
// evidence without disclosing submitted input or the configured allowlist.
type OriginError struct{}

// Error returns the stable redacted origin-denial classification.
func (OriginError) Error() string { return "identity.http.origin_denied" }

// OriginGuardConfig selects the HTTPS browser profile. Network is required and
// remains the sole proxy/host policy owner. TrustedOrigins contains 1..128
// distinct canonical origins of at most 2048 bytes each; no wildcard, opaque,
// extension or local HTTP origins are supported by this profile. Zero or Deny
// disables Referer fallback. SameOriginHTTPS permits it only when Origin is
// absent and the Referer matches the current effective origin and allowlist.
type OriginGuardConfig struct {
	Network         *NetworkResolver
	TrustedOrigins  []Origin
	RefererFallback RefererFallbackPolicy
}

// OriginGuard owns copied immutable origin policy and borrows an immutable
// NetworkResolver. Zero is invalid. Independent requests may share it. No body,
// DNS, callback, authentication, token consumption or domain work occurs. This
// is only origin admission: cookie mutations still require session-bound CSRF
// tokens, and callbacks require their protocol/continuation bindings.
type OriginGuard struct {
	network  *NetworkResolver
	origins  map[Origin]struct{}
	fallback RefererFallbackPolicy
}

// NewOriginGuard validates and copies one complete policy without IO. Invalid
// network owners, bounds, noncanonical/duplicate origins or unknown fallback
// values return ErrInvalidInput without retaining partial policy.
func NewOriginGuard(config OriginGuardConfig) (*OriginGuard, error) {
	if config.Network == nil || config.Network.decoder == nil || len(config.TrustedOrigins) < 1 || len(config.TrustedOrigins) > 128 || config.RefererFallback > RefererFallbackSameOriginHTTPS {
		return nil, ErrInvalidInput
	}
	g := &OriginGuard{network: config.Network, fallback: config.RefererFallback, origins: make(map[Origin]struct{}, len(config.TrustedOrigins))}
	for _, origin := range config.TrustedOrigins {
		canonical, ok := g.canonicalOrigin(string(origin))
		if !ok || canonical != origin {
			return nil, ErrInvalidInput
		}
		if _, exists := g.origins[origin]; exists {
			return nil, ErrInvalidInput
		}
		g.origins[origin] = struct{}{}
	}
	return g, nil
}

// Check requires one exact canonical allowlisted Origin on the current request.
// A present invalid/empty Origin never falls back. Only explicit
// SameOriginHTTPS may admit an absent Origin through one absolute HTTPS Referer
// whose normalized origin equals BOTH the resolved effective origin and one
// trusted origin. Referer may contain path/query, but not userinfo or fragment.
// Request origin bytes are not repaired or silently normalized. Referer host
// normalization uses NetworkResolver's fixed Unicode 15.1 IDNA policy.
// Network/envelope/context errors are preserved; origin denial is redacted.
// Every error returns an empty Origin. Network facts are resolved internally
// for this request, never supplied by a caller or taken from a cache. Server
// composition must retain custody of request metadata during this call.
func (g *OriginGuard) Check(r *http.Request) (Origin, error) {
	if g == nil || g.network == nil || r == nil {
		return "", ErrInvalidInput
	}
	facts, err := g.network.Resolve(r)
	if err != nil {
		return "", err
	}
	raw, present, valid := originHeader(r.Header, "Origin")
	if !valid {
		return "", OriginError{}
	}
	var origin Origin
	if present {
		canonical, ok := g.canonicalOrigin(raw)
		if !ok || string(canonical) != raw {
			return "", OriginError{}
		}
		origin = canonical
	} else {
		if g.fallback != RefererFallbackSameOriginHTTPS || facts.Scheme() != "https" {
			return "", OriginError{}
		}
		raw, present, valid = originHeader(r.Header, "Referer")
		if !valid || !present {
			return "", OriginError{}
		}
		u, ok := originURL(raw)
		if !ok {
			return "", OriginError{}
		}
		origin, ok = g.canonicalOrigin(u.Scheme + "://" + u.Host)
		if !ok || string(origin) != facts.Origin() {
			return "", OriginError{}
		}
	}
	if _, trusted := g.origins[origin]; !trusted {
		return "", OriginError{}
	}
	if err := r.Context().Err(); err != nil {
		return "", err
	}
	return origin, nil
}

// CheckBound adds an exact initiating-origin comparison to Check. The stored
// bound value must itself be a configured canonical origin; empty/untrusted
// bindings deny. It does not verify or consume the owning workflow's nonce,
// state, token or continuation. A caller cannot use it as standalone proof of
// authentication, CSRF token validation or one-time completion.
func (g *OriginGuard) CheckBound(r *http.Request, bound Origin) (Origin, error) {
	origin, err := g.Check(r)
	if err != nil {
		return "", err
	}
	if origin != bound {
		return "", OriginError{}
	}
	return origin, nil
}

func (g *OriginGuard) canonicalOrigin(raw string) (Origin, bool) {
	u, ok := originURL(raw)
	if !ok || u.Path != "" || u.RawQuery != "" || u.ForceQuery {
		return "", false
	}
	host, authority, ok := g.network.authority(u.Host)
	if !ok {
		return "", false
	}
	if authority == host+":443" {
		authority = host
	}
	return Origin("https://" + authority), true
}

// Header.Get/Values hide differently cased map keys. Presence must be tracked
// separately from an empty value so an invalid Origin cannot enable fallback.
func originHeader(headers http.Header, wanted string) (raw string, present, valid bool) {
	for name, values := range headers {
		if !strings.EqualFold(name, wanted) {
			continue
		}
		if present || len(values) != 1 {
			return "", true, false
		}
		raw, present = values[0], true
	}
	return raw, present, true
}

func originURL(raw string) (*url.URL, bool) {
	if raw == "" || len(raw) > 2048 || strings.ContainsAny(raw, "\\#") {
		return nil, false
	}
	for i := range raw {
		if raw[i] <= 32 || raw[i] >= 127 {
			return nil, false
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" {
		return nil, false
	}
	// net/url also accepts raw characters it would escape when serializing.
	// Validate original path/query bytes against RFC3986 pchar plus '/' and
	// query '?', not EscapedPath (which would silently repair malformed input).
	_, remainder, absolute := strings.Cut(raw, "://")
	if !absolute {
		return nil, false
	}
	if start := strings.IndexAny(remainder, "/?"); start >= 0 {
		for _, c := range remainder[start:] {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~!$&'()*+,;=:@/%?", c)) {
				return nil, false
			}
		}
	}
	// url.Parse validates path escapes, but leaves RawQuery unchecked. Only
	// validate its escape syntax: retain the original URL and query bytes.
	if _, err := url.QueryUnescape(u.RawQuery); err != nil {
		return nil, false
	}
	return u, true
}
