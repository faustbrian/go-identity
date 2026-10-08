package identityhttp

import (
	"context"
	"strings"
)

// RedirectGuardConfig selects the exact HTTPS redirect profile. Network is an
// immutable host-syntax owner, not a source of redirect trust. Targets contains
// 1..128 distinct full URLs of at most 2048 bytes each. Scheme/authority must
// already be canonical: lowercase https and ASCII/IDNA host, canonical port,
// no explicit default port. Path/query bytes are retained exactly; no wildcard,
// userinfo, fragment or backslash is allowed. Caller must not mutate inputs
// during construction. Local HTTP and native-application profiles are separate
// future work, not implicit exceptions to this profile.
type RedirectGuardConfig struct {
	Network *NetworkResolver
	Targets []string
}

// RedirectGuard owns a copied immutable full-target allowlist. Zero is invalid;
// independent calls may share a constructed guard. It does not derive trust
// from request Host, Origin, Referer, proxy or tenant metadata and does no IO.
// A successful check is target admission only, not client/tenant/flow binding,
// authentication, state/nonce/PKCE validation or permission to append parameters.
// Use a separate guard for each policy owner; never union unrelated clients'
// redirect sets to replace their protocol-specific registration checks.
type RedirectGuard struct {
	targets map[string]struct{}
}

// NewRedirectGuard validates and copies the complete allowlist without IO.
// Invalid owners, bounds, duplicates or malformed/noncanonical URLs return
// ErrInvalidInput and no partial guard. Network's fixed Unicode host policy is
// reused for syntax validation; redirect hosts need not be served host-map keys.
func NewRedirectGuard(config RedirectGuardConfig) (*RedirectGuard, error) {
	if config.Network == nil || config.Network.decoder == nil || len(config.Targets) < 1 || len(config.Targets) > 128 {
		return nil, ErrInvalidInput
	}
	guard := &RedirectGuard{targets: make(map[string]struct{}, len(config.Targets))}
	origin := &OriginGuard{network: config.Network}
	for _, target := range config.Targets {
		u, ok := originURL(target)
		if !ok || !strings.HasPrefix(target, "https://") || strings.Contains(target, "*") {
			return nil, ErrInvalidInput
		}
		canonical, ok := origin.canonicalOrigin("https://" + u.Host)
		if !ok || string(canonical) != "https://"+u.Host {
			return nil, ErrInvalidInput
		}
		if _, exists := guard.targets[target]; exists {
			return nil, ErrInvalidInput
		}
		guard.targets[target] = struct{}{}
	}
	return guard, nil
}

// Check returns target unchanged only for exact allowlist membership. It never
// normalizes a candidate, emits Location, appends protocol parameters or returns
// a fallback URL. Nil context/zero owner returns ErrInvalidInput; cancellation
// retains its context error; all other denials return redacted OriginError.
// Every error returns an empty string. Callers must not redirect even an OAuth
// error to a denied target. After admission the owning workflow must still bind
// the registered client, tenant and initiating transaction, and separately own
// any protocol-defined response construction.
func (g *RedirectGuard) Check(ctx context.Context, target string) (string, error) {
	if g == nil || len(g.targets) == 0 || ctx == nil {
		return "", ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	// Bound even hashing work before looking up an untrusted candidate. Syntax
	// was validated at construction, so equality is the complete admission test.
	if len(target) > 2048 {
		return "", OriginError{}
	}
	if _, allowed := g.targets[target]; !allowed {
		return "", OriginError{}
	}
	return target, nil
}
