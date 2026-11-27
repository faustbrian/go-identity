package postgres

import (
	"context"
	"crypto/subtle"
	"errors"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
)

// ProxyCallbackRateSource authenticates original callback attribution for a
// transport provider budget. The tenant must be the trusted network realm
// selected by production, never a value inferred from callback input. This
// read neither reserves state nor opens capability or verifier custody, emits
// an outcome, or grants admission. The callback must independently repeat its
// current native fences, including the registered preview-target decision.
// Lifetime is the immutable original interval, not a renewable deadline.
// Unavailable originals return ErrOriginalUnavailable; uncertain reads or
// authentication return CallbackReconcile. Every error returns zero attribution.
func (s *ProxyForwardService) ProxyCallbackRateSource(ctx context.Context, tenant identity.TenantID, lookup oauthproxy.CallbackLookup) (out oauth.CallbackRateContext, err error) {
	if s == nil || s.pool == nil || ctx == nil || ctx.Err() != nil {
		return oauth.CallbackRateContext{}, oauthproxy.CallbackReconcile
	}
	defer func() {
		if recover() != nil {
			out, err = oauth.CallbackRateContext{}, oauthproxy.CallbackReconcile
		}
	}()
	if !rpDirectoryID(string(tenant)) || lookup.ProductionDeployment != s.config.ProductionDeployment ||
		proxyBindingHTTPS(lookup.ProductionCallback) == nil || proxyBindingHTTPS(lookup.Issuer) == nil ||
		!rpASCII(lookup.ClientID, 1, 1024) || !rpProviderID(lookup.ProviderID) || lookup.ProviderVersion == 0 ||
		lookup.StateDigest == ([32]byte{}) {
		return oauth.CallbackRateContext{}, oauthproxy.ErrOriginalUnavailable
	}
	ctx, stop := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer stop()
	row, err := readProxyLookup(ctx, s.pool.Raw(), s.config.Schema, s.config.StateKeys, proxyLookupSelection{
		production: lookup.ProductionDeployment, provider: lookup.ProviderID, callback: lookup.ProductionCallback,
		providerVersion: lookup.ProviderVersion, state: lookup.StateDigest,
	})
	defer row.clear()
	if err != nil {
		var denied identity.ForbiddenError
		if ctx.Err() == nil && errors.As(err, &denied) {
			return oauth.CallbackRateContext{}, oauthproxy.ErrOriginalUnavailable
		}
		return oauth.CallbackRateContext{}, oauthproxy.CallbackReconcile
	}
	if row.version != "1" || row.tenant != string(tenant) {
		return oauth.CallbackRateContext{}, oauthproxy.ErrOriginalUnavailable
	}
	locator, err := row.forwardLocator(lookup)
	if err != nil {
		return oauth.CallbackRateContext{}, oauthproxy.CallbackReconcile
	}
	original, err := openProxyOriginalBinding(ctx, s.envelopes, locator, row.binding)
	if err != nil || ctx.Err() != nil {
		return oauth.CallbackRateContext{}, oauthproxy.CallbackReconcile
	}
	if original.Evidence.Issuer != lookup.Issuer || original.Evidence.ClientID != lookup.ClientID ||
		subtle.ConstantTimeCompare(original.Evidence.StateDigest[:], lookup.StateDigest[:]) != 1 {
		return oauth.CallbackRateContext{}, oauthproxy.ErrOriginalUnavailable
	}
	return oauth.CallbackRateContext{
		ProviderID: original.Evidence.ProviderID, TransactionID: string(original.Evidence.TransactionID),
		Lifetime: original.Evidence.ExpiresAt.Sub(original.Evidence.IssuedAt),
	}, nil
}
