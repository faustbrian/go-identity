// Package oauthserverhttp composes opt-in OAuth workload token, introspection
// and revocation endpoints. OAuth core/native adapters retain all credential,
// grant, current-authority, transaction and recovery ownership.
package oauthserverhttp

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	oauth "github.com/faustbrian/go-oauth-server"
)

// FeatureConfig borrows the configured native OAuth service, strong rate store
// and prompt concurrent clock for the lifetime of returned handlers. Network is
// copied; earlier request deadlines win over MaximumDuration (1ms..30s).
// Native RFC8414 configuration supplies trusted issuer/endpoint availability
// without storage IO; this feature does not register a discovery endpoint.
//
// Each route is independently opt-in. Token selects only client_credentials
// with confidential Basic authentication, never code, refresh, exchange, OIDC
// or device variants. Introspect requires native owning-client introspection.
// Constructors allocate no durable state, start no goroutines and own none of
// the borrowed service/store resources. Consumers must use a real configured
// native service, not supply missing authentication or transaction callbacks.
type FeatureConfig struct {
	Service                   *oauth.Service
	Token, Introspect, Revoke bool
	Network                   identityhttp.NetworkConfig
	Rate                      RateConfig
	Now                       func() time.Time
	MaximumDuration           time.Duration
}

func (FeatureConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "oauthserverhttp.FeatureConfig(redacted)")
}

// NewFeature freezes one complete selected contribution and its OpenAPI wire
// definitions. Native discovery is read only as a configured capability/issuer
// projection; no public metadata route is implicitly exposed. Missing or
// incompatible selected dependencies return no partial feature. It performs no
// client authentication, admission, network or database IO.
func NewFeature(ctx context.Context, c FeatureConfig) (identityhttp.Feature, error) {
	invalid := identityhttp.ErrInvalidInput
	if ctx == nil || c.Service == nil || !c.Token && !c.Introspect && !c.Revoke || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.Network.Limits.MaximumBodyBytes > 16384 || c.Network.Limits.MaximumDecodedBytes > 16384 {
		return identityhttp.Feature{}, invalid
	}
	metadata, err := c.Service.DiscoveryOauth(ctx, oauth.DiscoveryOauthRequest{})
	if err != nil {
		return identityhttp.Feature{}, invalid
	}
	m := metadata.Metadata
	issuerURL, err := url.Parse(m.Issuer)
	if err != nil {
		return identityhttp.Feature{}, invalid
	}
	issuerHost := issuerURL.Hostname()
	if strings.Contains(issuerHost, ":") {
		issuerHost = "[" + issuerHost + "]"
	}
	hostSelected := slices.Contains(c.Network.PublicHosts, issuerHost)
	for _, binding := range c.Network.TenantHosts {
		hostSelected = hostSelected || binding.Host == issuerHost
	}
	if !hostSelected {
		return identityhttp.Feature{}, invalid
	}
	if !slices.Contains(m.TokenEndpointAuthMethodsSupported, "client_secret_basic") || c.Token && (!slices.Contains(m.GrantTypesSupported, "client_credentials") || m.TokenEndpoint != m.Issuer+"/oauth2/token") || c.Revoke && m.RevocationEndpoint != m.Issuer+"/oauth2/revoke" || c.Introspect && m.IntrospectionEndpoint != m.Issuer+"/oauth2/introspect" {
		return identityhttp.Feature{}, invalid
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	rate, err := newProtocolRate(c.Rate, m.Issuer)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	var ops []identityhttp.OperationDescriptor
	for _, selected := range []struct {
		action string
		on     bool
	}{{"token", c.Token}, {"introspect", c.Introspect}, {"revoke", c.Revoke}} {
		if !selected.on {
			continue
		}
		h, err := newHandler(c, selected.action, m.Issuer, network, decoder, rate)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "oauth-server", OperationID: "identity.oauth-server." + selected.action, Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: 16384})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = operationWire(selected.action, len(ops) == 0)
		ops = append(ops, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "oauth-server", Operations: ops})
}
