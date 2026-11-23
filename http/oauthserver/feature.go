// Package oauthserverhttp composes opt-in OAuth workload token, introspection
// and revocation endpoints. OAuth core/native adapters retain all credential,
// grant, current-authority, transaction and recovery ownership.
package oauthserverhttp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
	"github.com/faustbrian/go-oauth-server/device"
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
	features, err := newFeatures(ctx, c, nil)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	return features[0], nil
}

// DeviceFeatureConfig selects device authorization, native session consent,
// and the device grant on the existing token route. It borrows the configured
// native device service, including current session and protected rate stores.
// The normal session cookie is used only for the browser consent operations.
type DeviceFeatureConfig struct {
	Service       *device.Service
	SessionCookie session.CookiePolicy
}

func (DeviceFeatureConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "oauthserverhttp.DeviceFeatureConfig(redacted)")
}

// NewFeaturesWithDevice returns the issuer and device contributions together.
// Both must be selected. The single token route serves the device grant and,
// only when c.Token is enabled, confidential workload client credentials.
// No provider, store, release or background work is created at construction.
func NewFeaturesWithDevice(ctx context.Context, c FeatureConfig, selected DeviceFeatureConfig) ([]identityhttp.Feature, error) {
	if !selected.Service.Enabled() {
		return nil, identityhttp.ErrInvalidInput
	}
	return newFeatures(ctx, c, &selected)
}

func newFeatures(ctx context.Context, c FeatureConfig, selected *DeviceFeatureConfig) ([]identityhttp.Feature, error) {
	invalid := identityhttp.ErrInvalidInput
	if ctx == nil || c.Service == nil || selected == nil && !c.Token && !c.Introspect && !c.Revoke || c.Now == nil ||
		c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.Network.Limits.MaximumBodyBytes > 16384 || c.Network.Limits.MaximumDecodedBytes > 16384 {
		return nil, invalid
	}
	metadata, err := c.Service.DiscoveryOauth(ctx, oauth.DiscoveryOauthRequest{})
	if err != nil {
		return nil, invalid
	}
	m := metadata.Metadata
	issuerURL, err := url.Parse(m.Issuer)
	if err != nil {
		return nil, invalid
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
		return nil, invalid
	}
	tokenSelected := c.Token || selected != nil
	if (c.Token || c.Introspect || c.Revoke) && !slices.Contains(m.TokenEndpointAuthMethodsSupported, "client_secret_basic") ||
		tokenSelected && m.TokenEndpoint != m.Issuer+"/oauth2/token" || c.Token && !slices.Contains(m.GrantTypesSupported, "client_credentials") ||
		c.Revoke && m.RevocationEndpoint != m.Issuer+"/oauth2/revoke" || c.Introspect && m.IntrospectionEndpoint != m.Issuer+"/oauth2/introspect" {
		return nil, invalid
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return nil, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return nil, err
	}
	rate, err := newProtocolRate(c.Rate, m.Issuer)
	if err != nil {
		return nil, err
	}
	var ops []identityhttp.OperationDescriptor
	for _, route := range []struct {
		action string
		on     bool
	}{{"token", tokenSelected}, {"introspect", c.Introspect}, {"revoke", c.Revoke}} {
		if !route.on {
			continue
		}
		var selectedToken *device.Service
		if route.action == "token" && selected != nil {
			selectedToken = selected.Service
		}
		h, err := newHandlerWithDevice(c, route.action, m.Issuer, network, decoder, rate, selectedToken)
		if err != nil {
			return nil, err
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "oauth-server", OperationID: "identity.oauth-server." + route.action, Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: 16384})
		if err != nil {
			return nil, err
		}
		if selectedToken != nil {
			op.Wire = tokenWireWithDevice(c.Token, len(ops) == 0)
		} else {
			op.Wire = operationWire(route.action, len(ops) == 0)
		}
		ops = append(ops, op)
	}
	issuer, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "oauth-server", Operations: ops})
	if err != nil {
		return nil, err
	}
	if selected == nil {
		return []identityhttp.Feature{issuer}, nil
	}
	browser := DeviceConsentConfig{Service: selected.Service, SessionCookie: selected.SessionCookie,
		Origin: identityhttp.Origin(m.Issuer), Network: c.Network, Now: c.Now, MaximumDuration: c.MaximumDuration}
	deviceFeature, err := newDeviceFeature(browser, network, decoder, rate)
	if err != nil {
		return nil, err
	}
	return []identityhttp.Feature{issuer, deviceFeature}, nil
}

func newDeviceFeature(browser DeviceConsentConfig, network *identityhttp.NetworkResolver, decoder *identityhttp.RequestDecoder, rate *protocolRate) (identityhttp.Feature, error) {
	const owner = "oauth-server/device"
	operations := make([]identityhttp.OperationDescriptor, 0, 4)
	for _, action := range []string{"device-authorize", "device-inspect", "device-approve", "device-deny"} {
		var handler http.Handler
		var err error
		var wireBrowser *DeviceConsentConfig
		csrf := identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}
		if action == "device-authorize" {
			handler, err = newDeviceAuthorizationHandler(browser.Service, browser.Now, browser.MaximumDuration, string(browser.Origin), network, decoder, rate)
		} else {
			wireBrowser = &browser
			handler, err = newDeviceConsentHandler(browser, action)
			if action != "device-inspect" {
				csrf = identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}
			}
		}
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
			Owner: owner, OperationID: "identity.oauth-server." + action, Handler: handler, CSRF: csrf, MaximumSerializedBytes: 16384,
		})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire, err = deviceOperationWire(action, wireBrowser, action == "device-inspect")
		if err != nil {
			return identityhttp.Feature{}, err
		}
		operations = append(operations, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: owner, Requires: []identityhttp.ModuleID{"oauth-server"}, Operations: operations})
}
