package reference

import (
	"context"
	"net/url"
	"strings"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	oauthhttp "github.com/faustbrian/go-identity/http/oauthserver"
)

func (s *Server) oauthDeviceFeatures(network identityhttp.NetworkConfig) ([]identityhttp.Feature, error) {
	n := s.state.features.oauthDevice
	if n == nil || n.transport == nil {
		return nil, nil
	}
	issuer, err := url.Parse(n.issuer)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	host := issuer.Hostname()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	var tenantMatched bool
	for _, binding := range network.TenantHosts {
		if binding.Host == host && binding.TenantID == n.scope.TenantID {
			tenantMatched = true
			break
		}
	}
	if !tenantMatched {
		return nil, identityhttp.ErrInvalidInput
	}

	features, err := oauthhttp.NewFeaturesWithDevice(context.Background(), oauthhttp.FeatureConfig{
		Service: n.core, Network: network, Now: time.Now, MaximumDuration: n.maximum,
		Rate: oauthhttp.RateConfig{Shared: s.state.httpRate.backend, Namespace: n.transport.Namespace, Now: time.Now, MaximumDuration: n.rateBudget},
	}, oauthhttp.DeviceFeatureConfig{Service: n.native, SessionCookie: n.cookie})
	if err != nil {
		return nil, err
	}
	for i, feature := range features {
		ops := feature.Operations()
		for j := range ops {
			ops[j].Handler = &passkeyLifetimeHandler{state: s.state, next: ops[j].Handler}
		}
		var requires []identityhttp.ModuleID
		if feature.ID() == "oauth-server/device" {
			// Device polling is served on its issuer contribution's token route.
			requires = []identityhttp.ModuleID{"oauth-server"}
		}
		features[i], err = identityhttp.NewFeature(identityhttp.FeatureConfig{ID: feature.ID(), Requires: requires, Operations: ops})
		if err != nil {
			return nil, err
		}
	}
	return features, nil
}
