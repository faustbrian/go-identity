package reference

import (
	"context"
	"net/url"
	"strings"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	oauthhttp "github.com/faustbrian/go-identity/http/oauthserver"
)

func (s *Server) oauthWorkloadFeature(network identityhttp.NetworkConfig) (*identityhttp.Feature, error) {
	n := s.state.features.oauthWorkload
	if n == nil || n.http == nil {
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
	var tenant string
	for _, binding := range network.TenantHosts {
		if binding.Host == host {
			tenant = string(binding.TenantID)
			break
		}
	}
	if tenant == "" {
		return nil, identityhttp.ErrInvalidInput
	}
	// Reference guardTenant and the HTTP tenant rate bucket resolve this host.
	// Native workload authority instead comes from immutable client registration.
	// Reject conflicting deployment identities before either owner can be used.
	for _, scope := range n.scopes {
		if string(scope.TenantID) != tenant {
			return nil, identityhttp.ErrInvalidInput
		}
	}
	h := n.http
	feature, err := oauthhttp.NewFeature(context.Background(), oauthhttp.FeatureConfig{Service: n.native, Token: h.Token, Introspect: h.Introspect, Revoke: h.Revoke, Network: network, Rate: oauthhttp.RateConfig{Shared: s.state.httpRate.backend, Namespace: h.Namespace, Now: time.Now, MaximumDuration: n.rateMaximum}, Now: time.Now, MaximumDuration: n.maximum})
	if err != nil {
		return nil, err
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		return nil, err
	}
	for i := range ops {
		ops[i].Handler = &passkeyLifetimeHandler{state: s.state, next: ops[i].Handler}
	}
	feature, err = identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "oauth-server", Operations: ops})
	return &feature, err
}
