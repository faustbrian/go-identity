package reference

import (
	identityhttp "github.com/faustbrian/go-identity/http"
	impersonationhttp "github.com/faustbrian/go-identity/http/impersonation"
)

func (s *Server) impersonationFeature(network identityhttp.NetworkConfig) (*identityhttp.Feature, error) {
	if s.state.features == nil || s.state.features.impersonation == nil || s.state.features.impersonation.keyed == nil {
		return nil, nil
	}
	n := s.state.features.impersonation
	feature, err := impersonationhttp.NewStartStopFeature(impersonationhttp.StartConfig{
		Network: network, TrustedOrigins: n.origins, OriginalCookieName: n.cookie,
		Native: n.keyed, MaximumDuration: s.budget,
	}, n.native)
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
	feature, err = identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/impersonation", Operations: ops})
	return &feature, err
}
