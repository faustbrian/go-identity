package reference

import (
	identityhttp "github.com/faustbrian/go-identity/http"
	impersonationhttp "github.com/faustbrian/go-identity/http/impersonation"
)

func (s *Server) impersonationFeature(network identityhttp.NetworkConfig) (*identityhttp.Feature, error) {
	if s.state.features == nil || s.state.features.impersonation == nil {
		return nil, nil
	}
	n := s.state.features.impersonation
	start := impersonationhttp.StartConfig{
		Network: network, TrustedOrigins: n.origins, OriginalCookieName: n.cookie,
		Native: n.keyed, MaximumDuration: s.budget,
	}
	var feature identityhttp.Feature
	var err error
	switch {
	case n.keyed != nil && n.admin != nil:
		feature, err = impersonationhttp.NewStartStopDenyFeature(start, n.native, n.native, n.admin)
	case n.keyed != nil:
		feature, err = impersonationhttp.NewStartStopFeature(start, n.native)
	case n.admin != nil:
		feature, err = impersonationhttp.NewDenyFeature(impersonationhttp.DenyConfig{
			Network: network, TrustedOrigins: n.origins, OriginalCookieName: n.cookie,
			Native: n.native, Rate: n.admin, MaximumDuration: s.budget,
		})
	default:
		return nil, nil
	}
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
