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
	case n.keyed != nil && n.httpDeny:
		feature, err = impersonationhttp.NewStartStopDenyFeature(start, n.native, n.native, n.admin)
	case n.keyed != nil:
		feature, err = impersonationhttp.NewStartStopFeature(start, n.native)
	case n.httpDeny:
		feature, err = impersonationhttp.NewDenyFeature(impersonationhttp.DenyConfig{
			Network: network, TrustedOrigins: n.origins, OriginalCookieName: n.cookie,
			Native: n.native, Rate: n.admin, MaximumDuration: s.budget,
		})
	}
	if err != nil {
		return nil, err
	}
	ops := feature.Operations()
	if n.httpQuorum {
		quorum, err := impersonationhttp.NewQuorumFeature(impersonationhttp.QuorumConfig{
			Network: network, OriginalCookieName: n.cookie, Native: n.native, Rate: n.admin, MaximumDuration: s.budget,
		})
		if err != nil {
			return nil, err
		}
		ops = append(ops, quorum.Operations()...)
	}
	if len(ops) == 0 {
		return nil, nil
	}
	for i := range ops {
		ops[i].Handler = &passkeyLifetimeHandler{state: s.state, next: ops[i].Handler}
	}
	feature, err = identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/impersonation", Operations: ops})
	return &feature, err
}
