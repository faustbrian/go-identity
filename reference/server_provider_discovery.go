package reference

import (
	"io"
	"net/http"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	oauthhttp "github.com/faustbrian/go-identity/http/oauth"
)

func (s *Server) providerDiscoveryFeature(network identityhttp.NetworkConfig, localization *oauthhttp.ProviderListLocalizationConfig) (*identityhttp.Feature, error) {
	owner := s.state.features.providerDiscovery
	if owner == nil {
		if localization != nil {
			return nil, identity.InvalidInputError{Field: "reference_provider_discovery_localization"}
		}
		return nil, nil
	}
	feature, err := oauthhttp.NewProviderListFeature(oauthhttp.ProviderListConfig{
		Network: network, Catalog: owner.catalog, Rate: owner.rate, MaximumDuration: owner.duration,
		Localization: localization,
	})
	if err != nil {
		return nil, err
	}
	return &feature, nil
}

// Only the exact selected public read uses this lifetime boundary. All other
// operations retain guardTenant. The published feature owns HTTPS, host, query
// parsing and canonical safe-rate admission; no tenant callback substitutes for
// public discovery and no ambient session is consulted. Shutdown cancels and
// drains the complete native handler call through the existing graph owner.
func (s *Server) guardProviderDiscoveryLifetime(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deny := func() {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(http.StatusServiceUnavailable)
			if r == nil || r.Method != http.MethodHead {
				_, _ = io.WriteString(w, "{\"error\":\"unavailable\"}\n")
			}
		}
		if r == nil || r.URL == nil || r.Method != http.MethodGet || r.URL.Path != "/v1/oauth/provider-list" || r.URL.EscapedPath() != r.URL.Path {
			deny()
			return
		}
		ctx, done, err := s.state.enterFeature(r.Context(), true)
		if err != nil {
			deny()
			return
		}
		defer done()
		next.ServeHTTP(w, r.Clone(ctx))
	})
}
