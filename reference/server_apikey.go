package reference

import (
	"fmt"
	"io"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	identityhttp "github.com/faustbrian/go-identity/http"
	apikeyhttp "github.com/faustbrian/go-identity/http/apikey"
)

// HTTPAPIKeyConfiguration selects each strict-password-bearer management route
// independently. Native APIKey, Session and the shared strong HTTPRate backend
// are required. Use the same immutable secret namespace/key as other selected
// secret integrations so cross-route budgets remain shared. Changing that
// deployment identity resets budgets and original debit correlation.
type HTTPAPIKeyConfiguration struct {
	Create, Rotate, Revoke bool
	SecretNamespace        string
	SecretKey              [32]byte
}

type apiKeyHTTPState struct {
	config  HTTPAPIKeyConfiguration
	limiter *identityhttp.KeyedSecretRateLimiter
}

func (s *apiKeyHTTPState) close() {
	if s != nil && s.limiter != nil {
		s.limiter.Close()
	}
}
func composeAPIKeyHTTP(c StoreConfiguration, owner *apiKeyState, shared *httpRateState) (*apiKeyHTTPState, error) {
	if c.HTTPAPIKey == nil {
		return nil, nil
	}
	h := *c.HTTPAPIKey
	invalid := identity.InvalidInputError{Field: "reference_http_api_key"}
	if owner == nil || shared == nil || c.HTTPRate == nil || !h.Create && !h.Rotate && !h.Revoke {
		return nil, invalid
	}
	limiter, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: shared.backend, Namespace: h.SecretNamespace, Key: h.SecretKey, Now: time.Now, MaximumDuration: c.HTTPRate.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	return &apiKeyHTTPState{config: h, limiter: limiter}, nil
}

func (s *Server) apiKeyFeature(network identityhttp.NetworkConfig) (*identityhttp.Feature, error) {
	f := s.state.features
	if f == nil || f.httpAPIKey == nil {
		return nil, nil
	}
	if f.apiKey == nil || f.session == nil {
		return nil, identity.InvalidInputError{Field: "reference_http_api_key"}
	}
	h, n := f.httpAPIKey, f.apiKey
	feature, err := apikeyhttp.NewFeature(apikeyhttp.FeatureConfig{Config: apikeyhttp.Config{Network: network, Sessions: f.session.reader, Creator: n.native, Rotator: n.native, Revoker: n.native, SecretRate: h.limiter, Now: time.Now, MaximumDuration: n.maximum}, Create: h.config.Create, Rotate: h.config.Rotate, Revoke: h.config.Revoke})
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
	feature, err = identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/apikey", Operations: ops})
	return &feature, err
}
func (HTTPAPIKeyConfiguration) Format(s fmt.State, _ rune) {
	io.WriteString(s, "reference.HTTPAPIKeyConfiguration(redacted)")
}
func (HTTPAPIKeyConfiguration) MarshalJSON() ([]byte, error) { return nil, apikey.ErrDisclosure }
func (HTTPAPIKeyConfiguration) MarshalText() ([]byte, error) { return nil, apikey.ErrDisclosure }
