package reference

import (
	"context"
	"fmt"
	"io"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	identityhttp "github.com/faustbrian/go-identity/http"
	apikeyhttp "github.com/faustbrian/go-identity/http/apikey"
)

// HTTPAPIKeyConfiguration selects each strict-password-bearer management route
// independently. Native APIKey, Session and HTTPRate are required. Mutations
// use the same immutable secret namespace/key as other secret integrations;
// changing that deployment identity resets budgets and debit correlation.
// Reads borrow the existing session/MFA/email/passkey safe limiter. Supply
// StandaloneRate only when none exists; parallel emergency budgets are rejected.
type HTTPAPIKeyConfiguration struct {
	Create, Rotate, Revoke bool
	Get, List              bool
	// OrganizationOwned separately selects organization management on HTTP.
	// Native organization support alone must not expand transport authority.
	OrganizationOwned bool
	SecretNamespace   string
	SecretKey         [32]byte
	StandaloneRate    *APIKeyMetadataRateConfiguration
}

// APIKeyMetadataRateConfiguration selects a safe-read owner only when no other
// safe HTTP owner is selected. Degraded must synchronously record emergency
// decisions within ctx and support concurrent calls; it grants no key authority.
type APIKeyMetadataRateConfiguration struct {
	Namespace            string
	EmergencyMaximumKeys int
	Degraded             func(context.Context, identityhttp.SafeRateEvent) error
}

type apiKeyHTTPState struct {
	config    HTTPAPIKeyConfiguration
	limiter   *identityhttp.KeyedSecretRateLimiter
	safe      *identityhttp.SafeRateLimiter
	ownedSafe bool
}

func (s *apiKeyHTTPState) close() {
	if s != nil && s.limiter != nil {
		s.limiter.Close()
	}
	if s != nil && s.ownedSafe && s.safe != nil {
		s.safe.Close()
	}
}
func composeAPIKeyHTTP(c StoreConfiguration, owner *apiKeyState, shared *httpRateState, sessions *sessionHTTPState, mfa *mfaListHTTPState, addresses *emailAddressesHTTPState, passkeys *passkeyHTTPState) (_ *apiKeyHTTPState, err error) {
	if c.HTTPAPIKey == nil {
		return nil, nil
	}
	h := *c.HTTPAPIKey
	invalid := identity.InvalidInputError{Field: "reference_http_api_key"}
	mutations, reads := h.Create || h.Rotate || h.Revoke, h.Get || h.List
	if owner == nil || shared == nil || c.HTTPRate == nil || !mutations && !reads || h.OrganizationOwned && !owner.organization || h.List && !owner.metadataPaging || !reads && h.StandaloneRate != nil {
		return nil, invalid
	}
	out := &apiKeyHTTPState{config: h}
	defer func() {
		if err != nil {
			out.close()
		}
	}()
	if mutations {
		out.limiter, err = identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: shared.backend, Namespace: h.SecretNamespace, Key: h.SecretKey, Now: time.Now, MaximumDuration: c.HTTPRate.MaximumDuration})
		if err != nil {
			return nil, invalid
		}
	}
	if reads {
		switch {
		case sessions != nil:
			out.safe = sessions.rate
		case mfa != nil:
			out.safe = mfa.rate
		case addresses != nil:
			out.safe = addresses.rate
		case passkeys != nil:
			out.safe = passkeys.safe
		}
		if out.safe != nil {
			if h.StandaloneRate != nil {
				return nil, invalid
			}
		} else {
			if h.StandaloneRate == nil {
				return nil, invalid
			}
			r := *h.StandaloneRate
			out.safe, err = identityhttp.NewSafeRateLimiter(identityhttp.SafeRateConfig{Shared: shared.backend, Namespace: r.Namespace, Now: time.Now, Degraded: r.Degraded, MaximumDuration: c.HTTPRate.MaximumDuration, EmergencyMaximumKeys: r.EmergencyMaximumKeys})
			if err != nil {
				return nil, invalid
			}
			out.ownedSafe = true
		}
	}
	return out, nil
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
	native := n.selfOnly
	var organizationCreator apikeyhttp.OrganizationCreator
	if h.config.OrganizationOwned {
		native = n.native
		if h.config.Create {
			organizationCreator = native
		}
	}
	feature, err := apikeyhttp.NewFeature(apikeyhttp.FeatureConfig{Config: apikeyhttp.Config{Network: network, Sessions: f.session.reader, Creator: native, OrganizationCreator: organizationCreator, Rotator: native, Revoker: native, Getter: native, Lister: native, SecretRate: h.limiter, SafeRate: h.safe, Now: time.Now, MaximumDuration: n.maximum}, Create: h.config.Create, Rotate: h.config.Rotate, Revoke: h.config.Revoke, Get: h.config.Get, List: h.config.List, OrganizationOwned: h.config.OrganizationOwned})
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

// Format redacts deployment policy and callbacks.
func (APIKeyMetadataRateConfiguration) Format(s fmt.State, _ rune) {
	io.WriteString(s, "reference.APIKeyMetadataRateConfiguration(redacted)")
}

// MarshalJSON rejects implicit callback/policy export.
func (APIKeyMetadataRateConfiguration) MarshalJSON() ([]byte, error) {
	return nil, apikey.ErrDisclosure
}

// MarshalText rejects implicit callback/policy export.
func (APIKeyMetadataRateConfiguration) MarshalText() ([]byte, error) {
	return nil, apikey.ErrDisclosure
}
