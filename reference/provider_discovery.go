package reference

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/oauth/providers"
	"github.com/faustbrian/go-identity/risk"
)

// ProviderDiscoveryConfiguration selects only public configured-provider
// discovery on the PostgreSQL DurableAdmission and HTTPRate base. Authentication
// features cannot be selected in this standalone profile. Catalog is passed to
// the real providers.NewCatalog constructor, which snapshots the already-built
// provider facts and copies cursor-key custody. The caller retains provider
// lifetimes and clears source key bytes after construction.
//
// Authorize binds the same comparable handle as ReferenceConfig.Policies; it
// is never invoked to authenticate or authorize anonymous discovery. Degraded
// is the bounded, concurrency-safe mandatory safe-rate degradation recorder.
// RateNamespace and EmergencyMaximumKeys obey identityhttp.SafeRateConfig.
// MaximumDuration is 1ms..30s and never extends the incoming deadline. The
// reference graph owns the catalog snapshot and dedicated shared safe limiter;
// the PostgreSQL pool and callbacks remain borrowed. Construction performs no IO.
type ProviderDiscoveryConfiguration struct {
	Catalog              providers.CatalogConfig
	Authorize            authorization.Service
	RateNamespace        string
	EmergencyMaximumKeys int
	Degraded             func(context.Context, identityhttp.SafeRateEvent) error
	MaximumDuration      time.Duration
}

type providerDiscoveryState struct {
	catalog   *providers.CatalogImpl
	rate      *identityhttp.SafeRateLimiter
	duration  time.Duration
	authorize authorization.Service
}

func composeProviderDiscovery(c StoreConfiguration, rate *httpRateState) (*providerDiscoveryState, error) {
	if c.ProviderDiscovery == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_provider_discovery"}
	if !providerDiscoveryOnly(c) || rate == nil || rate.backend == nil {
		return nil, invalid
	}
	n := *c.ProviderDiscovery
	if nilServerDependency(n.Authorize) || n.MaximumDuration < time.Millisecond || n.MaximumDuration > 30*time.Second {
		return nil, invalid
	}
	catalog, err := providers.NewCatalog(n.Catalog)
	if err != nil {
		return nil, invalid
	}
	limiter, err := identityhttp.NewSafeRateLimiter(identityhttp.SafeRateConfig{
		Shared: rate.backend, Namespace: n.RateNamespace, Now: time.Now, Degraded: n.Degraded,
		MaximumDuration: c.HTTPRate.MaximumDuration, EmergencyMaximumKeys: n.EmergencyMaximumKeys,
	})
	if err != nil {
		return nil, invalid
	}
	return &providerDiscoveryState{catalog: catalog, rate: limiter, duration: n.MaximumDuration, authorize: n.Authorize}, nil
}

func (s *providerDiscoveryState) close() {
	if s != nil && s.rate != nil {
		_ = s.rate.Close()
	}
}

// Format prevents implicit export of provider, cursor-key and callback custody.
func (ProviderDiscoveryConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.ProviderDiscoveryConfiguration(redacted)")
}

// MarshalJSON rejects implicit deployment configuration export.
func (ProviderDiscoveryConfiguration) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// MarshalText rejects implicit deployment configuration export.
func (ProviderDiscoveryConfiguration) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
