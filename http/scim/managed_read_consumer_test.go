package scimhttp_test

import (
	"net/http"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	scimhttp "github.com/faustbrian/go-identity/http/scim"
	"github.com/faustbrian/go-identity/session"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
)

// These assertions prove the published native owner needs no consumer adapter.
// Real database/current-authority acceptance belongs to the existing Reference
// signup + organization + native PostgreSQL fixture, not this transport double.
var (
	_ scimhttp.ManagedConnectionGetter = (*scimpostgres.ManagedConnectionService)(nil)
	_ scimhttp.ManagedConnectionLister = (*scimpostgres.ManagedConnectionService)(nil)
)

func ExampleNewManagedReadFeature() {
	compose := func(native *scimpostgres.ManagedConnectionService, sessions *session.SessionService, safe *identityhttp.SafeRateLimiter, policy identityhttp.TransportPolicy) (http.Handler, error) {
		feature, err := scimhttp.NewManagedReadFeature(scimhttp.ManagedReadConfig{
			Network: policy.Network, Sessions: sessions, Getter: native, Lister: native,
			SafeRate: safe, Now: time.Now, MaximumDuration: 5 * time.Second,
		})
		if err != nil {
			return nil, err
		}
		operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			return nil, err
		}
		handler, _, err := identityhttp.NewRouter(policy, operations, nil)
		return handler, err
	}
	_ = compose
}
