package scimhttp_test

import (
	"net/http"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	scimhttp "github.com/faustbrian/go-identity/http/scim"
	"github.com/faustbrian/go-identity/session"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
)

var _ scimhttp.ManagedConnectionCreator = (*scimpostgres.ManagedConnectionService)(nil)

func ExampleNewManagedCreateFeature() {
	compose := func(native *scimpostgres.ManagedConnectionService, sessions *session.SessionService, admin *organizationhttp.AdminRateLimiter, limits scimpostgres.ManagedConnectionServiceConfig, policy identityhttp.TransportPolicy) (http.Handler, error) {
		feature, err := scimhttp.NewManagedCreateFeature(scimhttp.ManagedCreateConfig{
			Network: policy.Network, Sessions: sessions, Creator: native, AdminRate: admin, Limits: limits.Limits, Now: time.Now, MaximumDuration: 5 * time.Second,
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
