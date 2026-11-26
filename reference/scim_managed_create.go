package reference

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	scimhttp "github.com/faustbrian/go-identity/http/scim"
	scim "github.com/faustbrian/go-scim"
	scimpg "github.com/faustbrian/go-scim/postgres"
)

// HTTPManagedSCIMCreateConfiguration opts into native managed connection
// creation for core User mappings and RemoveMembership. Provisioning supplies
// field policy and an existing service principal in the graph's authority,
// not a configured connection or credential. Reference retains no raw
// issued bearer. AdminRate must be nil to reuse an already selected shared
// organization admin owner; otherwise configure the same native quota owner.
type HTTPManagedSCIMCreateConfiguration struct {
	Authorization      authorization.Service
	PolicyVersion      uint64
	MaximumDuration    time.Duration
	CursorKey          [32]byte
	Provisioning       scimpg.Config
	CredentialKey      [32]byte
	CredentialLifetime time.Duration
	AdminRate          *ManagedSCIMCreateAdminConfiguration
}

// ManagedSCIMCreateAdminConfiguration supplies the stable deployment quota
// identity and synchronous denial auditor when there is no organization HTTP
// admin owner to borrow. The Reference PostgreSQL backend remains shared.
type ManagedSCIMCreateAdminConfiguration struct {
	Namespace string
	Key       [32]byte
	Denied    func(context.Context, organizationhttp.AdminRateEvent) error
}

func (HTTPManagedSCIMCreateConfiguration) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "reference.HTTPManagedSCIMCreateConfiguration(redacted)")
}

func (HTTPManagedSCIMCreateConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "reference_http_managed_scim_create"}
}

func (c HTTPManagedSCIMCreateConfiguration) MarshalText() ([]byte, error) { return c.MarshalJSON() }

func (ManagedSCIMCreateAdminConfiguration) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "reference.ManagedSCIMCreateAdminConfiguration(redacted)")
}

func (ManagedSCIMCreateAdminConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "reference_http_managed_scim_create"}
}

func (c ManagedSCIMCreateAdminConfiguration) MarshalText() ([]byte, error) { return c.MarshalJSON() }

type managedSCIMCreateState struct {
	native   *scimpg.ManagedConnectionService
	rate     *organizationhttp.AdminRateLimiter
	ownsRate bool
	limits   scim.Limits
	maximum  time.Duration
}

func (m *managedSCIMCreateState) close() {
	if m != nil && m.ownsRate {
		_ = m.rate.Close()
	}
}

func (s *storeState) composeManagedSCIMCreate(c StoreConfiguration, d ReferenceDependencies, sessions *sessionState, org *organizationState, httpOrg *organizationHTTPState) (*managedSCIMCreateState, error) {
	if c.HTTPManagedSCIMCreate == nil {
		return nil, nil
	}
	n := *c.HTTPManagedSCIMCreate
	invalid := identity.InvalidInputError{Field: "reference_http_managed_scim_create"}
	if s.httpRate == nil {
		return nil, invalid
	}
	native, err := composeManagedSCIMConnection(c, d, sessions, org, ManagedSCIMConnectionConfiguration{
		Authorization: n.Authorization, PolicyVersion: n.PolicyVersion, MaximumDuration: n.MaximumDuration,
		CursorKey: n.CursorKey, Provisioning: n.Provisioning, CredentialKey: n.CredentialKey, CredentialLifetime: n.CredentialLifetime,
	})
	if err != nil {
		return nil, invalid
	}
	state := &managedSCIMCreateState{native: native, limits: n.Provisioning.Limits, maximum: n.MaximumDuration}
	if httpOrg != nil && httpOrg.admin != nil {
		if n.AdminRate != nil {
			return nil, invalid
		}
		state.rate = httpOrg.admin
		return state, nil
	}
	if n.AdminRate == nil {
		return nil, invalid
	}
	state.rate, err = organizationhttp.NewAdminRateLimiter(organizationhttp.AdminRateConfig{
		Shared: s.httpRate.backend, Namespace: n.AdminRate.Namespace, Key: n.AdminRate.Key, Now: time.Now,
		Denied: n.AdminRate.Denied, MaximumDuration: c.HTTPRate.MaximumDuration,
	})
	if err != nil {
		return nil, invalid
	}
	state.ownsRate = true
	return state, nil
}

func (s *Server) managedSCIMCreateFeature(network identityhttp.NetworkConfig) (identityhttp.Feature, error) {
	f := s.state.features
	selected := f.httpManagedSCIMCreate
	return scimhttp.NewManagedCreateFeature(scimhttp.ManagedCreateConfig{
		Network: network, Sessions: f.session.reader, Creator: selected.native, AdminRate: selected.rate,
		Limits: selected.limits, Now: time.Now, MaximumDuration: selected.maximum,
	})
}
