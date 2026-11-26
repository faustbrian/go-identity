package reference

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	scimhttp "github.com/faustbrian/go-identity/http/scim"
	scim "github.com/faustbrian/go-scim"
	scimpg "github.com/faustbrian/go-scim/postgres"
)

// HTTPManagedSCIMReadConfiguration selects the bearer-only managed SCIM
// connection reads independently of Bulk. Reference supplies its primary
// session, organization and PostgreSQL rate owners. Authorization must serve
// current org:scim-read decisions at PolicyVersion. The cursor key and safe
// rate namespace must be stable across instances. Degraded has the safe rate
// limiter's synchronous, bounded audit contract. No writes are selected.
type HTTPManagedSCIMReadConfiguration struct {
	Get, List            bool
	Authorization        authorization.Service
	PolicyVersion        uint64
	MaximumDuration      time.Duration
	CursorKey            [32]byte
	Limits               scim.Limits
	SafeNamespace        string
	EmergencyMaximumKeys int
	Degraded             func(context.Context, identityhttp.SafeRateEvent) error
}

func (HTTPManagedSCIMReadConfiguration) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "reference.HTTPManagedSCIMReadConfiguration(redacted)")
}

func (HTTPManagedSCIMReadConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "reference_http_managed_scim_read"}
}

func (c HTTPManagedSCIMReadConfiguration) MarshalText() ([]byte, error) { return c.MarshalJSON() }

type managedSCIMReadState struct {
	native    *scimpg.ManagedConnectionService
	rate      *identityhttp.SafeRateLimiter
	get, list bool
	maximum   time.Duration
}

func (m *managedSCIMReadState) close() {
	if m != nil {
		m.rate.Close()
	}
}

func (s *storeState) composeManagedSCIMRead(c StoreConfiguration, d ReferenceDependencies, sessions *sessionState, org *organizationState) (*managedSCIMReadState, error) {
	if c.HTTPManagedSCIMRead == nil {
		return nil, nil
	}
	n := *c.HTTPManagedSCIMRead
	invalid := identity.InvalidInputError{Field: "reference_http_managed_scim_read"}
	if sessions == nil || !sessions.reader.Configured() || org == nil || s.httpRate == nil || !n.Get && !n.List || nilServerDependency(n.Authorization) {
		return nil, invalid
	}
	native, err := scimpg.NewManagedConnectionService(d.PostgreSQL, scimpg.ManagedConnectionServiceConfig{
		Sessions: sessions.reader, Authorization: n.Authorization, PolicyVersion: n.PolicyVersion,
		MaximumDuration: n.MaximumDuration, CursorKey: n.CursorKey, Limits: n.Limits,
	})
	if err != nil {
		return nil, invalid
	}
	rate, err := identityhttp.NewSafeRateLimiter(identityhttp.SafeRateConfig{
		Shared: s.httpRate.backend, Namespace: n.SafeNamespace, Now: time.Now, MaximumDuration: c.HTTPRate.MaximumDuration,
		EmergencyMaximumKeys: n.EmergencyMaximumKeys, Degraded: n.Degraded,
	})
	if err != nil {
		return nil, invalid
	}
	return &managedSCIMReadState{native: native, rate: rate, get: n.Get, list: n.List, maximum: n.MaximumDuration}, nil
}

func (s *Server) scimFeature(network identityhttp.NetworkConfig) (*identityhttp.Feature, error) {
	bulk, err := s.scimBulkFeature(network)
	if err != nil {
		return nil, err
	}
	f := s.state.features
	selected := f.httpManagedSCIMRead
	if selected == nil && f.httpManagedSCIMCreate == nil && f.httpManagedSCIMUsersList == nil {
		return bulk, nil
	}
	var ops []identityhttp.OperationDescriptor
	if bulk != nil {
		ops = bulk.Operations()
	}
	appendManaged := func(feature identityhttp.Feature) {
		managed := feature.Operations()
		for i := range managed {
			managed[i].Handler = &passkeyLifetimeHandler{state: s.state, next: managed[i].Handler}
		}
		ops = append(ops, managed...)
	}
	if selected != nil {
		c := scimhttp.ManagedReadConfig{Network: network, Sessions: f.session.reader, SafeRate: selected.rate, Now: time.Now, MaximumDuration: selected.maximum}
		if selected.get {
			c.Getter = selected.native
		}
		if selected.list {
			c.Lister = selected.native
		}
		read, err := scimhttp.NewManagedReadFeature(c)
		if err != nil {
			return nil, identity.InvalidInputError{Field: "reference_http_managed_scim_read"}
		}
		appendManaged(read)
	}
	if f.httpManagedSCIMCreate != nil {
		create, err := s.managedSCIMCreateFeature(network)
		if err != nil {
			return nil, identity.InvalidInputError{Field: "reference_http_managed_scim_create"}
		}
		appendManaged(create)
	}
	if f.httpManagedSCIMUsersList != nil {
		users, err := s.managedSCIMUsersListFeature(network)
		if err != nil {
			return nil, identity.InvalidInputError{Field: managedSCIMUsersListField}
		}
		ops = append(ops, users.Operations()...)
	}
	feature, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "scim", Operations: ops})
	return &feature, err
}
