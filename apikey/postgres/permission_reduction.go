package postgres

import (
	"context"
	"fmt"
	"io"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

// PermissionReductionStoreConfig fixes trusted maintenance/recovery custody.
// TenantID/UserID select one real USER owner; ActorID is a separate service
// actor, never a human credential or a key actor. ActorPolicyNamespace must be
// independently provisioned through the public authorization owner and differ
// from the primary's USER namespace. Its current epoch and application policy
// are checked on every operation, and fenced on mutation through the real Work.
// Request input cannot select any of these fields.
type PermissionReductionStoreConfig struct {
	TenantID             identity.TenantID
	UserID               identity.UserID
	ActorID              identity.ActorID
	ActorPolicyNamespace string
}

func (PermissionReductionStoreConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "apikey/postgres.PermissionReductionStoreConfig(redacted)")
}
func (PermissionReductionStoreConfig) MarshalJSON() ([]byte, error) { return nil, apikey.ErrDisclosure }

// PermissionReductionStore is server-selected current-policy maintenance using
// the primary Service's existing coordinator, preparation and native effects.
// Caller decisions are compare-only inputs, never mutation authority. It owns
// no pool, transaction, journal, authentication credential or background work.
// Immutable composition supports concurrent calls with concurrent-safe borrowed
// owners. Historical inquiry is restricted to this exact fixed scope. The distinct
// organization constructor selects a nonhuman owner without widening USER APIs.
type PermissionReductionStore struct {
	primary        *Service
	config         PermissionReductionStoreConfig
	organizationID apikey.OrganizationID
}

// NewPermissionReductionStore validates composition without I/O. It selects
// modern USER/Narrow only; existing Service constructors and default profiles
// are unchanged. Provision actual actor authority before use. Primary remains
// borrowed and must outlive the Store; no closer or worker is created.
func NewPermissionReductionStore(primary *Service, c PermissionReductionStoreConfig) (*PermissionReductionStore, error) {
	if primary == nil || primary.config == nil || primary.pool == nil || primary.pool.Raw() == nil || primary.organization != nil || primary.organizationID != "" {
		return nil, apikey.ErrInvalid
	}
	source := primary.config()
	profile := source.Configuration.Spec()
	if !scope(string(c.TenantID)) || !scope(string(c.UserID)) || !scope(string(c.ActorID)) || !scope(c.ActorPolicyNamespace) || c.ActorPolicyNamespace == source.Profile.PolicyNamespace || profile.Algorithm != apikey.AlgorithmModernHMACSHA256 || profile.State != apikey.ConfigurationActive || profile.PermissionReduction != apikey.PermissionReductionNarrow || profile.Cache != apikey.CacheDisabled {
		return nil, apikey.ErrInvalid
	}
	return &PermissionReductionStore{primary: primary, config: c}, nil
}

func (s *PermissionReductionStore) actorScope() authority.AuthorityScope {
	return authority.AuthorityScope{TenantID: authorization.TenantID(s.config.TenantID), PolicyNamespace: s.config.ActorPolicyNamespace, SubjectID: authorization.SubjectID(s.config.ActorID)}
}

func (s *PermissionReductionStore) authorizeActor(ctx context.Context) (uint64, error) {
	if s == nil || s.primary == nil || s.primary.config == nil || ctx == nil {
		return 0, apikey.ErrInvalid
	}
	primary := s.primary
	store, err := authority.NewAuthorityStore(primary.pool.Raw(), primary.config().MaximumDuration)
	if err != nil {
		return 0, identity.UnavailableError{}
	}
	current, err := store.Get(ctx, s.actorScope())
	if err != nil {
		return 0, apikey.ErrDenied
	}
	configurationID := primary.config().Configuration.Spec().ID
	dc := authorization.DecisionContext{PolicyRevision: authorization.Revision(primary.config().PolicyVersion), Request: authorization.Request{Tenant: authorization.TenantID(s.config.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(s.config.ActorID)}, Action: "identity.apikey.update", Resource: authorization.Resource{Type: "api-key", ID: authorization.ResourceID(configurationID), Attributes: authorization.Attributes{
		"api-key.owner-user-id":          authorization.StringValue(string(s.config.UserID)),
		"api-key.configuration-id":       authorization.StringValue(configurationID),
		"api-key.actor-policy-namespace": authorization.StringValue(s.config.ActorPolicyNamespace),
	}}}}
	if s.organizationID != "" {
		dc.Request.Resource.Type, dc.Request.Resource.ID = "organization-api-key", authorization.ResourceID(s.organizationID)
		delete(dc.Request.Resource.Attributes, "api-key.owner-user-id")
		dc.Request.Resource.Attributes["api-key.owner-organization-id"] = authorization.StringValue(string(s.organizationID))
	}
	if err := primary.allow(ctx, dc); err != nil {
		return 0, err
	}
	return current.Version, nil
}

func (PermissionReductionStore) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "apikey/postgres.PermissionReductionStore(redacted)")
}
func (PermissionReductionStore) MarshalJSON() ([]byte, error) { return nil, apikey.ErrDisclosure }
