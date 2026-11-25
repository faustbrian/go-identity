package reference

import (
	"context"
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	scimorganization "github.com/faustbrian/go-scim/organization"
	scimpg "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

// DirectoryGroupSourceConfiguration selects the native Groups source on the
// Reference primary. Configure the exact directory tenant, organization and
// connection plus the installed provider. The graph's EnvelopeKeys must be the
// keyring provider required by SCIM. Install the owned schemas and initialize
// the source using its SCIM owner before Apply. No SCIM or Apply HTTP is enabled.
type DirectoryGroupSourceConfiguration struct {
	SCIM           scimpg.Config
	MaximumMembers int
	// Apply binds one immutable mapping to this graph. Leave it nil while
	// installing or initializing the source. Switch graphs to change mappings.
	Apply *DirectoryGroupApplyConfiguration
	// Roles selects the directory role schema and, independently of Apply,
	// can bind a direct role executor and current permission reader.
	Roles *DirectoryGroupRoleConfiguration
	// Mixed selects the remaining organization histories and can bind an
	// independent Go-only executor on this same source.
	Mixed *DirectoryMixedConfiguration
}

// DirectoryGroupApplyConfiguration is trusted deployment configuration for
// one versioned source-to-team mapper. A caller presenting a directory delta
// cannot choose these mappings or either authorization owner. Authorization
// separately controls original-child admission/receipt observation. Supply a
// current absolute decision deadline through ApplyAuthorization; the drift
// inspection action requires a separate decision.
type DirectoryGroupApplyConfiguration struct {
	Mapping            scimorganization.DirectoryMappingConfig
	Authorization      authorization.Service
	ApplyAuthorization ssopg.DirectorySyncGroupAuthorization
}

type directoryGroupSource struct {
	source   *scimpg.GroupsService
	executor *ssopg.DirectoryGroupSyncService
	roles    *directoryGroupRoleSource
	mixed    *directoryMixedSource
}

func (DirectoryGroupSourceConfiguration) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "reference.DirectoryGroupSourceConfiguration(redacted)")
}

func (DirectoryGroupSourceConfiguration) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

func (DirectoryGroupSourceConfiguration) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

func composeDirectoryGroupSource(d ReferenceDependencies, scope DirectorySyncConfiguration, p ssopg.ProviderServiceConfig, org *organizationState) (*directoryGroupSource, error) {
	invalid := identity.InvalidInputError{Field: "reference_directory_group_source"}
	c := *scope.GroupSource
	selected := c.SCIM.Scope
	if !org.teamLifecycle || c.Roles != nil && !org.teamRoleBindings {
		return nil, invalid
	}
	groups, err := composeDirectorySource(d, scope, c.SCIM, c.MaximumMembers)
	if err != nil {
		return nil, invalid
	}
	source := &directoryGroupSource{source: groups}
	if c.Roles != nil {
		source.roles, err = composeDirectoryGroupRoles(d, scope, p, groups)
		if err != nil {
			return nil, err
		}
	}
	if c.Mixed != nil {
		source.mixed, err = composeDirectoryMixedSource(d, scope, p, source.source)
		if err != nil {
			return nil, err
		}
	}
	if c.Apply == nil {
		return source, nil
	}
	config := *c.Apply
	mapping := config.Mapping
	if mapping.TenantID != selected.TenantID || mapping.OrganizationID != selected.OrganizationID ||
		string(mapping.ProviderID) != selected.ProviderID || mapping.ConnectionID != selected.ConnectionID {
		return nil, invalid
	}
	mapper, err := scimorganization.NewDirectoryMapper(mapping)
	if err != nil {
		return nil, invalid
	}
	executor, err := ssopg.NewDirectoryGroupSyncService(d.PostgreSQL, ssopg.DirectoryGroupSyncConfig{
		TenantID: scope.TenantID, OrganizationID: organization.ID(scope.OrganizationID), ConnectionID: scope.ConnectionID,
		Clock: p.Clock, MaximumDuration: p.MaximumDuration, PolicyID: p.PolicyID, PolicyVersion: p.PolicyVersion, Coordinator: p.Coordinator,
	}, ssopg.DirectorySyncGroupEdgesConfig{
		Source: groups, Mapping: mapper, AuthorityNamespace: c.SCIM.AuthorityNamespace,
		Authorization: config.Authorization, ApplyAuthorization: config.ApplyAuthorization,
	})
	if err != nil {
		return nil, invalid
	}
	source.executor = executor
	return source, nil
}

func composeDirectorySource(d ReferenceDependencies, scope DirectorySyncConfiguration, c scimpg.Config, maximum int) (*scimpg.GroupsService, error) {
	selected := c.Scope
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	if !ok || keys == nil || selected.TenantID != scope.TenantID || string(selected.OrganizationID) != scope.OrganizationID || selected.ConnectionID != scope.ConnectionID {
		return nil, identity.InvalidInputError{Field: "reference_directory_source"}
	}
	native, err := scimpg.NewService(d.PostgreSQL, c, keys)
	if err != nil {
		return nil, err
	}
	return scimpg.NewGroupsService(native, maximum)
}

// DirectoryGroupApplyService is a direct, versioned worker handle. Copies
// share immutable configuration and respect Reference initialization, tenant
// selection and shutdown. It owns no route or background work.
type DirectoryGroupApplyService struct {
	state    *storeState
	tenant   identity.TenantID
	executor *ssopg.DirectoryGroupSyncService
}

// DirectoryGroupApply returns the graph's configured native executor.
// It performs no I/O and retains no human credentials. Apply uses the native
// source's confirmed service account, not a value supplied in the call.
func (f FeatureSet) DirectoryGroupApply() (*DirectoryGroupApplyService, error) {
	state := f.state
	if state == nil {
		return nil, identity.InvalidInputError{Field: "reference_directory_group_apply"}
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed || state.features == nil || !state.features.composed || state.features.directorySync == nil ||
		state.features.directorySync.groups == nil || state.features.directorySync.groups.executor == nil {
		return nil, identity.UnavailableError{}
	}
	native := state.features.directorySync
	return &DirectoryGroupApplyService{state: state, tenant: native.scope.TenantID, executor: native.groups.executor}, nil
}

// Apply runs or recovers the exact original batch. Preserve the original
// generation, child command IDs and predecessor on retry; a returned prefix
// does not advance an unsettled checkpoint.
func (s *DirectoryGroupApplyService) Apply(ctx context.Context, request ssopg.DirectoryGroupApplyRequest) (sso.DirectoryApplyResult, error) {
	if s == nil || s.executor == nil {
		return sso.DirectoryApplyResult{}, identity.InvalidInputError{Field: "reference_directory_group_apply"}
	}
	bounded, done, err := (composedPasswordReset{state: s.state}).enter(ctx, s.tenant)
	if err != nil {
		return sso.DirectoryApplyResult{}, err
	}
	defer done()
	return s.executor.ApplyGeneration(bounded, request)
}

// ObserveDrift compares one mapped Group edge with its exact organization
// grant at the current running Apply or dry-run checkpoint. It requires the
// configured service account's independent drift inspection authorization.
// It writes nothing and does not grant permission to repair the reported drift.
func (s *DirectoryGroupApplyService) ObserveDrift(ctx context.Context, request ssopg.DirectoryGroupApplyRequest) (scimorganization.DirectoryMembershipDrift, error) {
	if s == nil || s.executor == nil {
		return scimorganization.DirectoryMembershipDrift{}, identity.InvalidInputError{Field: "reference_directory_group_drift"}
	}
	bounded, done, err := (composedPasswordReset{state: s.state}).enter(ctx, s.tenant)
	if err != nil {
		return scimorganization.DirectoryMembershipDrift{}, err
	}
	defer done()
	return s.executor.ObserveDrift(bounded, request)
}

func (DirectoryGroupApplyService) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "reference.DirectoryGroupApplyService(redacted)")
}

func (DirectoryGroupApplyService) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (DirectoryGroupApplyService) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
