package reference

import (
	"context"
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	scimorganization "github.com/faustbrian/go-scim/organization"
	scimpg "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

// DirectoryMixedConfiguration selects native User membership and successor
// histories for the existing Group source. Leave Apply nil while installing
// the schema. Selecting mixed execution exposes no HTTP route or permission
// reader; configure GroupSource.Roles independently if needed.
type DirectoryMixedConfiguration struct {
	Apply *DirectoryMixedApplyConfiguration
}

// DirectoryMixedApplyConfiguration freezes explicit User and at least one
// Group or role mapping at the same source and version. Mixed generation
// authorization and original-child admission/recovery are separate policies.
// Membership limits apply to new grants. Role mapping requires GroupSource.Roles.
type DirectoryMixedApplyConfiguration struct {
	Users              scimorganization.DirectoryUserMappingConfig
	Groups             *scimorganization.DirectoryMappingConfig
	Roles              *scimorganization.DirectoryRoleMappingConfig
	Authorization      authorization.Service
	ApplyAuthorization ssopg.DirectorySyncGroupAuthorization
	MaximumMembers     uint64
	MaximumPerUser     uint64
}

type directoryMixedSource struct {
	executor *ssopg.DirectoryMixedSyncService
}

func composeDirectoryMixedSource(d ReferenceDependencies, scope DirectorySyncConfiguration, provider ssopg.ProviderServiceConfig, source *scimpg.GroupsService) (*directoryMixedSource, error) {
	selected := scope.GroupSource
	if selected.Mixed.Apply == nil {
		return &directoryMixedSource{}, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_directory_mixed_apply"}
	apply := *selected.Mixed.Apply
	if apply.Roles != nil && selected.Roles == nil {
		return nil, invalid
	}
	if nilServerDependency(apply.Authorization) || nilServerDependency(apply.ApplyAuthorization) {
		return nil, invalid
	}
	mapping, native := apply.Users, selected.SCIM.Scope
	if mapping.TenantID != native.TenantID || mapping.OrganizationID != native.OrganizationID ||
		string(mapping.ProviderID) != native.ProviderID || mapping.ConnectionID != native.ConnectionID {
		return nil, invalid
	}
	mapper, err := newReferenceDirectoryMixedMapper(apply)
	if err != nil {
		return nil, invalid
	}
	executor, err := ssopg.NewDirectoryMixedSyncService(d.PostgreSQL, ssopg.DirectoryGroupSyncConfig{
		TenantID: scope.TenantID, OrganizationID: organization.ID(scope.OrganizationID), ConnectionID: scope.ConnectionID,
		Clock: provider.Clock, MaximumDuration: provider.MaximumDuration, PolicyID: provider.PolicyID,
		PolicyVersion: provider.PolicyVersion, Coordinator: provider.Coordinator,
	}, ssopg.DirectorySyncMixedConfig{
		Source: source, Mapping: mapper, AuthorityNamespace: selected.SCIM.AuthorityNamespace,
		Authorization: apply.Authorization, ApplyAuthorization: apply.ApplyAuthorization,
		MaximumMembers: apply.MaximumMembers, MaximumPerUser: apply.MaximumPerUser,
	})
	if err != nil {
		return nil, invalid
	}
	return &directoryMixedSource{executor: executor}, nil
}

func newReferenceDirectoryMixedMapper(apply DirectoryMixedApplyConfiguration) (scimorganization.DirectoryMixedMapper, error) {
	var selected scimorganization.DirectoryMixedMappingConfig
	var err error
	selected.Users, err = scimorganization.NewDirectoryUserMapper(apply.Users)
	if err != nil {
		return scimorganization.DirectoryMixedMapper{}, err
	}
	if apply.Groups != nil {
		selected.Groups, err = scimorganization.NewDirectoryMapper(*apply.Groups)
		if err != nil {
			return scimorganization.DirectoryMixedMapper{}, err
		}
	}
	if apply.Roles != nil {
		selected.Roles, err = scimorganization.NewDirectoryRoleMapper(*apply.Roles)
		if err != nil {
			return scimorganization.DirectoryMixedMapper{}, err
		}
	}
	return scimorganization.NewDirectoryMixedMapper(selected)
}

// DirectoryMixedApplyService is the direct Go worker handle for a single
// configured source. Copies share the initialized graph and its shutdown.
type DirectoryMixedApplyService struct {
	state    *storeState
	tenant   identity.TenantID
	executor *ssopg.DirectoryMixedSyncService
}

// DirectoryMixedApply returns the explicitly selected mixed executor. It does
// no I/O and retains no browser credential.
func (f FeatureSet) DirectoryMixedApply() (*DirectoryMixedApplyService, error) {
	state := f.state
	if state == nil {
		return nil, identity.InvalidInputError{Field: "reference_directory_mixed_apply"}
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed || state.features == nil || !state.features.composed || state.features.directorySync == nil {
		return nil, identity.UnavailableError{}
	}
	native := state.features.directorySync
	if native.groups == nil || native.groups.mixed == nil || native.groups.mixed.executor == nil {
		return nil, identity.UnavailableError{}
	}
	return &DirectoryMixedApplyService{state: state, tenant: native.scope.TenantID, executor: native.groups.mixed.executor}, nil
}

// Apply runs or recovers the exact ordered generation request. Keep the
// original ordered child commands and predecessor after an unknown result.
func (s *DirectoryMixedApplyService) Apply(ctx context.Context, request ssopg.DirectoryMixedApplyRequest) (sso.DirectoryApplyResult, error) {
	if s == nil || s.executor == nil {
		return sso.DirectoryApplyResult{}, identity.InvalidInputError{Field: "reference_directory_mixed_apply"}
	}
	bounded, done, err := (composedPasswordReset{state: s.state}).enter(ctx, s.tenant)
	if err != nil {
		return sso.DirectoryApplyResult{}, err
	}
	defer done()
	return s.executor.ApplyGeneration(bounded, request)
}

// ObserveBatchDrift previews the current state of the mapped children at the
// running checkpoint in request order. It requires separate inspection
// authorization, does not apply changes or advance the generation, and
// returns no report on failure. Do not mutate request.Deltas concurrently.
func (s *DirectoryMixedApplyService) ObserveBatchDrift(ctx context.Context, request ssopg.DirectoryMixedApplyRequest) ([]ssopg.DirectoryMixedDrift, error) {
	if s == nil || s.executor == nil {
		return nil, identity.InvalidInputError{Field: "reference_directory_mixed_drift"}
	}
	bounded, done, err := (composedPasswordReset{state: s.state}).enter(ctx, s.tenant)
	if err != nil {
		return nil, err
	}
	defer done()
	return s.executor.ObserveBatchDrift(bounded, request)
}

func (DirectoryMixedConfiguration) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "reference.DirectoryMixedConfiguration(redacted)")
}

func (DirectoryMixedConfiguration) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (DirectoryMixedConfiguration) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

func (DirectoryMixedApplyConfiguration) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "reference.DirectoryMixedApplyConfiguration(redacted)")
}

func (DirectoryMixedApplyConfiguration) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (DirectoryMixedApplyConfiguration) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

func (DirectoryMixedApplyService) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "reference.DirectoryMixedApplyService(redacted)")
}

func (DirectoryMixedApplyService) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (DirectoryMixedApplyService) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
