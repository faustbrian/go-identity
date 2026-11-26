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

// DirectoryGroupRoleConfiguration selects the directory team-role history.
// An empty configuration installs only the history when migrations run.
// Set Apply to also enable direct role reconciliation and current role reads.
type DirectoryGroupRoleConfiguration struct {
	Apply *DirectoryGroupRoleApplyConfiguration
}

// DirectoryGroupRoleApplyConfiguration binds an explicit source-to-team and
// custom-role mapping. Authorization controls original child admission and
// receipt recovery. ApplyAuthorization separately authorizes the configured
// service account for role Apply on the exact generation.
type DirectoryGroupRoleApplyConfiguration struct {
	Mapping            scimorganization.DirectoryRoleMappingConfig
	Authorization      authorization.Service
	ApplyAuthorization ssopg.DirectorySyncRoleAuthorization
}

type directoryGroupRoleSource struct {
	executor *ssopg.DirectoryGroupRoleSyncService
}

func composeDirectoryGroupRoles(d ReferenceDependencies, scope DirectorySyncConfiguration, provider ssopg.ProviderServiceConfig, source *scimpg.GroupsService) (*directoryGroupRoleSource, error) {
	selected := scope.GroupSource
	if selected.Roles.Apply == nil {
		return &directoryGroupRoleSource{}, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_directory_group_roles"}
	apply := *selected.Roles.Apply
	mapping, native := apply.Mapping.Directory, selected.SCIM.Scope
	if mapping.TenantID != native.TenantID || mapping.OrganizationID != native.OrganizationID ||
		string(mapping.ProviderID) != native.ProviderID || mapping.ConnectionID != native.ConnectionID {
		return nil, invalid
	}
	mapper, err := scimorganization.NewDirectoryRoleMapper(apply.Mapping)
	if err != nil {
		return nil, invalid
	}
	executor, err := ssopg.NewDirectoryGroupRoleSyncService(d.PostgreSQL, ssopg.DirectoryGroupRoleSyncConfig{
		TenantID: scope.TenantID, OrganizationID: organization.ID(scope.OrganizationID), ConnectionID: scope.ConnectionID,
		Clock: provider.Clock, MaximumDuration: provider.MaximumDuration, PolicyID: provider.PolicyID,
		PolicyVersion: provider.PolicyVersion, Coordinator: provider.Coordinator,
	}, ssopg.DirectorySyncGroupRolesConfig{
		Source: source, Mapping: mapper, AuthorityNamespace: selected.SCIM.AuthorityNamespace,
		Authorization: apply.Authorization, ApplyAuthorization: apply.ApplyAuthorization,
	})
	if err != nil {
		return nil, invalid
	}
	return &directoryGroupRoleSource{executor: executor}, nil
}

// DirectoryGroupRoleApplyService is the direct role worker handle. It borrows
// the immutable graph and respects its initialization and shutdown. It does
// not carry human credentials or own a route or background job.
type DirectoryGroupRoleApplyService struct {
	state    *storeState
	tenant   identity.TenantID
	executor *ssopg.DirectoryGroupRoleSyncService
}

// DirectoryGroupRoleApply returns the explicitly bound role worker. A source
// or migration selection alone does not expose it. This performs no I/O.
func (f FeatureSet) DirectoryGroupRoleApply() (*DirectoryGroupRoleApplyService, error) {
	state := f.state
	if state == nil {
		return nil, identity.InvalidInputError{Field: "reference_directory_group_role_apply"}
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed || state.features == nil || !state.features.composed || state.features.directorySync == nil {
		return nil, identity.UnavailableError{}
	}
	native := state.features.directorySync
	if native.groups == nil || native.groups.roles == nil || native.groups.roles.executor == nil {
		return nil, identity.UnavailableError{}
	}
	return &DirectoryGroupRoleApplyService{state: state, tenant: native.scope.TenantID, executor: native.groups.roles.executor}, nil
}

// Apply applies one role-bearing edge. Retry with the exact original
// generation, predecessor and child command; the native owner decides whether
// there is a current successor or a retained original receipt to recover.
func (s *DirectoryGroupRoleApplyService) Apply(ctx context.Context, request ssopg.DirectoryGroupRoleApplyRequest) (sso.DirectoryApplyResult, error) {
	if s == nil || s.executor == nil {
		return sso.DirectoryApplyResult{}, identity.InvalidInputError{Field: "reference_directory_group_role_apply"}
	}
	bounded, done, err := (composedPasswordReset{state: s.state}).enter(ctx, s.tenant)
	if err != nil {
		return sso.DirectoryApplyResult{}, err
	}
	defer done()
	return s.executor.ApplyGeneration(bounded, request)
}

// ObserveDrift inspects the exact mapped role at the current directory
// checkpoint under separate read authorization. It does not change access,
// apply a repair, or advance the generation. Failure returns no report.
func (s *DirectoryGroupRoleApplyService) ObserveDrift(ctx context.Context, request ssopg.DirectoryGroupRoleApplyRequest) (ssopg.DirectoryGroupRoleDrift, error) {
	if s == nil || s.executor == nil {
		return ssopg.DirectoryGroupRoleDrift{}, identity.InvalidInputError{Field: "reference_directory_group_role_drift"}
	}
	bounded, done, err := (composedPasswordReset{state: s.state}).enter(ctx, s.tenant)
	if err != nil {
		return ssopg.DirectoryGroupRoleDrift{}, err
	}
	defer done()
	return s.executor.ObserveDrift(bounded, request)
}

func (DirectoryGroupRoleConfiguration) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "reference.DirectoryGroupRoleConfiguration(redacted)")
}
func (DirectoryGroupRoleApplyConfiguration) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "reference.DirectoryGroupRoleApplyConfiguration(redacted)")
}
func (DirectoryGroupRoleApplyService) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "reference.DirectoryGroupRoleApplyService(redacted)")
}

func (DirectoryGroupRoleConfiguration) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (DirectoryGroupRoleApplyConfiguration) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (DirectoryGroupRoleApplyService) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

func (DirectoryGroupRoleConfiguration) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (DirectoryGroupRoleApplyConfiguration) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (DirectoryGroupRoleApplyService) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
