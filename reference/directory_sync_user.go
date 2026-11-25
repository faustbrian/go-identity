package reference

import (
	"context"
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-scim"
	scimorganization "github.com/faustbrian/go-scim/organization"
	scimpg "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

// DirectoryUserSourceConfiguration selects source-owned organization
// membership. Set SCIM for User-only graphs. Leave it nil when GroupSource
// is selected; both profiles then use the same SCIM owner. Leave Apply nil
// to prepare the schema without selecting a worker handle. No route is added.
type DirectoryUserSourceConfiguration struct {
	SCIM  *scimpg.Config
	Apply *DirectoryUserApplyConfiguration
}

// DirectoryUserApplyConfiguration freezes one versioned mapping and its
// admission/withdrawal policy. Separate policy owners authorize generation
// admission and original child execution/recovery. Limits apply only to grants.
type DirectoryUserApplyConfiguration struct {
	Mapping            scimorganization.DirectoryUserMappingConfig
	Authorization      authorization.Service
	ApplyAuthorization ssopg.DirectorySyncUserAuthorization
	MaximumMembers     uint64
	MaximumPerUser     uint64
}

type directoryUserSource struct {
	executor *ssopg.DirectoryUserSyncService
}

func composeDirectoryUserSource(d ReferenceDependencies, scope DirectorySyncConfiguration, provider ssopg.ProviderServiceConfig, group *directoryGroupSource) (*directoryUserSource, error) {
	invalid := identity.InvalidInputError{Field: "reference_directory_user_source"}
	config := *scope.UserSource
	var source *scimpg.GroupsService
	var native scimpg.Config
	if group == nil {
		if config.SCIM == nil {
			return nil, invalid
		}
		native = *config.SCIM
		var err error
		source, err = composeDirectorySource(d, scope, native, scim.DefaultGroupMembers)
		if err != nil {
			return nil, invalid
		}
	} else {
		if config.SCIM != nil {
			return nil, invalid
		}
		native, source = scope.GroupSource.SCIM, group.source
	}
	if config.Apply == nil {
		return &directoryUserSource{}, nil
	}
	apply, selected := *config.Apply, native.Scope
	mapping := apply.Mapping
	if mapping.TenantID != selected.TenantID || mapping.OrganizationID != selected.OrganizationID ||
		string(mapping.ProviderID) != selected.ProviderID || mapping.ConnectionID != selected.ConnectionID {
		return nil, invalid
	}
	mapper, err := scimorganization.NewDirectoryUserMapper(mapping)
	if err != nil {
		return nil, invalid
	}
	executor, err := ssopg.NewDirectoryUserSyncService(d.PostgreSQL, ssopg.DirectoryUserSyncConfig{
		TenantID: scope.TenantID, OrganizationID: organization.ID(scope.OrganizationID), ConnectionID: scope.ConnectionID,
		Clock: provider.Clock, MaximumDuration: provider.MaximumDuration, PolicyID: provider.PolicyID,
		PolicyVersion: provider.PolicyVersion, Coordinator: provider.Coordinator,
	}, ssopg.DirectorySyncUsersConfig{
		Source: source, Mapping: mapper, AuthorityNamespace: native.AuthorityNamespace,
		Authorization: apply.Authorization, ApplyAuthorization: apply.ApplyAuthorization,
		MaximumMembers: apply.MaximumMembers, MaximumPerUser: apply.MaximumPerUser,
	})
	if err != nil {
		return nil, invalid
	}
	return &directoryUserSource{executor: executor}, nil
}

// DirectoryUserApplyService is the direct worker handle. Copies share the
// configured graph lifecycle, immutable mapper and native source owner.
type DirectoryUserApplyService struct {
	state    *storeState
	tenant   identity.TenantID
	executor *ssopg.DirectoryUserSyncService
}

// DirectoryUserApply returns the explicitly selected direct User executor.
// It performs no I/O and borrows no human credentials.
func (f FeatureSet) DirectoryUserApply() (*DirectoryUserApplyService, error) {
	state := f.state
	if state == nil {
		return nil, identity.InvalidInputError{Field: "reference_directory_user_apply"}
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed || state.features == nil || !state.features.composed || state.features.directorySync == nil ||
		state.features.directorySync.users == nil || state.features.directorySync.users.executor == nil {
		return nil, identity.UnavailableError{}
	}
	native := state.features.directorySync
	return &DirectoryUserApplyService{state: state, tenant: native.scope.TenantID, executor: native.users.executor}, nil
}

// Apply runs or recovers the exact User delta accepted by the native owner.
// On an unknown outcome preserve the original request and predecessor.
func (s *DirectoryUserApplyService) Apply(ctx context.Context, request ssopg.DirectoryUserApplyRequest) (sso.DirectoryApplyResult, error) {
	if s == nil || s.executor == nil {
		return sso.DirectoryApplyResult{}, identity.InvalidInputError{Field: "reference_directory_user_apply"}
	}
	bounded, done, err := (composedPasswordReset{state: s.state}).enter(ctx, s.tenant)
	if err != nil {
		return sso.DirectoryApplyResult{}, err
	}
	defer done()
	return s.executor.ApplyGeneration(bounded, request)
}

func (DirectoryUserSourceConfiguration) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "reference.DirectoryUserSourceConfiguration(redacted)")
}

func (DirectoryUserSourceConfiguration) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

func (DirectoryUserSourceConfiguration) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

func (DirectoryUserApplyService) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "reference.DirectoryUserApplyService(redacted)")
}

func (DirectoryUserApplyService) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

func (DirectoryUserApplyService) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
