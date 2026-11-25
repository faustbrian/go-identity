package reference

import (
	"context"
	"slices"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scimpg "github.com/faustbrian/go-scim/postgres"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func (s StoreSet) directorySyncMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if s.state.features == nil || s.state.features.directorySync == nil {
		return catalog, nil
	}
	catalog, err := organizationCredentialAuthorityMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(catalog, func(h migrationHistory) bool { return h.namespace == "identity_enterprise_oidc" }) {
		providers, err := enterpriseProviderMigrationHistory(ctx, false, false)
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, providers)
	}
	// Apply the native empty generation table after its provider registry.
	// Keeping a separate history preserves the provider and sign-in prefixes.
	generation := migrationHistory{namespace: "identity_sso_directory_sync", owners: map[migrations.Version]ModuleID{}}
	err = appendEnterpriseMigration(ctx, &generation, "sso/postgres", ssopg.DirectorySyncGenerationMigrationSource{Version: 1},
		migrationGuard{version: 1, schema: "sso_providers", tables: []string{"directory_sync_generations"}})
	if err != nil {
		return nil, err
	}
	catalog = append(catalog, generation)
	profile := s.state.features.directorySync
	if profile.groups == nil && profile.users == nil {
		return catalog, nil
	}
	selected := directorySyncSourceMigrations{users: profile.users != nil}
	if groups := profile.groups; groups != nil {
		selected.groups, selected.roles, selected.mixed = true, groups.roles != nil, groups.mixed != nil
	}
	return directorySyncSourceMigrationCatalog(ctx, catalog, selected)
}

type directorySyncSourceMigrations struct{ groups, users, roles, mixed bool }

func directorySyncSourceMigrationCatalog(ctx context.Context, catalog []migrationHistory, selected directorySyncSourceMigrations) ([]migrationHistory, error) {
	if len(catalog) == 0 || catalog[0].namespace != "" {
		return nil, identity.InvalidInputError{Field: "reference_catalog"}
	}
	if !slices.ContainsFunc(catalog, func(h migrationHistory) bool { return h.namespace == canonicalRequestHistory }) {
		requests, err := canonicalRequestMigrationHistory(ctx, catalog[0].history)
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, requests)
	}
	// Keep the complete, already-published SCIM history under one namespace.
	// Adding or removing a worker profile must not re-own its installed prefix.
	scimHistory := migrationHistory{namespace: "identity_scim_directory_groups", owners: map[migrations.Version]ModuleID{}}
	base := scimpg.MigrationSource{Version: 1}
	users := scimpg.UsersMigrationSource{Base: base, Version: 2}
	groups := scimpg.GroupsMigrationSource{Base: users, Version: 3}
	err := appendEnterpriseMigration(ctx, &scimHistory, "scim/postgres", groups,
		migrationGuard{version: 1, schema: "scim", tables: []string{"connections", "users"}})
	if err != nil {
		return nil, err
	}
	scimHistory.guards = append(scimHistory.guards,
		migrationGuard{version: 2, schema: "scim", columns: []string{"users.generation", "users.deleted_at"}},
		migrationGuard{version: 3, schema: "scim", tables: []string{"groups"}})
	catalog = append(catalog, scimHistory)
	if selected.groups {
		grants := migrationHistory{namespace: "identity_organization_directory_grants", owners: map[migrations.Version]ModuleID{}}
		err := appendEnterpriseMigration(ctx, &grants, "organization/postgres", organizationpg.DirectoryTeamGrantMigrationSource{Version: 1},
			migrationGuard{version: 1, schema: "organization", tables: []string{"directory_team_grants"}})
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, grants)
		if selected.roles {
			roles := migrationHistory{namespace: "identity_organization_directory_roles", owners: map[migrations.Version]ModuleID{}}
			err := appendEnterpriseMigration(ctx, &roles, "organization/postgres", organizationpg.DirectoryTeamRoleMigrationSource{Version: 1},
				migrationGuard{version: 1, schema: "organization", tables: []string{"directory_team_role_grants"}})
			if err != nil {
				return nil, err
			}
			catalog = append(catalog, roles)
		}
	}
	if selected.users || selected.mixed {
		members := migrationHistory{namespace: "identity_organization_directory_membership", owners: map[migrations.Version]ModuleID{}}
		err := appendEnterpriseMigration(ctx, &members, "organization/postgres", organizationpg.DirectoryMembershipMigrationSource{Version: 1},
			migrationGuard{version: 1, schema: "organization", tables: []string{"directory_membership_grants"}})
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, members)
	}
	if selected.mixed {
		successor := migrationHistory{namespace: "identity_organization_directory_successor", owners: map[migrations.Version]ModuleID{}}
		err := appendEnterpriseMigration(ctx, &successor, "organization/postgres", organizationpg.DirectoryMembershipSuccessorMigrationSource{Version: 1},
			migrationGuard{version: 1, schema: "organization", columns: []string{
				"command_effects.directory_org_before", "command_effects.directory_org_after", "command_effects.directory_credential_version",
			}})
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, successor)
	}
	if selected.mixed && selected.roles {
		roleSuccessor := migrationHistory{namespace: "identity_organization_directory_role_successor", owners: map[migrations.Version]ModuleID{}}
		err := appendEnterpriseMigration(ctx, &roleSuccessor, "organization/postgres", organizationpg.DirectoryTeamRoleSuccessorMigrationSource{Version: 1},
			migrationGuard{version: 1, schema: "organization", constraints: []string{"command_effects.organization_directory_successor_scope"}})
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, roleSuccessor)
	}
	return catalog, nil
}
