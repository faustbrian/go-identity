package reference

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

// Roles use their own append-only history: enabling them never inserts versions
// into installed organization/team/invitation histories. Team binding schema
// follows the selected terminal team identity history, not an application store.
func (s StoreSet) organizationRoleMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if !s.state.features.organization.dynamicRoles {
		return catalog, nil
	}
	history := migrationHistory{namespace: "identity_organization_roles", owners: make(map[migrations.Version]ModuleID)}
	suffixes := []struct {
		source migrations.Source
		guard  migrationGuard
	}{
		{organizationpg.DynamicRoleMigrationSource{Version: 1}, migrationGuard{version: 1, schema: "organization", tables: []string{"custom_roles", "role_bindings", "organization_role_member"}}},
		{organizationpg.DynamicRoleDeleteOperationLookupMigrationSource{Version: 2}, migrationGuard{version: 2, schema: "organization", columns: []string{"command_effects.delete_role_id", "command_effects.delete_role_version"}, tables: []string{"organization_repeat_role_delete"}, constraints: []string{"command_effects.organization_role_delete_operation_scope"}}},
	}
	if s.state.features.organization.teamRoleBindings {
		suffixes = append(suffixes, struct {
			source migrations.Source
			guard  migrationGuard
		}{organizationpg.TeamRoleBindingMigrationSource{Version: 3}, migrationGuard{version: 3, schema: "organization", tables: []string{"team_role_bindings", "organization_team_role_effective"}}})
	}
	for _, suffix := range suffixes {
		steps, err := suffix.source.Load(ctx)
		if err != nil {
			return nil, err
		}
		history.history = append(history.history, steps...)
		history.owners[suffix.guard.version] = "organization/postgres"
		history.guards = append(history.guards, suffix.guard)
	}
	catalog = append(catalog, history)
	if s.state.features.organization.directRoleBindings {
		// Keep this independent of optional team version 3: selecting direct
		// bindings first must not prevent a later team-role upgrade.
		steps, err := (organizationpg.RoleBindingRevokeOperationLookupMigrationSource{Version: 1}).Load(ctx)
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, migrationHistory{namespace: "identity_organization_direct_bindings", history: steps, owners: map[migrations.Version]ModuleID{1: "organization/postgres"}, guards: []migrationGuard{{version: 1, schema: "organization", columns: []string{"command_effects.revoke_role_id", "command_effects.revoke_role_version", "command_effects.revoke_member_version", "command_effects.revoke_binding_version"}, tables: []string{"organization_repeat_role_revoke"}, constraints: []string{"command_effects.organization_role_binding_revoke_scope"}}}})
	}
	if s.state.features.organization.teamRoleOperations {
		steps, err := (organizationpg.TeamRoleBindingRevokeOperationLookupMigrationSource{Version: 1}).Load(ctx)
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, migrationHistory{namespace: "identity_organization_team_bindings", history: steps, owners: map[migrations.Version]ModuleID{1: "organization/postgres"}, guards: []migrationGuard{{version: 1, schema: "organization", columns: []string{"command_effects.revoke_team_role_id", "command_effects.revoke_team_role_version", "command_effects.revoke_team_id", "command_effects.revoke_team_version", "command_effects.revoke_team_binding_version"}, tables: []string{"organization_repeat_team_role_revoke"}, constraints: []string{"command_effects.organization_team_role_revoke_scope"}}}})
	}
	return catalog, nil
}
