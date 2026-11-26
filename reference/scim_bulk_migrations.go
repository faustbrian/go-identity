package reference

import (
	"context"
	"slices"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	scimpg "github.com/faustbrian/go-scim/postgres"
)

const (
	scimProjectionHistory = "identity_scim_directory_groups"
	scimBulkHistory       = "identity_scim_bulk"
	scimManagedHistory    = "identity_scim_managed_connections"
	scimManagedVersion    = migrations.Version(11)
	scimBulkAliasHistory  = "identity_scim_bulk_requests"
	scimBulkAliasVersion  = migrations.Version(2454)
	scimBulkAliasGuard    = "request_key_aliases.request_key_aliases_scim_bulk_method"
	scimSAMLPredecessor   = "request_key_aliases.request_key_aliases_saml_start_method"
)

func (s StoreSet) managedSCIMReadMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if s.state.features == nil || s.state.features.httpManagedSCIMRead == nil && s.state.features.httpManagedSCIMCreate == nil {
		return catalog, nil
	}
	if s.state.features.httpManagedSCIMCreate != nil {
		// Native Create snapshots the organization's credential epoch even
		// when neither Bulk nor another credential owner is selected.
		var err error
		catalog, err = organizationCredentialAuthorityMigrationCatalog(ctx, catalog)
		if err != nil {
			return nil, err
		}
	}
	catalog, err := ensureSCIMProjectionHistory(ctx, catalog)
	if err != nil {
		return nil, err
	}
	projection := catalog[slices.IndexFunc(catalog, func(h migrationHistory) bool { return h.namespace == scimProjectionHistory })].history
	full, err := (scimpg.ManagedConnectionsMigrationSource{Base: fixedMigrationSource(projection), Version: scimManagedVersion}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return append(catalog, migrationHistory{
		namespace: scimManagedHistory,
		history:   full[len(projection):],
		owners:    map[migrations.Version]ModuleID{scimManagedVersion: "scim/postgres"},
		guards:    []migrationGuard{{version: scimManagedVersion, schema: "scim", tables: []string{"managed_connections"}}},
	}), nil
}

// Bulk and directory synchronization consume the same installed native
// connection/projection history. Neither owns a second copy of its prefix.
func ensureSCIMProjectionHistory(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if slices.ContainsFunc(catalog, func(h migrationHistory) bool { return h.namespace == scimProjectionHistory }) {
		return catalog, nil
	}
	history := migrationHistory{namespace: scimProjectionHistory, owners: map[migrations.Version]ModuleID{}}
	base := scimpg.MigrationSource{Version: 1}
	users := scimpg.UsersMigrationSource{Base: base, Version: 2}
	groups := scimpg.GroupsMigrationSource{Base: users, Version: 3}
	if err := appendEnterpriseMigration(ctx, &history, "scim/postgres", groups,
		migrationGuard{version: 1, schema: "scim", tables: []string{"connections", "users"}}); err != nil {
		return nil, err
	}
	history.guards = append(history.guards,
		migrationGuard{version: 2, schema: "scim", columns: []string{"users.generation", "users.deleted_at"}},
		migrationGuard{version: 3, schema: "scim", tables: []string{"groups"}})
	return append(catalog, history), nil
}

func (s StoreSet) scimBulkMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if s.state.features == nil || s.state.features.scimBulk == nil {
		return catalog, nil
	}
	if len(catalog) == 0 || catalog[0].namespace != "" {
		return nil, identity.InvalidInputError{Field: "reference_catalog"}
	}
	catalog, err := organizationCredentialAuthorityMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	canonicalIndex := slices.IndexFunc(catalog, func(h migrationHistory) bool { return h.namespace == canonicalRequestHistory })
	if canonicalIndex < 0 {
		requests, err := canonicalRequestMigrationHistory(ctx, catalog[0].history)
		if err != nil {
			return nil, err
		}
		canonicalIndex = len(catalog)
		catalog = append(catalog, requests)
	}
	catalog, err = ensureSCIMProjectionHistory(ctx, catalog)
	if err != nil {
		return nil, err
	}
	projectionIndex := slices.IndexFunc(catalog, func(h migrationHistory) bool { return h.namespace == scimProjectionHistory })
	canonical := append(slices.Clone(catalog[0].history), catalog[canonicalIndex].history...)
	aliases, err := (kernel.CanonicalSCIMBulkRequestMigrationSource{
		Base: fixedMigrationSource(canonical), Version: scimBulkAliasVersion,
	}).Load(ctx)
	if err != nil {
		return nil, err
	}
	alias := migrationHistory{namespace: scimBulkAliasHistory, history: aliases[len(canonical):],
		owners: map[migrations.Version]ModuleID{scimBulkAliasVersion: "identity/postgres", scimBulkAliasVersion + 1: "identity/postgres"},
		guards: []migrationGuard{{version: scimBulkAliasVersion, schema: "identity", constraints: []string{scimBulkAliasGuard}}},
	}

	projections := catalog[projectionIndex].history
	admission := scimpg.BulkAdmissionMigrationSource{Base: fixedMigrationSource(projections), Version: 4}
	children := scimpg.BulkChildExecutionMigrationSource{Base: admission, Version: 5}
	mutations := scimpg.BulkGroupMutationMigrationSource{Base: children, Version: 6}
	typed := scimpg.BulkTypedValidationMigrationSource{Base: mutations, Version: 7, ValidationVersion: 8}
	full, err := (scimpg.BulkSnapshotValidationMigrationSource{Base: typed, Version: 9, ValidationVersion: 10}).Load(ctx)
	if err != nil {
		return nil, err
	}
	bulk := migrationHistory{namespace: scimBulkHistory, history: full[len(projections):],
		owners: make(map[migrations.Version]ModuleID),
		guards: []migrationGuard{
			{version: 4, schema: "scim", tables: []string{"bulk_requests", "bulk_children"}},
			{version: 5, schema: "scim", columns: []string{"bulk_children.result_code", "bulk_children.result_resource_id", "bulk_children.result_version"}},
			{version: 6, schema: "scim", columns: []string{"bulk_children.group_mutation_input"}},
			{version: 7, schema: "scim", columns: []string{"bulk_children.result_denial_code"}},
			{version: 9, schema: "scim", constraints: []string{"bulk_children.bulk_typed_validation_result_shape"}, constraintValue: "18"},
		},
	}
	for _, step := range bulk.history {
		bulk.owners[step.Version()] = "scim/postgres"
	}
	// Record only the native suffixes. Turning Bulk off must not make the
	// still-selected projection or canonical request history look shortened.
	return append(catalog, alias, bulk), nil
}
