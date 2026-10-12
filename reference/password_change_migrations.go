package reference

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Native change prerequisites are independent suffixes. Replacement keeps the
// existing reset kernel's allocation, so selecting reset later extends the same
// physical history rather than creating the credential-effect table twice.
func passwordChangeMigrationCatalog(ctx context.Context, catalog []migrationHistory, schema string) ([]migrationHistory, error) {
	if schema == "" || len(catalog) == 0 {
		return nil, identity.InvalidInputError{Field: "reference_password_change_migrations"}
	}
	base := fixedMigrationSource(catalog[0].history)
	replacementPresent := false
	for _, prior := range catalog {
		replacementPresent = replacementPresent || prior.namespace == "identity_reset_kernel"
	}
	if !replacementPresent {
		full, err := (kernel.CredentialReplacementMigrationSource{Base: base, Version: 1500}).Load(ctx)
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, migrationHistory{namespace: "identity_reset_kernel", history: full[len(catalog[0].history):], owners: map[migrations.Version]ModuleID{1500: "identity/postgres"}, guards: []migrationGuard{{version: 1500, schema: "identity", tables: []string{"credential_replacements"}}}})
	}
	var err error
	catalog, err = counterPreparationMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	continuation, err := (sessionpg.CredentialContinuationMigrationSource{Schema: schema, Version: 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	effects, err := (sessionpg.PasswordChangeMigrationSource{Schema: schema, Version: 2}).Load(ctx)
	if err != nil {
		return nil, err
	}
	catalog = append(catalog, migrationHistory{namespace: "identity_password_change_session", history: append(continuation, effects...), owners: map[migrations.Version]ModuleID{1: "identity/session/postgres", 2: "identity/session/postgres"}, guards: []migrationGuard{
		{version: 1, schema: schema, constraints: []string{"sessions.session_credential_continuation_v1"}},
		{version: 2, schema: schema, tables: []string{"password_changes"}},
	}})
	return catalog, nil
}

// Counted feature preparation has one physical owner. Reuse its established
// standalone allocation for change/enrollment; a selected legacy TOTP shared
// prefix already supplies it and must not get the same DDL again.
func counterPreparationMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	for _, h := range catalog {
		for _, step := range h.history {
			if step.Name() == "identity_command_preparation_counters" {
				return catalog, nil
			}
		}
	}
	if len(catalog) == 0 {
		return nil, identity.InvalidInputError{Field: "reference_counter_preparation_migrations"}
	}
	full, err := (kernel.CounterPreparationMigrationSource{Base: fixedMigrationSource(catalog[0].history), Version: 1700}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return append(catalog, migrationHistory{namespace: "identity_password_change_kernel", history: full[len(catalog[0].history):], owners: map[migrations.Version]ModuleID{1700: "identity/postgres"}, guards: []migrationGuard{{version: 1700, schema: "identity", columns: []string{"commands.preparation_declaration"}, functions: []string{"guard_preparation_declaration"}}}}), nil
}
