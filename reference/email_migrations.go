package reference

import (
	"context"
	"maps"
	"slices"

	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Select only native forward histories, retaining their established physical
// namespaces and checksums. Email does not create another migration engine or
// require the signup workflow just to supply a common identifier table.
func emailMigrationCatalog(ctx context.Context, catalog []migrationHistory, riskSchema string, management, change bool) ([]migrationHistory, error) {
	invalid := identity.InvalidInputError{Field: "reference_email_migrations"}
	if ctx == nil || len(catalog) == 0 || change && !management {
		return nil, invalid
	}
	result := slices.Clone(catalog)
	if slices.IndexFunc(result, func(h migrationHistory) bool { return h.namespace == "identity_registration" }) < 0 {
		full, err := (kernel.IdentifierMutationMigrationSource{Base: fixedMigrationSource(result[0].history), Version: 1600}).Load(ctx)
		if err != nil {
			return nil, err
		}
		result = append(result, migrationHistory{namespace: "identity_registration", history: full[len(result[0].history):], owners: map[migrations.Version]ModuleID{1600: "identity/postgres"}, guards: []migrationGuard{{version: 1600, schema: "identity", tables: []string{"identifier_retirements"}}}})
	}
	if !management {
		return result, nil
	}
	var err error
	result, err = counterPreparationMigrationCatalog(ctx, result)
	if err != nil {
		return nil, err
	}
	capabilities, err := migrations.NewFSSource(ownedMigrationFiles{capabilitypg.Migrations()}, ".")
	if err != nil {
		return nil, err
	}
	for _, selected := range []struct {
		namespace string
		owner     ModuleID
		source    migrations.Source
		guard     *migrationGuard
	}{
		{"identity_password", "identity/password/postgres", passwordpg.EmailReauthenticationMigrationSource{}, nil},
		{"identity_mfa", "identity/mfa/postgres", mfapg.MigrationSource{Version: 1}, &migrationGuard{version: 1, schema: "identity_mfa", tables: []string{"factor_authorities"}}},
		{"identity_capability", "capability/postgres/identity", capabilities, &migrationGuard{version: 1, schema: "public", tables: []string{"capability_identity_one_use"}}},
		{"identity_registration_counters", "identity/risk/postgres", riskpg.VerificationCounterMigrationSource{Schema: riskSchema, Version: 1}, nil},
	} {
		steps, err := selected.source.Load(ctx)
		if err != nil {
			return nil, err
		}
		index := slices.IndexFunc(result, func(h migrationHistory) bool { return h.namespace == selected.namespace })
		if index < 0 {
			h := migrationHistory{namespace: selected.namespace, history: steps, owners: make(map[migrations.Version]ModuleID)}
			if selected.guard != nil {
				h.guards = []migrationGuard{*selected.guard}
			}
			for _, step := range steps {
				h.owners[step.Version()] = selected.owner
			}
			result = append(result, h)
			continue
		}
		prior := result[index]
		for n := 0; n < min(len(prior.history), len(steps)); n++ {
			if prior.history[n].Checksum() != steps[n].Checksum() {
				return nil, invalid
			}
		}
		if len(steps) <= len(prior.history) {
			continue
		}
		prior.owners = maps.Clone(prior.owners)
		prior.history = append(slices.Clone(prior.history), steps[len(prior.history):]...)
		for _, step := range steps {
			prior.owners[step.Version()] = selected.owner
		}
		result[index] = prior
	}
	if change && slices.IndexFunc(result, func(h migrationHistory) bool { return h.namespace == "identity_email_change_counters" }) < 0 {
		steps, err := (riskpg.EmailChangeCounterMigrationSource{Schema: riskSchema, Version: 1701}).Load(ctx)
		if err != nil {
			return nil, err
		}
		result = append(result, migrationHistory{namespace: "identity_email_change_counters", history: steps, owners: map[migrations.Version]ModuleID{1701: "identity/risk/postgres"}})
	}
	return result, nil
}

func emailRemovalMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if len(catalog) == 0 {
		return nil, identity.InvalidInputError{Field: "reference_email_removal_migrations"}
	}
	if slices.ContainsFunc(catalog, func(h migrationHistory) bool { return h.namespace == "identity_identifier_removal" }) {
		return catalog, nil
	}
	// This alters existing status admission tables. A table-presence guard would
	// incorrectly mark a populated pre-removal installation as already upgraded.
	base := catalog[0].history
	full, err := (kernel.IdentifierRemovalCascadeMigrationSource{Base: fixedMigrationSource(base), Version: 1702}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return append(slices.Clone(catalog), migrationHistory{namespace: "identity_identifier_removal", history: full[len(base):], owners: map[migrations.Version]ModuleID{1702: "identity/postgres"}}), nil
}
