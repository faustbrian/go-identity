package reference

import (
	"context"

	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Registration is selectable after an installed signin/reset deployment. Its
// independent suffix leaves every installed shared and native checksum intact.
// Actual source owners supply SQL; common physical histories are reused once.
func registrationKernelMigrationCatalog(ctx context.Context, catalog []migrationHistory, riskSchema string) ([]migrationHistory, error) {
	base := fixedMigrationSource(catalog[0].history)
	identifiers := kernel.IdentifierMutationMigrationSource{Base: base, Version: 1600}
	registration := kernel.PasswordRegistrationMigrationSource{Base: identifiers, Version: 1601}
	acceptance := kernel.PasswordSignupAcceptanceMigrationSource{Base: registration, Version: 1602}
	full, err := (kernel.EmailVerificationMigrationSource{Base: acceptance, Version: 1603}).Load(ctx)
	if err != nil {
		return nil, err
	}
	steps := full[len(catalog[0].history):]
	owned := migrationHistory{namespace: "identity_registration", history: steps, owners: make(map[migrations.Version]ModuleID), guards: []migrationGuard{
		{version: 1600, schema: "identity", tables: []string{"identifier_retirements"}},
		{version: 1601, schema: "identity", tables: []string{"registration_bindings"}},
		{version: 1602, schema: "identity", columns: []string{"registration_bindings.accepted_only"}},
		{version: 1603, schema: "identity", tables: []string{"email_verifications"}},
	}}
	for _, step := range steps {
		owned.owners[step.Version()] = "identity/postgres"
	}
	catalog = append(catalog, owned)
	counterSteps, err := (riskpg.VerificationCounterMigrationSource{Schema: riskSchema, Version: 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	// This forward extension changes existing CHECK constraints, introducing no
	// object identity. A collision guard on the existing tables/constraints would
	// reject every valid populated upgrade. Its native ledger/checksum and the
	// shared counter history retain custody; confirmation exercises the new arm.
	catalog = append(catalog, migrationHistory{namespace: "identity_registration_counters", history: counterSteps, owners: map[migrations.Version]ModuleID{1: "identity/risk/postgres"}})
	return catalog, nil
}

func passwordSignupMigrationCatalog(ctx context.Context, catalog []migrationHistory, riskSchema string) ([]migrationHistory, error) {
	catalog, err := registrationKernelMigrationCatalog(ctx, catalog, riskSchema)
	if err != nil {
		return nil, err
	}
	capabilities, err := migrations.NewFSSource(ownedMigrationFiles{capabilitypg.Migrations()}, ".")
	if err != nil {
		return nil, err
	}
	for _, source := range []struct {
		namespace string
		owner     ModuleID
		source    migrations.Source
		guard     migrationGuard
	}{
		{"identity_password", "identity/password/postgres", passwordpg.MigrationSource{}, migrationGuard{version: 1, schema: "identity_password"}},
		{"identity_mfa", "identity/mfa/postgres", mfapg.MigrationSource{Version: 1}, migrationGuard{version: 1, schema: "identity_mfa", tables: []string{"factor_authorities"}}},
		{"identity_capability", "capability/postgres/identity", capabilities, migrationGuard{version: 1, schema: "public", tables: []string{"capability_identity_one_use"}}},
	} {
		present := false
		for _, prior := range catalog {
			if prior.namespace == source.namespace {
				present = true
				break
			}
		}
		if present {
			continue
		}
		steps, err := source.source.Load(ctx)
		if err != nil {
			return nil, err
		}
		h := migrationHistory{namespace: source.namespace, history: steps, owners: make(map[migrations.Version]ModuleID), guards: []migrationGuard{source.guard}}
		for _, step := range steps {
			h.owners[step.Version()] = source.owner
		}
		catalog = append(catalog, h)
	}
	return catalog, nil
}
