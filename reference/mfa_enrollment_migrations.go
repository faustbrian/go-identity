package reference

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Extend the one physical MFA history, whether factor authority was selected
// by signup, reset or login first. Never duplicate its tables or rewrite a
// populated prefix. Enrollment adds no login/session issuance migrations.
func mfaEnrollmentMigrationCatalog(ctx context.Context, catalog []migrationHistory, riskSchema string) ([]migrationHistory, error) {
	if ctx == nil || len(catalog) == 0 {
		return nil, identity.InvalidInputError{Field: "reference_mfa_enrollment_migrations"}
	}
	var err error
	catalog, err = counterPreparationMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	lockoutsPresent := false
	for _, h := range catalog {
		lockoutsPresent = lockoutsPresent || h.namespace == "identity_risk_lockouts"
	}
	if !lockoutsPresent {
		riskBase := riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: riskSchema, Version: 1}, Version: 2}, Version: 3}, Version: 4}
		full, err := (riskpg.LockoutMigrationSource{Base: riskBase, Version: 5}).Load(ctx)
		if err != nil {
			return nil, err
		}
		step := full[len(full)-1]
		catalog = append(catalog, migrationHistory{namespace: "identity_risk_lockouts", history: []migrations.Migration{step}, owners: map[migrations.Version]ModuleID{5: "identity/risk/postgres"}, guards: []migrationGuard{{version: 5, schema: riskSchema, tables: []string{"counter_lockouts"}}}})
	}
	base := mfapg.MigrationSource{Version: 1}
	var source migrations.Source = mfapg.ContinuationMigrationSource{Base: base, Version: 2}
	source = mfapg.TOTPFactorMigrationSource{Base: source, Version: 3}
	source = mfapg.RecoveryMigrationSource{Base: source, Version: 4}
	source = mfapg.URIRevealMigrationSource{Base: source, Version: 5}
	source = mfapg.TOTPActivationMigrationSource{Base: source, Version: 6}
	steps, err := source.Load(ctx)
	if err != nil {
		return nil, err
	}
	index := -1
	for i, h := range catalog {
		if h.namespace == "identity_mfa" {
			if index != -1 {
				return nil, identity.InvalidInputError{Field: "reference_mfa_history"}
			}
			index = i
		}
	}
	if index == -1 {
		catalog = append(catalog, migrationHistory{namespace: "identity_mfa", owners: map[migrations.Version]ModuleID{}})
		index = len(catalog) - 1
	}
	h := catalog[index]
	if len(h.history) > len(steps) {
		return nil, identity.InvalidInputError{Field: "reference_mfa_history"}
	}
	for i, old := range h.history {
		if old != steps[i] {
			return nil, identity.InvalidInputError{Field: "reference_mfa_history"}
		}
	}
	prior := len(h.history)
	owners := make(map[migrations.Version]ModuleID, len(steps))
	for version, owner := range h.owners {
		owners[version] = owner
	}
	for _, step := range steps {
		owners[step.Version()] = "identity/mfa/postgres"
	}
	guards := append([]migrationGuard(nil), h.guards...)
	for _, guard := range []migrationGuard{
		{version: 1, schema: "identity_mfa", tables: []string{"factor_authorities"}},
		{version: 2, schema: "identity_mfa", tables: []string{"continuations"}},
		{version: 3, schema: "identity_mfa", tables: []string{"totp_factors"}},
		{version: 4, schema: "identity_mfa", tables: []string{"recovery_sets", "recovery_codes"}},
		{version: 5, schema: "identity_mfa", columns: []string{"totp_factors.reveal_command_id"}},
		{version: 6, schema: "identity_mfa", columns: []string{"totp_factors.activation_command_id"}},
	} {
		if int(guard.version) > prior {
			guards = append(guards, guard)
		}
	}
	catalog[index] = migrationHistory{namespace: h.namespace, history: steps, owners: owners, guards: guards}
	return catalog, nil
}
