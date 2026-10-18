package reference

import (
	"context"
	"slices"

	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// OTP signin and email verification reuse the common native MFA authority
// prefix, not link/password proof or
// capability histories. Signup or existing enrollment may already own a longer
// prefix in this permanent namespace. No factor is inferred or initialized.
func emailOTPFactorMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if slices.ContainsFunc(catalog, func(h migrationHistory) bool { return h.namespace == "identity_mfa" }) {
		return catalog, nil
	}
	steps, err := (mfapg.MigrationSource{Version: 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return append(slices.Clone(catalog), migrationHistory{namespace: "identity_mfa", history: steps, owners: map[migrations.Version]ModuleID{1: "identity/mfa/postgres"}, guards: []migrationGuard{{version: 1, schema: "identity_mfa", tables: []string{"factor_authorities"}}}}), nil
}
