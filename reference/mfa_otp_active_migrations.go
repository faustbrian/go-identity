package reference

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func (s StoreSet) otpActiveMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if s.state == nil || s.state.features == nil || s.state.features.mfaOTPEnrollment == nil || s.state.features.mfaOTPEnrollment.active == nil {
		return catalog, nil
	}
	for i, h := range catalog {
		if h.namespace != "identity_mfa_otp" {
			continue
		}
		steps, err := (mfapg.OTPFactorVerificationMigrationSource{Base: fixedMigrationSource(h.history), Version: 17}).Load(ctx)
		if err != nil {
			return nil, err
		}
		owners := make(map[migrations.Version]ModuleID, len(h.owners)+1)
		for v, owner := range h.owners {
			owners[v] = owner
		}
		owners[17] = "identity/mfa/postgres"
		catalog[i] = migrationHistory{namespace: h.namespace, history: steps, owners: owners, guards: append(append([]migrationGuard(nil), h.guards...), migrationGuard{version: 17, schema: "identity_mfa", tables: []string{"otp_factor_verifications"}})}
		if s.state.features.mfaOTPEnrollment.manage != nil {
			steps, err = (mfapg.OTPFactorManagementMigrationSource{Base: fixedMigrationSource(steps), Version: 18}).Load(ctx)
			if err != nil {
				return nil, err
			}
			owners[18] = "identity/mfa/postgres"
			catalog[i].history = steps
			catalog[i].guards = append(catalog[i].guards, migrationGuard{version: 18, schema: "identity_mfa", tables: []string{"otp_factor_update_effects"}, columns: []string{"otp_factors.label"}})
			if s.state.features.mfaOTPEnrollment.manage.RemovalConfigured() {
				steps, err = (mfapg.OTPFactorRemovalMigrationSource{Base: fixedMigrationSource(steps), Version: 19}).Load(ctx)
				if err != nil {
					return nil, err
				}
				owners[19] = "identity/mfa/postgres"
				catalog[i].history = steps
				catalog[i].guards = append(catalog[i].guards, migrationGuard{version: 19, schema: "identity_mfa", columns: []string{"otp_factor_update_effects.action", "otp_factor_update_effects.recovery_identity"}})
			}
			// Reuse the existing session disposition history when TOTP management
			// already selected it. OTP does not create another session-effect owner.
			for j, existing := range catalog {
				if existing.namespace == "identity_mfa_recovery_dispositions" {
					if existing.owners[2] == "" {
						extension, e := (sessionpg.MFAFactorUpdateSessionMigrationSource{Schema: s.state.features.migrations.passwordSigninSchema, Version: 2}).Load(ctx)
						if e != nil {
							return nil, e
						}
						catalog[j].history = append(append(existing.history[:0:0], existing.history...), extension...)
						catalog[j].owners = make(map[migrations.Version]ModuleID, len(existing.owners)+1)
						for v, owner := range existing.owners {
							catalog[j].owners[v] = owner
						}
						catalog[j].owners[2] = "identity/session/postgres"
					}
					return catalog, nil
				}
			}
			schema := s.state.features.migrations.passwordSigninSchema
			dispositions, e := (sessionpg.MFARecoverySessionMigrationSource{Schema: schema, Version: 1}).Load(ctx)
			if e != nil {
				return nil, e
			}
			extension, e := (sessionpg.MFAFactorUpdateSessionMigrationSource{Schema: schema, Version: 2}).Load(ctx)
			if e != nil {
				return nil, e
			}
			catalog = append(catalog, migrationHistory{namespace: "identity_mfa_recovery_dispositions", history: append(dispositions, extension...), owners: map[migrations.Version]ModuleID{1: "identity/session/postgres", 2: "identity/session/postgres"}, guards: []migrationGuard{{version: 1, schema: schema, tables: []string{"mfa_recovery_dispositions"}}}})
		}
		return catalog, nil
	}
	return nil, identity.InvalidInputError{Field: "reference_mfa_otp_active_history"}
}
