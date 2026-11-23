package reference

import (
	"context"
	"slices"

	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	oauthpg "github.com/faustbrian/go-oauth-server/postgres"
)

func (s StoreSet) oauthDeviceMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	n := s.state.features
	if n == nil || n.oauthDevice == nil {
		return catalog, nil
	}
	var err error
	catalog, err = counterPreparationMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(catalog, func(h migrationHistory) bool { return h.namespace == "identity_risk_lockouts" }) {
		schema := s.state.config.Schema
		base := riskpg.MigrationSource{Schema: schema, Version: 1}
		issued := riskpg.IssuanceIDMigrationSource{Base: base, Version: 2}
		reserved := riskpg.ReservationMigrationSource{Base: issued, Version: 3}
		counted := riskpg.CounterMigrationSource{Base: reserved, Version: 4}
		steps, err := (riskpg.LockoutMigrationSource{Base: counted, Version: 5}).Load(ctx)
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, migrationHistory{namespace: "identity_risk_lockouts", history: steps[len(steps)-1:],
			owners: map[migrations.Version]ModuleID{5: "identity/risk/postgres"},
			guards: []migrationGuard{{version: 5, schema: schema, tables: []string{"counter_lockouts"}}}})
	}
	// The device lineage uses the native human/consent history, not the
	// independently selected workload lineage at identity_oauth.
	schema := n.oauthDevice.schema
	base := oauthpg.MigrationSource{Schema: schema, Version: 1}
	consent := oauthpg.ConsentMigrationSource{Base: base, Schema: schema, Version: 2}
	steps, err := (oauthpg.DeviceMigrationSource{Base: consent, Schema: schema, Version: 3}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return append(catalog, migrationHistory{
		namespace: "identity_oauth_device", history: steps,
		owners: map[migrations.Version]ModuleID{1: "oauth-server/postgres", 2: "oauth-server/postgres", 3: "oauth-server/postgres"},
		guards: []migrationGuard{
			{version: 1, schema: schema},
			{version: 1, schema: schema, tables: []string{"grants", "artifacts", "consents", "effects"}},
			{version: 2, schema: schema,
				columns:     []string{"consents.state", "consents.generation", "consents.client_fingerprint", "grants.consent_id", "grants.consent_generation", "effects.consent_id"},
				constraints: []string{"consents.consent_owned_reference", "grants.grant_owned_consent", "effects.effect_exact_owner"}},
			{version: 3, schema: schema, tables: []string{"devices", "device_effects", "device_expiry_order"},
				columns:     []string{"artifacts.device_root", "artifacts.device_root_grant"},
				constraints: []string{"devices.devices_device_lookup", "devices.devices_user_lookup", "artifacts.artifacts_device_parent", "artifacts.artifacts_device_root_kind", "artifacts.artifacts_device_origin"}},
		},
	}), nil
}
