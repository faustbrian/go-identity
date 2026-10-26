package reference

import (
	"context"
	"slices"

	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

// New selections append independent native histories; installed baseline, risk
// and session prefixes are unchanged. Invitation suffixes follow membership's
// repeat-removal index so enabling invitations later cannot insert old steps.
func (s StoreSet) organizationMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if s.state.features == nil || s.state.features.organization == nil {
		return catalog, nil
	}
	var err error
	catalog, err = counterPreparationMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(catalog, func(h migrationHistory) bool { return h.namespace == "identity_risk_lockouts" }) {
		schema := s.state.config.Schema
		base := riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: schema, Version: 1}, Version: 2}, Version: 3}, Version: 4}
		steps, err := (riskpg.LockoutMigrationSource{Base: base, Version: 5}).Load(ctx)
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, migrationHistory{namespace: "identity_risk_lockouts", history: steps[len(steps)-1:], owners: map[migrations.Version]ModuleID{5: "identity/risk/postgres"}, guards: []migrationGuard{{version: 5, schema: schema, tables: []string{"counter_lockouts"}}}})
	}
	steps, err := (kernel.RequestKeyExpiryMigrationSource{Base: s.MigrationSource(), Version: 2300}).Load(ctx)
	if err != nil {
		return nil, err
	}
	catalog = append(catalog, migrationHistory{namespace: "identity_organization_kernel", history: steps[len(steps)-1:], owners: map[migrations.Version]ModuleID{2300: "identity/postgres"}, guards: []migrationGuard{{version: 2300, schema: "identity", columns: []string{"identity_command_id_claims.request_key_expiry_fingerprint"}, functions: []string{"request_key_expiry_immutable"}, constraints: []string{"identity_command_id_claims.identity_request_key_expiry_shape"}}}})
	history := migrationHistory{namespace: "identity_organization", owners: make(map[migrations.Version]ModuleID)}
	appendNative := func(source migrations.Source, guard migrationGuard) error {
		steps, err := source.Load(ctx)
		if err != nil {
			return err
		}
		for _, step := range steps {
			history.owners[step.Version()] = "organization/postgres"
		}
		history.history = append(history.history, steps...)
		history.guards = append(history.guards, guard)
		return nil
	}
	if err := appendNative(organizationpg.MigrationSource{Version: 1}, migrationGuard{version: 1, schema: "organization", tables: []string{"organizations", "memberships", "command_effects", "tenant_locks"}}); err != nil {
		return nil, err
	}
	if err := appendNative(organizationpg.OperationLookupTransactionalMigrationSource{Version: 2}, migrationGuard{version: 2, schema: "organization", tables: []string{"organization_repeat_removal"}}); err != nil {
		return nil, err
	}
	if s.state.features.organization.invitations != nil {
		// Invitations own issuance and consumption even without signup, reset
		// or another capability workflow. Reuse their native physical history.
		if !slices.ContainsFunc(catalog, func(h migrationHistory) bool { return h.namespace == "identity_capability" }) {
			source, err := migrations.NewFSSource(ownedMigrationFiles{capabilitypg.Migrations()}, ".")
			if err != nil {
				return nil, err
			}
			steps, err := source.Load(ctx)
			if err != nil {
				return nil, err
			}
			capabilities := migrationHistory{namespace: "identity_capability", history: steps, owners: make(map[migrations.Version]ModuleID), guards: []migrationGuard{{version: 1, schema: "public", tables: []string{"capability_identity_one_use"}}}}
			for _, step := range steps {
				capabilities.owners[step.Version()] = "capability/postgres/identity"
			}
			catalog = append(catalog, capabilities)
		}
		if err := appendNative(organizationpg.InvitationMigrationSource{Version: 3}, migrationGuard{version: 3, schema: "organization", tables: []string{"invitations"}, columns: []string{"command_effects.invitation_id"}}); err != nil {
			return nil, err
		}
		if err := appendNative(organizationpg.InvitationCapabilityMigrationSource{Version: 4}, migrationGuard{version: 4, schema: "organization", columns: []string{"invitations.capability_envelope", "invitations.capability_replay_key_version"}}); err != nil {
			return nil, err
		}
		if err := appendNative(organizationpg.InvitationRecipientIndexTransactionalMigrationSource{Version: 5}, migrationGuard{version: 5, schema: "organization", tables: []string{"organization_invitation_recipient_page"}}); err != nil {
			return nil, err
		}
	}
	return append(catalog, history), nil
}
