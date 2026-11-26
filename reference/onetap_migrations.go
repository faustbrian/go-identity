package reference

import (
	"context"

	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

const oneTapSessionIssuanceConstraint = "session_issuances.session_issuances_purpose_onetap_v1"

func (s StoreSet) oneTapMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if s.state.features == nil || s.state.features.oneTap == nil {
		return catalog, nil
	}
	n := s.state.features.oneTap
	catalog, err := counterPreparationMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	base := fixedMigrationSource(catalog[0].history)
	var preparation migrations.Source = kernel.OneTapStartPreparationErasureMigrationSource{Base: base, Version: 4800}
	if n.complete != nil {
		preparation = kernel.OneTapCallbackPreparationErasureMigrationSource{Base: preparation, Version: 4801}
	}
	full, err := preparation.Load(ctx)
	if err != nil {
		return nil, err
	}
	steps := full[len(catalog[0].history):]
	preparationOwners := make(map[migrations.Version]ModuleID, len(steps))
	for _, step := range steps {
		preparationOwners[step.Version()] = "identity/postgres"
	}
	catalog = append(catalog, migrationHistory{namespace: "identity_onetap_kernel", history: steps, owners: preparationOwners,
		guards: []migrationGuard{{version: 4800, schema: "identity", functions: []string{"guard_command_preparation"}}}})
	preauth, err := (sessionpg.OneTapStartPreAuthMigrationSource{Schema: n.session.Schema, Version: 1, ValidationVersion: 2}).Load(ctx)
	if err != nil {
		return nil, err
	}
	catalog = append(catalog, migrationHistory{namespace: "identity_onetap_preauth", history: preauth,
		owners: map[migrations.Version]ModuleID{1: "identity/session/postgres", 2: "identity/session/postgres"},
		guards: []migrationGuard{{version: 2, schema: n.session.Schema, constraints: []string{"preauth_issuances.preauth_issuances_purpose_check"}}}})
	rp, err := (oauthpg.MigrationSource{Schema: n.schema, Version: 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	grants, err := (oauthpg.OneTapCallbackGrantMigrationSource{Schema: n.schema, Version: 2}).Load(ctx)
	if err != nil {
		return nil, err
	}
	catalog = append(catalog, migrationHistory{namespace: "identity_onetap_oauth", history: append(rp, grants...),
		owners: map[migrations.Version]ModuleID{1: "identity/oauth/postgres", 2: "identity/oauth/postgres"},
		guards: []migrationGuard{{version: 1, schema: n.schema}, {version: 2, schema: n.schema, tables: []string{"onetap_callback_grants"}}}})
	if n.complete == nil {
		return catalog, nil
	}
	issuer, err := (sessionpg.OneTapCallbackSessionMigrationSource{Schema: n.session.Schema, Version: 1, ValidationVersion: 2,
		PreviousConstraint: sessionIssuancePredecessor(catalog, n.session.Schema)}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return append(catalog, migrationHistory{namespace: "identity_onetap_session", history: issuer,
		owners: map[migrations.Version]ModuleID{1: "identity/session/postgres", 2: "identity/session/postgres"},
		guards: []migrationGuard{{version: 2, schema: n.session.Schema, constraints: []string{oneTapSessionIssuanceConstraint}}}}), nil
}
