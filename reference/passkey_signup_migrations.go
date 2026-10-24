package reference

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	native "github.com/faustbrian/go-passkey/postgres"
)

// Signup appends actual owner histories after the retained enrollment/signin
// profile. Existing namespaces and migration bytes are never rewritten. The
// kernel's shared registration evidence is schema, not password-flow selection.
func (s StoreSet) passkeySignupMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	p := s.state.features.passkey
	if p.signup == nil {
		return catalog, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_passkey_signup_migrations"}
	registration := -1
	for i, h := range catalog {
		if h.namespace == "identity_registration" {
			registration = i
			break
		}
	}
	if registration < 0 {
		var err error
		catalog, err = passwordSignupMigrationCatalog(ctx, catalog, s.state.config.Schema)
		if err != nil {
			return nil, err
		}
		for i, h := range catalog {
			if h.namespace == "identity_registration" {
				registration = i
				break
			}
		}
	}
	if registration < 0 {
		return nil, invalid
	}
	base := append(append([]migrations.Migration(nil), catalog[0].history...), catalog[registration].history...)
	appendSuffix := func(namespace string, owner ModuleID, source migrations.Source, guard migrationGuard) error {
		history, err := source.Load(ctx)
		if err != nil {
			return err
		}
		if len(history) == 0 {
			return invalid
		}
		last := history[len(history)-1]
		catalog = append(catalog, migrationHistory{namespace: namespace, history: []migrations.Migration{last}, owners: map[migrations.Version]ModuleID{last.Version(): owner}, guards: []migrationGuard{guard}})
		return nil
	}
	if err := appendSuffix("identity_passkey_signup_kernel", "identity/postgres", kernel.PasskeyRegistrationMigrationSource{Base: fixedMigrationSource(base), Version: 1850}, migrationGuard{version: 1850, schema: "identity", constraints: []string{"registration_bindings.identity_registration_purpose_v4", "registration_bindings.identity_registration_disposition_v4"}}); err != nil {
		return nil, err
	}
	if err := appendSuffix("identity_passkey_signup_factors", "identity/mfa/postgres", mfapg.PasskeySignupMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 30}, migrationGuard{version: 30, schema: "identity_mfa", constraints: []string{"factor_authorities.factor_authorities_initialized_purpose_v4"}}); err != nil {
		return nil, err
	}
	if err := appendSuffix("identity_passkey_signup_counters", "identity/risk/postgres", riskpg.PasskeySignupCounterMigrationSource{Schema: s.state.config.Schema, Version: 6}, migrationGuard{version: 6, schema: s.state.config.Schema, constraints: []string{"counter_windows.counter_windows_dimension_check"}, constraintValue: "identity.passkey.register-options"}); err != nil {
		return nil, err
	}
	for i, h := range catalog {
		switch h.namespace {
		case "identity_passkey":
			steps, err := (native.SignupMigrationSource{Version: 4}).Load(ctx)
			if err != nil {
				return nil, err
			}
			h.history = append(h.history, steps...)
			h.owners[4] = "passkey/postgres"
			h.guards = append(h.guards, migrationGuard{version: 4, schema: "identity_passkey", tables: []string{"signup_contexts"}})
			catalog[i] = h
		case "identity_passkey_session":
			steps, err := (sessionpg.PasskeySignupMigrationSource{Schema: p.schema, Version: 2, PreviousConstraint: "session_issuances_purpose_passkey_v1"}).Load(ctx)
			if err != nil {
				return nil, err
			}
			h.history = append(h.history, steps...)
			h.owners[2] = "identity/session/postgres"
			h.guards = append(h.guards, migrationGuard{version: 2, schema: p.schema, constraints: []string{"session_issuances.session_issuances_purpose_passkey_signup_v1"}})
			catalog[i] = h
		}
	}
	return catalog, nil
}
