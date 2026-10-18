package reference

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Username is a final native forward suffix: selected email/MFA/verification
// histories install first and retain their exact bytes. These storage histories
// do not select any additional authentication workflow or transport.
func (s StoreSet) usernameMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if s.state.features == nil || s.state.features.username == nil {
		return catalog, nil
	}
	if len(catalog) == 0 {
		return nil, identity.InvalidInputError{Field: "reference_username_migrations"}
	}
	u := s.state.features.username
	if u.available != nil || u.rename != nil {
		var err error
		catalog, err = identifierMutationMigrationCatalog(ctx, catalog)
		if err != nil {
			return nil, err
		}
	}
	present := func(namespace string) bool {
		for _, h := range catalog {
			if h.namespace == namespace {
				return true
			}
		}
		return false
	}
	if u.signup != nil && !present("identity_magiclink_registration") {
		return nil, identity.InvalidInputError{Field: "reference_username_registration_prefix"}
	}
	var kernelHistory, factors, passwordHistory []migrations.Migration
	for _, h := range catalog {
		for _, m := range h.history {
			switch h.owners[m.Version()] {
			case "identity/postgres":
				kernelHistory = append(kernelHistory, m)
			case "identity/mfa/postgres":
				factors = append(factors, m)
			case "identity/password/postgres":
				passwordHistory = append(passwordHistory, m)
			}
		}
	}
	appendLast := func(namespace string, owner ModuleID, history []migrations.Migration, guard migrationGuard) {
		step := history[len(history)-1]
		catalog = append(catalog, migrationHistory{namespace: namespace, history: []migrations.Migration{step}, owners: map[migrations.Version]ModuleID{step.Version(): owner}, guards: []migrationGuard{guard}})
	}
	if u.available != nil && !(s.state.durable && u.availabilitySchema == s.state.config.Schema) {
		steps, err := (riskpg.DurableCounterMigrationSource{Schema: u.availabilitySchema, Version: 1}).Load(ctx)
		if err != nil {
			return nil, err
		}
		namespace := "identity_username_availability_counters"
		if u.availabilitySchema == s.state.config.Schema {
			// Share the established physical owner so enabling the durable graph
			// later does not adopt or recreate availability's installed tables.
			namespace = "identity_durable_admission"
		}
		appendLast(namespace, "identity/risk/postgres", steps, migrationGuard{version: 1, schema: u.availabilitySchema, tables: []string{"durable_counter_scopes", "durable_counter_keys", "durable_counter_windows", "durable_counter_aliases", "durable_counter_attempts"}})
	}
	normalized, err := (kernel.IdentifierNormalizationMigrationSource{Base: fixedMigrationSource(kernelHistory), Version: 1800}).Load(ctx)
	if err != nil {
		return nil, err
	}
	appendLast("identity_username_kernel", "identity/postgres", normalized, migrationGuard{version: 1800, schema: "identity", columns: []string{"identifiers.normalization_profile", "identifiers.normalization_version"}})
	if u.signup != nil {
		registration, err := (kernel.UsernameRegistrationMigrationSource{Base: fixedMigrationSource(normalized), Version: 1801}).Load(ctx)
		if err != nil {
			return nil, err
		}
		appendLast("identity_username_registration", "identity/postgres", registration, migrationGuard{version: 1801, schema: "identity", constraints: []string{"registration_bindings.identity_registration_purpose_v3", "email_verifications.identity_email_registration_purpose_v2"}})
		forward, err := (mfapg.UsernameSignupMigrationSource{Base: fixedMigrationSource(factors), Version: 20}).Load(ctx)
		if err != nil {
			return nil, err
		}
		appendLast("identity_username_factors", "identity/mfa/postgres", forward, migrationGuard{version: 20, schema: "identity_mfa", constraints: []string{"factor_authorities.factor_authorities_initialized_purpose_v3"}})
	}
	if u.signin != nil {
		forward, err := (passwordpg.UsernameSigninMigrationSource{Base: fixedMigrationSource(passwordHistory), Version: 20}).Load(ctx)
		if err != nil {
			return nil, err
		}
		appendLast("identity_username_password", "identity/password/postgres", forward, migrationGuard{version: 20, schema: "identity_password", constraints: []string{"signin_records.signin_records_purpose_v2"}})
		passwordHistory = forward
		predecessor := sessionpg.UsernameSigninAfterPassword
		switch {
		case present("identity_verification_mfa_session"):
			predecessor = sessionpg.UsernameSigninAfterVerificationMFA
		case present("identity_verification_signin_session"):
			predecessor = sessionpg.UsernameSigninAfterVerification
		case present("identity_magiclink_mfa_session"):
			predecessor = sessionpg.UsernameSigninAfterMFA
		case present("identity_magiclink_session"):
			predecessor = sessionpg.UsernameSigninAfterMagicLink
		case present("identity_registration_session"):
			predecessor = sessionpg.UsernameSigninAfterSignup
		}
		schema := s.state.features.migrations.passwordSigninSchema
		steps, err := (sessionpg.UsernameSigninMigrationSource{Schema: schema, Version: 1, Predecessor: predecessor, MFASignin: predecessor == sessionpg.UsernameSigninAfterVerification && present("identity_magiclink_mfa_session")}).Load(ctx)
		if err != nil {
			return nil, err
		}
		appendLast("identity_username_session", "identity/session/postgres", steps, migrationGuard{version: 1, schema: schema, constraints: []string{"session_issuances.session_issuances_purpose_username_v1"}})
	}
	if u.rename != nil || s.state.features.phone != nil {
		catalog, err = counterPreparationMigrationCatalog(ctx, catalog)
		if err != nil {
			return nil, err
		}
		if !present("identity_risk_lockouts") {
			// Reuse the same native allocation as MFA enrollment, without
			// selecting enrollment or constructing a second lockout authority.
			schema := s.state.config.Schema
			base := riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: schema, Version: 1}, Version: 2}, Version: 3}, Version: 4}
			steps, err := (riskpg.LockoutMigrationSource{Base: base, Version: 5}).Load(ctx)
			if err != nil {
				return nil, err
			}
			appendLast("identity_risk_lockouts", "identity/risk/postgres", steps, migrationGuard{version: 5, schema: schema, tables: []string{"counter_lockouts"}})
		}
		steps, err := (passwordpg.ActionReauthenticationMigrationSource{Base: fixedMigrationSource(passwordHistory), Version: 21}).Load(ctx)
		if err != nil {
			return nil, err
		}
		appendLast("identity_username_actions", "identity/password/postgres", steps, migrationGuard{version: 21, schema: "identity_password", constraints: []string{"reauthentication_records.reauthentication_consumption_complete"}, constraintValue: "identity.username.update"})
		passwordHistory = steps
	}
	if u.totp != nil {
		steps, err := (passwordpg.UsernameMFAMigrationSource{Base: fixedMigrationSource(passwordHistory), Version: 22}).Load(ctx)
		if err != nil {
			return nil, err
		}
		appendLast("identity_username_mfa_primary", "identity/password/postgres", steps, migrationGuard{version: 22, schema: "identity_password", constraints: []string{"mfa_primary_records.mfa_primary_records_purpose_v2"}})
		continuations, err := (mfapg.UsernameContinuationMigrationSource{Version: 1, VerificationSignin: present("identity_verification_mfa")}).Load(ctx)
		if err != nil {
			return nil, err
		}
		appendLast("identity_username_mfa_continuation", "identity/mfa/postgres", continuations, migrationGuard{version: 1, schema: "identity_mfa", constraints: []string{"continuations.continuations_origin_purpose_username_v1"}})
	}
	return catalog, nil
}
