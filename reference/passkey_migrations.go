package reference

import (
	"context"
	"maps"
	"slices"
	"strings"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	native "github.com/faustbrian/go-passkey/postgres"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

// Append public-owner histories after every selected predecessor. The explicit
// session CHECK lineage stays fixed for this deployment; a conflicting feature
// selection cannot silently change an installed passkey checksum or predicate.
func (s StoreSet) passkeyMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if s.state.features == nil || s.state.features.passkey == nil {
		return catalog, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_passkey_migrations"}
	if ctx == nil || len(catalog) == 0 {
		return nil, invalid
	}
	p := s.state.features.passkey
	if p.totp != nil {
		// The selected MFA-first deployment installs the native completion
		// prefix before passkey's permanently pinned issuance successor.
		present := slices.ContainsFunc(catalog, func(h migrationHistory) bool { return h.namespace == "identity_password_mfa_session" })
		if !present {
			var err error
			catalog, err = passwordTOTPMigrationCatalog(ctx, catalog, p.schema, s.state.config.Schema, true, s.state.features.verificationSessionLineage == VerificationBeforeMFA)
			if err != nil {
				return nil, err
			}
		}
	}
	previous := "session_issuances_purpose_check"
	for _, h := range catalog {
		for _, g := range h.guards {
			if g.schema != p.schema {
				continue
			}
			for _, name := range g.constraints {
				if strings.HasPrefix(name, "session_issuances.session_issuances_purpose_") {
					previous = strings.TrimPrefix(name, "session_issuances.")
				}
			}
		}
	}
	if previous != p.predecessor {
		return nil, invalid
	}
	var err error
	catalog, err = counterPreparationMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	appendOwned := func(namespace string, owner ModuleID, source migrations.Source, guards ...migrationGuard) error {
		steps, err := source.Load(ctx)
		if err != nil {
			return err
		}
		h := migrationHistory{namespace: namespace, history: steps, owners: make(map[migrations.Version]ModuleID), guards: guards}
		for _, step := range steps {
			h.owners[step.Version()] = owner
		}
		catalog = append(catalog, h)
		return nil
	}
	present := func(namespace string) bool {
		return slices.ContainsFunc(catalog, func(h migrationHistory) bool { return h.namespace == namespace })
	}
	if p.schema != s.state.features.migrations.sessionSchema {
		// The native passkey owner retains its browser flow in its selected
		// authenticated store. A separately named legacy preauth store cannot
		// supply those physical tables or prove they have been installed.
		base, err := (sessionpg.PreAuthMigrationSource{Schema: p.schema, Version: 1}).Load(ctx)
		if err != nil {
			return nil, err
		}
		issue, err := (sessionpg.PreAuthIssueMigrationSource{Schema: p.schema, Version: 2}).Load(ctx)
		if err != nil {
			return nil, err
		}
		if err := appendOwned("identity_passkey_preauth", "identity/session/postgres", fixedMigrationSource(append(base, issue...)), migrationGuard{version: 1, schema: p.schema, tables: []string{"preauth_transactions"}}, migrationGuard{version: 2, schema: p.schema, tables: []string{"preauth_issuances"}}); err != nil {
			return nil, err
		}
	}
	// Preserve the common password proof prefix in its existing physical ledger.
	// All later action suffixes retain separate namespaces and original bytes.
	if !p.standalone {
		prefix, err := (passwordpg.EmailReauthenticationMigrationSource{}).Load(ctx)
		if err != nil {
			return nil, err
		}
		index := slices.IndexFunc(catalog, func(h migrationHistory) bool { return h.namespace == "identity_password" })
		if index < 0 {
			return nil, invalid
		}
		h := catalog[index]
		for i := 0; i < min(len(h.history), len(prefix)); i++ {
			if h.history[i] != prefix[i] {
				return nil, invalid
			}
		}
		if len(h.history) < len(prefix) {
			h.owners = maps.Clone(h.owners)
			h.history = append(slices.Clone(h.history), prefix[len(h.history):]...)
			for _, step := range prefix {
				h.owners[step.Version()] = "identity/password/postgres"
			}
			catalog[index] = h
		}
	}
	if !present("identity_mfa") {
		if err := appendOwned("identity_mfa", "identity/mfa/postgres", mfapg.MigrationSource{Version: 1}, migrationGuard{version: 1, schema: "identity_mfa", tables: []string{"factor_authorities"}}); err != nil {
			return nil, err
		}
	}
	if !present("identity_risk_lockouts") {
		base := riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: s.state.config.Schema, Version: 1}, Version: 2}, Version: 3}, Version: 4}
		steps, err := (riskpg.LockoutMigrationSource{Base: base, Version: 5}).Load(ctx)
		if err != nil {
			return nil, err
		}
		if err := appendOwned("identity_risk_lockouts", "identity/risk/postgres", fixedMigrationSource(steps[len(steps)-1:]), migrationGuard{version: 5, schema: s.state.config.Schema, tables: []string{"counter_lockouts"}}); err != nil {
			return nil, err
		}
	}
	if !p.standalone {
		passwordHistory := func() []migrations.Migration {
			var out []migrations.Migration
			for _, h := range catalog {
				for _, step := range h.history {
					if h.owners[step.Version()] == "identity/password/postgres" {
						out = append(out, step)
					}
				}
			}
			return out
		}
		if !present("identity_username_actions") {
			steps, err := (passwordpg.ActionReauthenticationMigrationSource{Base: fixedMigrationSource(passwordHistory()), Version: 21}).Load(ctx)
			if err != nil {
				return nil, err
			}
			if err := appendOwned("identity_username_actions", "identity/password/postgres", fixedMigrationSource(steps[len(steps)-1:]), migrationGuard{version: 21, schema: "identity_password", constraints: []string{"reauthentication_records.reauthentication_consumption_complete"}, constraintValue: "identity.username.update"}); err != nil {
				return nil, err
			}
		}
		steps, err := (passwordpg.PasskeyReauthenticationMigrationSource{Base: fixedMigrationSource(passwordHistory()), Version: 40}).Load(ctx)
		if err != nil {
			return nil, err
		}
		if err := appendOwned("identity_passkey_password", "identity/password/postgres", fixedMigrationSource(steps[len(steps)-1:]), migrationGuard{version: 40, schema: "identity_password", constraints: []string{"reauthentication_records.reauthentication_consumption_complete"}, constraintValue: "identity.passkey.register-verify"}); err != nil {
			return nil, err
		}
		// Deletion retains the published label-proof suffix even when its runtime
		// owner is off. Otherwise an existing signed/consumed update row could lose
		// its allowance when the deletion suffix replaces the shared constraint.
		if p.management != nil || p.deletion != nil {
			steps, err := (passwordpg.PasskeyManagementReauthenticationMigrationSource{Base: fixedMigrationSource(passwordHistory()), Version: 41}).Load(ctx)
			if err != nil {
				return nil, err
			}
			if err := appendOwned("identity_passkey_management_password", "identity/password/postgres", fixedMigrationSource(steps[len(steps)-1:]), migrationGuard{version: 41, schema: "identity_password", constraints: []string{"reauthentication_records.reauthentication_consumption_complete"}, constraintValue: "identity.passkey.update"}); err != nil {
				return nil, err
			}
		}
		if p.deletion != nil {
			steps, err := (passwordpg.PasskeyDeletionReauthenticationMigrationSource{Base: fixedMigrationSource(passwordHistory()), Version: 42}).Load(ctx)
			if err != nil {
				return nil, err
			}
			if err := appendOwned("identity_passkey_deletion_password", "identity/password/postgres", fixedMigrationSource(steps[len(steps)-1:]), migrationGuard{version: 42, schema: "identity_password", constraints: []string{"reauthentication_records.reauthentication_consumption_complete"}, constraintValue: "identity.passkey.delete"}); err != nil {
				return nil, err
			}
		}
	}
	protocol, err := (webauthnpg.MigrationSource{}).Load(ctx)
	if err != nil {
		return nil, err
	}
	if err := appendOwned("webauthn", "webauthn/postgres", fixedMigrationSource(protocol),
		migrationGuard{version: 1, schema: "webauthn"},
		migrationGuard{version: 2, schema: "webauthn", constraints: []string{"effects.effects_subject_namespace"}, constraintValue: "webauthn.begin-get-discoverable"},
		migrationGuard{version: 3, schema: "webauthn", constraints: []string{"effects.effects_subject_namespace"}, constraintValue: "identity.passkey.signin-options"},
		migrationGuard{version: 5, schema: "webauthn", columns: []string{"ceremonies.authorization_expires_at", "ceremonies.authorization_ceremony_id", "effects.enrollment_stage", "effects.enrollment_source"}, constraints: []string{"ceremonies.ceremonies_enrollment_authority", "effects.effects_enrollment_profile"}},
		migrationGuard{version: 6, schema: "webauthn", columns: []string{"effects.removal_before_credential", "effects.removal_after_credential"}, constraints: []string{"effects.effects_removal_assertion_profile"}},
	); err != nil {
		return nil, err
	}
	mapping, err := (native.MigrationSource{}).Load(ctx)
	if err != nil {
		return nil, err
	}
	signin, err := (native.SigninMigrationSource{Version: 2}).Load(ctx)
	if err != nil {
		return nil, err
	}
	metadata, err := (native.MetadataVersionMigrationSource{Version: 3}).Load(ctx)
	if err != nil {
		return nil, err
	}
	// Mapping1 and signin2 retain their installed identities. Updated native
	// inventory always reads metadata_version, even when mutation is disabled.
	history := append(append(mapping, signin...), metadata...)
	if err := appendOwned("identity_passkey", "passkey/postgres", fixedMigrationSource(history), migrationGuard{version: 1, schema: "identity_passkey"}, migrationGuard{version: 2, schema: "identity_passkey", tables: []string{"signin_contexts"}}, migrationGuard{version: 3, schema: "identity_passkey", columns: []string{"credentials.metadata_version"}}); err != nil {
		return nil, err
	}
	if err := appendOwned("identity_passkey_session", "identity/session/postgres", sessionpg.PasskeySigninMigrationSource{Schema: p.schema, Version: 1, PreviousConstraint: p.predecessor}, migrationGuard{version: 1, schema: p.schema, constraints: []string{"session_issuances.session_issuances_purpose_passkey_v1"}}); err != nil {
		return nil, err
	}
	catalog, err = s.passkeySignupMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	return s.passkeyTOTPMigrationCatalog(ctx, catalog)
}
