package reference

import (
	"context"

	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Native histories have one physical owner even when several features consume
// them. Reuse reset/signup factor/issuer and password/continuation prefixes;
// magic-link-only selection installs session constraint prerequisites without
// enabling those authentication workflows or copying their SQL.
func magicLinkMigrationCatalog(ctx context.Context, catalog []migrationHistory, schema string, mfaChallenge ...bool) ([]migrationHistory, error) {
	present := func(namespace string) bool {
		for _, h := range catalog {
			if h.namespace == namespace {
				return true
			}
		}
		return false
	}
	capabilities, err := migrations.NewFSSource(ownedMigrationFiles{capabilitypg.Migrations()}, ".")
	if err != nil {
		return nil, err
	}
	for _, item := range []struct {
		namespace string
		owner     ModuleID
		source    migrations.Source
		guards    []migrationGuard
	}{
		{"identity_mfa", "identity/mfa/postgres", mfapg.MigrationSource{Version: 1}, []migrationGuard{{version: 1, schema: "identity_mfa", tables: []string{"factor_authorities"}}}},
		{"identity_capability", "capability/postgres/identity", capabilities, []migrationGuard{{version: 1, schema: "public", tables: []string{"capability_identity_one_use"}}}},
	} {
		if present(item.namespace) {
			continue
		}
		steps, err := item.source.Load(ctx)
		if err != nil {
			return nil, err
		}
		h := migrationHistory{namespace: item.namespace, history: steps, owners: map[migrations.Version]ModuleID{}, guards: item.guards}
		for _, m := range steps {
			h.owners[m.Version()] = item.owner
		}
		catalog = append(catalog, h)
	}
	if len(mfaChallenge) != 0 && mfaChallenge[0] {
		// Extend the MFA owner's one physical history, including when registration
		// already contributed its factor-authority root. Preserve every prefix
		// byte; the challenge profile may not infer or backfill enrolled factors.
		for i := range catalog {
			if catalog[i].namespace != "identity_mfa" {
				continue
			}
			base := mfapg.MigrationSource{Version: 1}
			source := mfapg.TOTPFactorMigrationSource{Base: mfapg.ContinuationMigrationSource{Base: base, Version: 2}, Version: 3}
			steps, err := source.Load(ctx)
			if err != nil {
				return nil, err
			}
			if len(catalog[i].history) > len(steps) {
				return nil, identity.InvalidInputError{Field: "reference_mfa_history"}
			}
			for j, old := range catalog[i].history {
				if old != steps[j] {
					return nil, identity.InvalidInputError{Field: "reference_mfa_history"}
				}
			}
			catalog[i].history = steps
			owners := make(map[migrations.Version]ModuleID, len(steps))
			for version, owner := range catalog[i].owners {
				owners[version] = owner
			}
			owners[2], owners[3] = "identity/mfa/postgres", "identity/mfa/postgres"
			catalog[i].owners = owners
			catalog[i].guards = append(append([]migrationGuard(nil), catalog[i].guards...), migrationGuard{version: 2, schema: "identity_mfa", tables: []string{"continuations"}}, migrationGuard{version: 3, schema: "identity_mfa", tables: []string{"totp_factors"}})
		}
	}
	if schema == "" {
		return catalog, nil
	}
	for _, item := range []struct {
		namespace string
		source    migrations.Source
		guards    []migrationGuard
	}{
		{"identity_password_session", sessionpg.PasswordSigninMigrationSource{Schema: schema, Version: 1}, []migrationGuard{{version: 1, schema: schema, constraints: []string{"session_issuances.session_issuances_purpose_v3"}}}},
		{"identity_registration_session", sessionpg.PasswordSignupMigrationSource{Schema: schema, Version: 1}, []migrationGuard{{version: 1, schema: schema, constraints: []string{"session_issuances.session_issuances_purpose_v4"}}}},
		{"identity_password_change_session", sessionpg.CredentialContinuationMigrationSource{Schema: schema, Version: 1}, []migrationGuard{{version: 1, schema: schema, constraints: []string{"sessions.session_credential_continuation_v1"}}}},
	} {
		if present(item.namespace) {
			continue
		}
		steps, err := item.source.Load(ctx)
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, migrationHistory{namespace: item.namespace, history: steps, owners: map[migrations.Version]ModuleID{1: "identity/session/postgres"}, guards: item.guards})
	}
	profile, err := (sessionpg.MagicLinkMigrationSource{Schema: schema, Version: 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	issue, err := (sessionpg.MagicLinkSigninMigrationSource{Schema: schema, Version: 2}).Load(ctx)
	if err != nil {
		return nil, err
	}
	catalog = append(catalog, migrationHistory{namespace: "identity_magiclink_session", history: append(profile, issue...), owners: map[migrations.Version]ModuleID{1: "identity/session/postgres", 2: "identity/session/postgres"}, guards: []migrationGuard{{version: 1, schema: schema, constraints: []string{"sessions.session_record_binding_v5", "sessions.session_credential_continuation_v2"}}, {version: 2, schema: schema, constraints: []string{"session_issuances.session_issuances_purpose_v5"}}}})
	return catalog, nil
}
