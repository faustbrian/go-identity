package reference

import (
	"context"
	"strings"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func (s StoreSet) passkeyTOTPMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	p := s.state.features.passkey
	if p.totp == nil {
		return catalog, nil
	}
	var base []migrations.Migration
	previous := ""
	verification, username, phone := false, false, false
	for _, h := range catalog {
		if h.namespace == "identity_mfa" {
			base = h.history
		}
		verification = verification || h.namespace == "identity_verification_mfa"
		username = username || h.namespace == "identity_username_mfa"
		phone = phone || h.namespace == "identity_phone_mfa"
		for _, guard := range h.guards {
			if guard.schema != p.schema {
				continue
			}
			for _, name := range guard.constraints {
				if strings.HasPrefix(name, "sessions.session_record_binding_") {
					previous = strings.TrimPrefix(name, "sessions.")
				}
			}
		}
	}
	if len(base) == 0 || previous == "" {
		return nil, identity.InvalidInputError{Field: "reference_passkey_totp_migrations"}
	}
	continuation, err := (mfapg.PasskeyContinuationMigrationSource{Base: fixedMigrationSource(base), Version: 31, PasswordSignin: true, VerificationSignin: verification, UsernameSignin: username, PhoneSignin: phone}).Load(ctx)
	if err != nil {
		return nil, err
	}
	step := continuation[len(continuation)-1]
	catalog = append(catalog, migrationHistory{namespace: "identity_passkey_mfa", history: []migrations.Migration{step}, owners: map[migrations.Version]ModuleID{31: "identity/mfa/postgres"}, guards: []migrationGuard{{version: 31, schema: "identity_mfa", constraints: []string{"continuations.continuations_origin_purpose_passkey_v1"}}}})
	sessions, err := (sessionpg.PasskeyMFAMigrationSource{Schema: p.schema, Version: 1, PreviousConstraint: previous}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return append(catalog, migrationHistory{namespace: "identity_passkey_mfa_session", history: sessions, owners: map[migrations.Version]ModuleID{1: "identity/session/postgres"}, guards: []migrationGuard{{version: 1, schema: p.schema, constraints: []string{"sessions.session_record_binding_passkey_mfa_v1", "sessions.session_credential_continuation_passkey_mfa_v1"}}}}), nil
}
