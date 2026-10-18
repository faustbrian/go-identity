package reference

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Preserve the common MFA prefix and fixed future enrollment allocations even
// when password login selects it first. These tables do not enable any API.
func passwordTOTPMigrationCatalog(ctx context.Context, catalog []migrationHistory, schema, riskSchema string, completion, verificationFirst bool) ([]migrationHistory, error) {
	var err error
	catalog, err = mfaEnrollmentMigrationCatalog(ctx, catalog, riskSchema)
	if err != nil {
		return nil, err
	}
	index := -1
	for j, h := range catalog {
		if h.namespace == "identity_mfa" {
			index = j
			break
		}
	}
	if index < 0 {
		return nil, identity.InvalidInputError{Field: "reference_password_mfa_history"}
	}
	h := catalog[index]
	full, err := (mfapg.PasswordContinuationMigrationSource{Base: fixedMigrationSource(h.history), Version: 7}).Load(ctx)
	if err != nil {
		return nil, err
	}
	owners := make(map[migrations.Version]ModuleID, len(h.owners)+1)
	for v, owner := range h.owners {
		owners[v] = owner
	}
	owners[7] = "identity/mfa/postgres"
	// PasswordContinuationMigrationSource reuses version2's CHECK name. Its
	// newly allowed password operation, not that predecessor name alone, detects
	// an unmanaged version7 installation without rejecting ordinary upgrades.
	catalog[index] = migrationHistory{namespace: h.namespace, history: full, owners: owners, guards: append(append([]migrationGuard(nil), h.guards...), migrationGuard{version: 7, schema: "identity_mfa", constraints: []string{"continuations.continuations_origin_purpose_check"}, constraintValue: "identity.password.signin"})}
	if !completion {
		return catalog, nil
	}
	predecessor := false
	for _, h := range catalog {
		predecessor = predecessor || h.namespace == "identity_magiclink_session"
	}
	if !predecessor {
		// This catalog installs session-owned record-format predecessors, not
		// a magic-link service or transport. Reuse their permanent allocations
		// so selecting magic-link later cannot replay or rewrite that history.
		catalog, err = magicLinkMigrationCatalog(ctx, catalog, schema)
		if err != nil {
			return nil, err
		}
	}
	existing := false
	for _, h := range catalog {
		existing = existing || h.namespace == "identity_magiclink_mfa_session"
	}
	if !existing {
		catalog, err = magicLinkTOTPRequiredMigrations(ctx, catalog, schema, riskSchema, verificationFirst)
		if err != nil {
			return nil, err
		}
	}
	steps, err := (sessionpg.PasswordMFAMigrationSource{Schema: schema, Version: 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return append(catalog, migrationHistory{namespace: "identity_password_mfa_session", history: steps, owners: map[migrations.Version]ModuleID{1: "identity/session/postgres"}, guards: []migrationGuard{{version: 1, schema: schema, constraints: []string{"sessions.session_record_binding_v7", "sessions.session_credential_continuation_v4"}}}}), nil
}
