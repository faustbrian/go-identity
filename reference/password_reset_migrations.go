package reference

import (
	"context"
	"slices"

	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Independent reset histories still consume the shared kernel/session base.
// Discover its authoritative status even when the operator selects only a
// downstream owner; pending prerequisites must be explicitly selected for apply.
func migrationDiscoveryIDs(catalog []migrationHistory, ids []ModuleID) []ModuleID {
	result := slices.Clone(ids)
	if slices.Contains(ids, ModuleID("outbox/postgres/identity")) && !slices.Contains(result, ModuleID("outbox/postgres")) {
		result = append(result, "outbox/postgres")
	}
	for _, h := range catalog {
		if !resetKernelDependent(h.namespace) {
			continue
		}
		for _, owner := range h.owners {
			if slices.Contains(ids, owner) && !slices.Contains(result, ModuleID("identity/postgres")) {
				result = append(result, "identity/postgres")
			}
		}
	}
	return result
}

func resetKernelDependent(namespace string) bool {
	switch namespace {
	case "identity_password", "identity_mfa", "identity_capability", "identity_reset_session", "identity_password_session", "identity_registration", "identity_registration_counters", "identity_password_change_session", "identity_password_change_kernel", "identity_registration_session", "identity_magiclink_session", "identity_magiclink_mfa_session", "identity_mfa_counters":
		return true
	case "identity_password_mfa_session", "identity_mfa_otp", "identity_mfa_otp_counters", "identity_mfa_otp_session":
		return true
	default:
		return false
	}
}

// Reset is independently selectable after an installed OTP deployment. Keep
// its forward extensions outside the shared history so enabling reset cannot
// prevent a later selection of the already allocated signin suffix. SQL and
// checksums remain native owner values; no reset workflow ledger is introduced.
func passwordResetMigrationCatalog(ctx context.Context, shared []migrations.Migration, schema string) ([]migrationHistory, error) {
	// These allocations are permanent in identity_reset_kernel. The native
	// extension sources require a nonempty earlier base, which is not copied into
	// this physical history: reference applies the shared kernel first.
	base := fixedMigrationSource(shared)
	replacement := kernel.CredentialReplacementMigrationSource{Base: base, Version: 1500}
	full, err := (kernel.CredentialResetMigrationSource{Base: replacement, Version: 1501}).Load(ctx)
	if err != nil {
		return nil, err
	}
	kernelSteps := append([]migrations.Migration(nil), full[len(shared):]...)
	passwordSteps, err := (passwordpg.MigrationSource{}).Load(ctx)
	if err != nil {
		return nil, err
	}
	factorSteps, err := (mfapg.MigrationSource{Version: 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	sessionSteps, err := (sessionpg.PasswordResetMigrationSource{Schema: schema, Version: 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	capabilitySource, err := migrations.NewFSSource(ownedMigrationFiles{capabilitypg.Migrations()}, ".")
	if err != nil {
		return nil, err
	}
	capabilitySteps, err := capabilitySource.Load(ctx)
	if err != nil {
		return nil, err
	}
	selected := []struct {
		namespace string
		owner     ModuleID
		steps     []migrations.Migration
		guards    []migrationGuard
	}{
		{"identity_reset_kernel", "identity/postgres", kernelSteps, []migrationGuard{{version: 1500, schema: "identity", tables: []string{"credential_replacements"}}}},
		{"identity_password", "identity/password/postgres", passwordSteps, []migrationGuard{{version: 1, schema: "identity_password"}}},
		{"identity_mfa", "identity/mfa/postgres", factorSteps, []migrationGuard{{version: 1, schema: "identity_mfa", tables: []string{"factor_authorities"}}}},
		{"identity_capability", "capability/postgres/identity", capabilitySteps, []migrationGuard{{version: 1, schema: "public", tables: []string{"capability_identity_one_use"}}}},
		{"identity_reset_session", "identity/session/postgres", sessionSteps, []migrationGuard{{version: 1, schema: schema, tables: []string{"password_resets"}}}},
	}
	result := make([]migrationHistory, 0, len(selected))
	for _, source := range selected {
		h := migrationHistory{namespace: source.namespace, history: source.steps, owners: make(map[migrations.Version]ModuleID), guards: source.guards}
		for _, step := range source.steps {
			h.owners[step.Version()] = source.owner
		}
		result = append(result, h)
	}
	return result, nil
}
