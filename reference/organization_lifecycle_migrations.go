package reference

import (
	"context"
	"slices"

	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func (s StoreSet) organizationActionMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	n := s.state.features.organization
	if n.transferProofs == nil && n.lifecycleProofs == nil {
		return catalog, nil
	}
	present := func(name string) bool {
		return slices.ContainsFunc(catalog, func(h migrationHistory) bool { return h.namespace == name })
	}
	owned := func() []migrations.Migration {
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
	appendLast := func(namespace string, version migrations.Version, source migrations.Source, purpose string) error {
		steps, err := source.Load(ctx)
		if err != nil {
			return err
		}
		catalog = append(catalog, migrationHistory{namespace: namespace, history: steps[len(steps)-1:], owners: map[migrations.Version]ModuleID{version: "identity/password/postgres"}, guards: []migrationGuard{{version: version, schema: "identity_password", constraints: []string{"reauthentication_records.reauthentication_consumption_complete"}, constraintValue: purpose}}})
		return nil
	}
	// Keep the existing physical allocation even without username selection.
	if !present("identity_username_actions") {
		if err := appendLast("identity_username_actions", 21, passwordpg.ActionReauthenticationMigrationSource{Base: fixedMigrationSource(owned()), Version: 21}, "identity.username.update"); err != nil {
			return nil, err
		}
	}
	if n.lifecycleProofs != nil && !present("identity_organization_actions") {
		// Native anonymous30/passkey40+ CHECKs already retain both lifecycle
		// purposes. Never install older SQL over their consumed records, even
		// with handlers off: storage selection retains the installed histories.
		if present("identity_anonymous_upgrade_password") || present("identity_passkey_password") {
			return catalog, nil
		}
		if err := appendLast("identity_organization_actions", 28, passwordpg.OrganizationLifecycleReauthenticationMigrationSource{Base: fixedMigrationSource(owned()), Version: 28}, "identity.organization.restore"); err != nil {
			return nil, err
		}
	}
	return catalog, nil
}
