package reference

import (
	"maps"
	"reflect"
	"slices"
	"testing"

	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestDirectorySyncMigrationCatalogPreservesProviderHistory(t *testing.T) {
	ctx := t.Context()
	store := StoreSet{state: &storeState{features: &featureState{}}}
	off, err := store.directorySyncMigrationCatalog(ctx, nil)
	if err != nil || len(off) != 0 {
		t.Fatal("unselected directory changed the migration graph", err)
	}
	store.state.features.directorySync = &directorySyncState{}
	selected, err := store.directorySyncMigrationCatalog(ctx, nil)
	if err != nil || len(selected) != 3 {
		t.Fatal("standalone directory did not select credential authority, provider history and its own generation", err)
	}
	const providerNamespace = "identity_enterprise_oidc"
	providerIndex := slices.IndexFunc(selected, func(h migrationHistory) bool { return h.namespace == providerNamespace })
	if providerIndex < 0 {
		t.Fatal("directory selected a competing registry namespace")
	}
	standalone := selected[providerIndex]
	withLogin, err := enterpriseProviderMigrationHistory(ctx, true, true)
	if err != nil || len(standalone.history) != 4 || len(withLogin.history) != 7 {
		t.Fatal("directory enabled login-only schemas or changed the enterprise provider history", err)
	}
	for i, step := range standalone.history {
		if step.Version() != migrations.Version(i+1) || step.Checksum() != withLogin.history[i].Checksum() {
			t.Fatal("provider-prefix bytes changed when selecting sign-in")
		}
	}
	combined, err := store.directorySyncMigrationCatalog(ctx, []migrationHistory{withLogin})
	if err != nil || len(combined) != len(selected) || combined[0].namespace != providerNamespace || len(combined[0].history) != 7 || combined[len(combined)-1].namespace != "identity_sso_directory_sync" {
		t.Fatal("combined selection duplicated, replaced or reordered the existing provider history", err)
	}
}

func TestDirectoryGroupMigrationCatalogSharesCanonicalRequests(t *testing.T) {
	ctx := t.Context()
	base, err := migrations.NewMigration(1, "identity_base", migrations.TransactionModeDefault, "SELECT 1", "")
	if err != nil {
		t.Fatal(err)
	}
	nativeBase, err := (kernel.RequestKeyMigrationSource{Base: fixedMigrationSource{base}, Version: 1017}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	shared := migrationHistory{history: nativeBase}
	prior, err := canonicalRequestMigrationHistory(ctx, shared.history)
	if err != nil || len(prior.history) != 3 {
		t.Fatal("existing SAML request history changed", err)
	}
	for _, before := range [][]migrationHistory{{shared}, {shared, prior}} {
		after, err := directorySyncSourceMigrationCatalog(ctx, before, directorySyncSourceMigrations{groups: true})
		if err != nil || len(after) != 4 || after[1].namespace != canonicalRequestHistory || len(after[1].history) != len(prior.history) ||
			after[2].namespace != "identity_scim_directory_groups" || after[3].namespace != "identity_organization_directory_grants" {
			t.Fatal("Group selection did not preserve and reuse the same schema histories", err)
		}
		for i, step := range after[1].history {
			if step.Version() != prior.history[i].Version() || step.Checksum() != prior.history[i].Checksum() {
				t.Fatal("Group selection changed the installed canonical request history")
			}
		}
	}
}

func TestDirectoryUserMigrationCatalogSharesSCIMWithoutSelectingTeamGrants(t *testing.T) {
	ctx := t.Context()
	base, err := migrations.NewMigration(1, "identity_base", migrations.TransactionModeDefault, "SELECT 1", "")
	if err != nil {
		t.Fatal(err)
	}
	nativeBase, err := (kernel.RequestKeyMigrationSource{Base: fixedMigrationSource{base}, Version: 1017}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	input := []migrationHistory{{history: nativeBase}}
	groups, err := directorySyncSourceMigrationCatalog(ctx, slices.Clone(input), directorySyncSourceMigrations{groups: true})
	if err != nil || len(groups) != 4 {
		t.Fatal("Group baseline missing", err)
	}
	users, err := directorySyncSourceMigrationCatalog(ctx, slices.Clone(input), directorySyncSourceMigrations{users: true})
	if err != nil || len(users) != 4 || users[3].namespace != "identity_organization_directory_membership" ||
		len(users[3].guards) != 1 || !slices.Equal(users[3].guards[0].tables, []string{"directory_membership_grants"}) {
		t.Fatal("User selection did not choose only the User membership history", err)
	}
	both, err := directorySyncSourceMigrationCatalog(ctx, slices.Clone(input), directorySyncSourceMigrations{groups: true, users: true})
	if err != nil || len(both) != 5 || both[3].namespace != groups[3].namespace || both[4].namespace != users[3].namespace {
		t.Fatal("combined selection duplicated the common history or reordered known steps", err)
	}
	for i := range both[:3] {
		for _, catalog := range [][]migrationHistory{groups, users} {
			step, combined := catalog[i], both[i]
			if step.namespace != combined.namespace || len(step.history) != len(combined.history) {
				t.Fatal("selection changed an existing migration history")
			}
			for j, migration := range step.history {
				if migration.Version() != combined.history[j].Version() || migration.Checksum() != combined.history[j].Checksum() {
					t.Fatal("selection changed an existing migration's bytes")
				}
			}
		}
	}
}

func TestDirectoryRoleMigrationCatalogSelectsIndependentHistory(t *testing.T) {
	ctx := t.Context()
	base, err := migrations.NewMigration(1, "identity_base", migrations.TransactionModeDefault, "SELECT 1", "")
	if err != nil {
		t.Fatal(err)
	}
	nativeBase, err := (kernel.RequestKeyMigrationSource{Base: fixedMigrationSource{base}, Version: 1017}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nativeRoles, err := (organizationpg.DirectoryTeamRoleMigrationSource{Version: 1}).Load(ctx)
	if err != nil || len(nativeRoles) != 1 {
		t.Fatal("native directory role history missing", err)
	}
	for _, profile := range []struct {
		name             string
		withUsers        bool
		existingRequests bool
	}{
		{name: "Group"},
		{name: "GroupWithExistingRequests", existingRequests: true},
		{name: "GroupAndUser", withUsers: true},
		{name: "GroupAndUserWithExistingRequests", withUsers: true, existingRequests: true},
	} {
		t.Run(profile.name, func(t *testing.T) {
			input := []migrationHistory{{history: nativeBase}}
			if profile.existingRequests {
				requests, err := canonicalRequestMigrationHistory(ctx, nativeBase)
				if err != nil {
					t.Fatal(err)
				}
				input = append(input, requests)
			}
			groups := &directoryGroupSource{}
			directory := &directorySyncState{groups: groups}
			if profile.withUsers {
				directory.users = &directoryUserSource{}
			}
			store := StoreSet{state: &storeState{features: &featureState{directorySync: directory}}}
			ordinary, err := store.directorySyncMigrationCatalog(ctx, slices.Clone(input))
			if err != nil {
				t.Fatal(err)
			}
			const roleNamespace = "identity_organization_directory_roles"
			if slices.ContainsFunc(ordinary, func(h migrationHistory) bool { return h.namespace == roleNamespace }) {
				t.Fatal("nil role profile selected the role schema")
			}
			groups.roles = &directoryGroupRoleSource{}
			selected, err := store.directorySyncMigrationCatalog(ctx, slices.Clone(input))
			if err != nil || len(selected) != len(ordinary)+1 {
				t.Fatal("role profile without an executor did not select exactly one independent history", err)
			}
			grantsIndex := slices.IndexFunc(selected, func(h migrationHistory) bool {
				return h.namespace == "identity_organization_directory_grants"
			})
			roleIndex := slices.IndexFunc(selected, func(h migrationHistory) bool { return h.namespace == roleNamespace })
			if grantsIndex < 0 || roleIndex != grantsIndex+1 {
				t.Fatal("role history did not follow the existing Group grants history")
			}
			roles := selected[roleIndex]
			if len(roles.history) != 1 || roles.history[0].Version() != 1 || roles.history[0].Checksum() != nativeRoles[0].Checksum() ||
				!maps.Equal(roles.owners, map[migrations.Version]ModuleID{1: "organization/postgres"}) || roles.preflight != "" {
				t.Fatal("role history changed native migration bytes or ownership")
			}
			guards := []migrationGuard{{version: 1, schema: "organization", tables: []string{"directory_team_role_grants"}}}
			if !reflect.DeepEqual(roles.guards, guards) {
				t.Fatal("role history did not guard exactly organization.directory_team_role_grants")
			}
			withoutRoles := append(slices.Clone(selected[:roleIndex]), selected[roleIndex+1:]...)
			seen := make(map[string]bool)
			for i, before := range ordinary {
				after := withoutRoles[i]
				if seen[after.namespace] {
					t.Fatalf("role selection duplicated history %q", after.namespace)
				}
				seen[after.namespace] = true
				if before.namespace != after.namespace || len(before.history) != len(after.history) ||
					!maps.Equal(before.owners, after.owners) || !reflect.DeepEqual(before.guards, after.guards) || before.preflight != after.preflight {
					t.Fatalf("role selection changed existing history %q", before.namespace)
				}
				for j, step := range before.history {
					if step.Version() != after.history[j].Version() || step.Checksum() != after.history[j].Checksum() {
						t.Fatalf("role selection changed existing migration bytes in %q", before.namespace)
					}
				}
			}
		})
	}
}
