package reference

import (
	"slices"
	"testing"

	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
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
		after, err := directorySyncGroupMigrationCatalog(ctx, before)
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
