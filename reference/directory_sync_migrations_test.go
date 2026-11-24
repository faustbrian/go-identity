package reference

import (
	"slices"
	"testing"

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
