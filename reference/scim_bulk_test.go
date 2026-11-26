package reference

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestSCIMBulkOptInRequiresNativeGraphAndLeavesDefaultUnchanged(t *testing.T) {
	_, err := ComposeStores(StoreConfiguration{SCIMBulk: &SCIMBulkConfiguration{}}, ReferenceDependencies{})
	var input identity.InvalidInputError
	if !errors.As(err, &input) || input.Field != "reference_scim_bulk" {
		t.Fatalf("incomplete selected graph returned %v, want SCIM Bulk selection error", err)
	}
	var stores StoreSet
	result, err := stores.InitializeSCIMBulkConnection(context.Background())
	if err == nil || result.Version != 0 {
		t.Fatal("unselected StoreSet initialized a SCIM connection")
	}
}

func TestSCIMBulkMigrationsRetainTheExactPriorNamespaces(t *testing.T) {
	ctx := context.Background()
	shared, err := (kernel.RequestKeyPreparationMigrationSource{
		Base: kernel.RequestKeyMigrationSource{Base: kernel.MigrationSource{}, Version: 1017}, Version: 1018,
	}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	prior, err := directorySyncSourceMigrationCatalog(ctx, []migrationHistory{{history: shared}}, directorySyncSourceMigrations{})
	if err != nil {
		t.Fatal(err)
	}
	stores := StoreSet{state: &storeState{features: &featureState{scimBulk: &scimBulkState{}}}}
	selected, err := stores.scimBulkMigrationCatalog(ctx, append([]migrationHistory(nil), prior...))
	if err != nil || len(selected) != len(prior)+3 {
		t.Fatalf("selected catalog did not add only credential authority and Bulk suffixes: histories %d, %v", len(selected), err)
	}
	for i, legacy := range prior {
		retained := selected[i]
		if retained.namespace != legacy.namespace || len(retained.history) != len(legacy.history) {
			t.Fatal("selection re-owned a prior namespace", legacy.namespace)
		}
		for j, step := range legacy.history {
			if retained.history[j].Version() != step.Version() || retained.history[j].Checksum() != step.Checksum() {
				t.Fatal("selection modified an installed migration", legacy.namespace, step.Version())
			}
		}
	}
	for _, want := range []struct {
		namespace   string
		first, last migrations.Version
	}{
		{scimBulkAliasHistory, 2454, 2455},
		{scimBulkHistory, 4, 10},
	} {
		found := false
		for _, history := range selected {
			if history.namespace == want.namespace {
				found = true
				if len(history.history) != int(want.last-want.first+1) || history.history[0].Version() != want.first ||
					history.history[len(history.history)-1].Version() != want.last {
					t.Fatal("wrong isolated native suffix", want.namespace)
				}
			}
		}
		if !found {
			t.Fatal("missing isolated native suffix", want.namespace)
		}
	}
	stores.state.features.scimBulk = nil
	disabled, err := stores.scimBulkMigrationCatalog(ctx, prior)
	if err != nil || len(disabled) != len(prior) {
		t.Fatal("disabling Bulk still selected its extension histories", err)
	}
}
