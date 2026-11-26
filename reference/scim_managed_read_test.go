package reference

import (
	"slices"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestManagedSCIMSelectionKeepsExistingProjectionHistory(t *testing.T) {
	stores := StoreSet{state: &storeState{features: &featureState{}}}
	base, err := ensureSCIMProjectionHistory(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	unselected, err := stores.managedSCIMReadMigrationCatalog(t.Context(), base)
	if err != nil || len(unselected) != 1 || unselected[0].namespace != scimProjectionHistory {
		t.Fatal("unselected reads changed existing SCIM history", err)
	}
	stores.state.features.httpManagedSCIMRead = &managedSCIMReadState{}
	for _, prior := range [][]migrationHistory{nil, base} {
		selected, err := stores.managedSCIMReadMigrationCatalog(t.Context(), prior)
		if err != nil || len(selected) != 2 || selected[0].namespace != scimProjectionHistory || selected[1].namespace != scimManagedHistory {
			t.Fatal("managed reads did not append one independent history", err)
		}
		if !slices.EqualFunc(selected[0].history, base[0].history, func(a, b migrations.Migration) bool { return a.Checksum() == b.Checksum() }) {
			t.Fatal("managed selection changed installed SCIM projection bytes")
		}
		managed := selected[1]
		if len(managed.history) != 1 || managed.history[0].Version() != scimManagedVersion || managed.owners[scimManagedVersion] != "scim/postgres" {
			t.Fatal("managed reads selected more than their native migration")
		}
	}
}
