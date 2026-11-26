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
	stores.state.features.httpManagedSCIMRead = nil
	stores.state.features.httpManagedSCIMCreate = &managedSCIMCreateState{}
	create, err := stores.managedSCIMReadMigrationCatalog(t.Context(), base)
	if err != nil || len(create) != 3 || create[1].namespace != "identity_organization_credential_authority" || create[2].namespace != scimManagedHistory || len(create[2].history) != 1 || create[2].history[0].Version() != scimManagedVersion {
		t.Fatal("create alone did not select managed schema and its credential epoch dependency", err)
	}
	if bulk, err := stores.scimBulkMigrationCatalog(t.Context(), create); err != nil || len(bulk) != len(create) {
		t.Fatal("create alone must not select Bulk migrations", err)
	}
}

func TestManagedSCIMDeleteSelectsOneSharedMembershipHistory(t *testing.T) {
	ctx := t.Context()
	stores := StoreSet{state: &storeState{features: &featureState{httpManagedSCIMUsers: &managedSCIMUsersState{deleteUser: true}}}}
	projection, err := ensureSCIMProjectionHistory(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := ensureDirectoryMembershipHistory(ctx, slices.Clone(projection))
	if err != nil {
		t.Fatal(err)
	}
	for _, prior := range [][]migrationHistory{projection, installed} {
		selected, err := stores.managedSCIMReadMigrationCatalog(ctx, slices.Clone(prior))
		if err != nil || len(selected) != 4 {
			t.Fatal("Delete did not select the existing membership, credential and SCIM histories exactly once", err)
		}
		owners := 0
		for _, h := range selected {
			if h.namespace != directoryMembershipHistory {
				continue
			}
			owners++
			if len(h.history) != 1 || h.owners[1] != "organization/postgres" || h.history[0].Checksum() != installed[1].history[0].Checksum() {
				t.Fatal("Delete changed the organization's existing membership migration")
			}
		}
		if owners != 1 {
			t.Fatal("Delete selected duplicate or missing membership histories", owners)
		}
	}
}

func TestManagedSCIMGroupReadSharesTheSelectedNativeAndRateOwner(t *testing.T) {
	native := &ManagedSCIMConnectionConfiguration{}
	groups := &HTTPManagedSCIMGroupsReadConfiguration{
		Native: native, RateNamespace: "directory", RateKey: [32]byte{1},
		EnableGet: true,
	}
	config := StoreConfiguration{HTTPManagedSCIMGroupsRead: groups}
	owner, field, err := managedSCIMUsersOptions(config)
	if err != nil || owner == nil || owner.Native != native || owner.RateNamespace != "directory" || owner.RateKey != groups.RateKey || field != "reference_http_managed_scim_groups_read" {
		t.Fatal("standalone Group Get did not own its exact managed configuration", err)
	}

	config.HTTPManagedSCIMUsersList = &HTTPManagedSCIMUsersListConfiguration{Native: native, RateNamespace: "directory", RateKey: [32]byte{1}}
	if _, _, err := managedSCIMUsersOptions(config); err == nil {
		t.Fatal("same-value competing Group native and quota owners were accepted")
	}
	config.HTTPManagedSCIMGroupsRead = &HTTPManagedSCIMGroupsReadConfiguration{EnableList: true}
	owner, _, err = managedSCIMUsersOptions(config)
	if err != nil || owner == nil || *owner != *config.HTTPManagedSCIMUsersList {
		t.Fatal("co-selected Group List did not share the User route's exact owner", err)
	}

	for _, invalid := range []HTTPManagedSCIMGroupsReadConfiguration{
		{},
		{EnableList: true, MaximumMembers: -1},
		{EnableGet: true, MaximumMembers: 10001},
		{EnableList: true, RateNamespace: "second-quota"},
		{EnableGet: true, RateKey: [32]byte{2}},
	} {
		config.HTTPManagedSCIMGroupsRead = &invalid
		if _, _, err := managedSCIMUsersOptions(config); err == nil {
			t.Fatal("invalid or competing Group configuration was accepted")
		}
	}
}

func TestManagedSCIMGroupReplaceSharesTheSelectedOwnerAndMemberCeiling(t *testing.T) {
	native := &ManagedSCIMConnectionConfiguration{}
	standalone := &HTTPManagedSCIMGroupsReplaceConfiguration{Native: native, RateNamespace: "directory", RateKey: [32]byte{1}, MaximumMembers: 2}
	config := StoreConfiguration{HTTPManagedSCIMGroupsReplace: standalone}
	owner, field, err := managedSCIMUsersOptions(config)
	if err != nil || owner == nil || owner.Native != native || owner.RateNamespace != standalone.RateNamespace || owner.RateKey != standalone.RateKey || field != managedSCIMGroupsReplaceField {
		t.Fatal("standalone Group Replace did not select its exact owner and quota", err)
	}
	config.HTTPManagedSCIMGroupsCreate = &HTTPManagedSCIMGroupsCreateConfiguration{Native: native, RateNamespace: "directory", RateKey: [32]byte{1}, MaximumMembers: 2}
	if _, _, err := managedSCIMUsersOptions(config); err == nil {
		t.Fatal("co-selected Group Replace accepted a second native/rate owner")
	}
	config.HTTPManagedSCIMGroupsReplace = &HTTPManagedSCIMGroupsReplaceConfiguration{MaximumMembers: 1}
	if _, _, err := managedSCIMUsersOptions(config); err == nil {
		t.Fatal("co-selected Group Replace accepted a different member ceiling")
	}
	config.HTTPManagedSCIMGroupsReplace.MaximumMembers = 2
	owner, field, err = managedSCIMUsersOptions(config)
	if err != nil || owner == nil || owner.Native != native || owner.RateKey != standalone.RateKey || field != managedSCIMGroupsCreateField {
		t.Fatal("co-selected Group Replace did not reuse the Create route's owner", err)
	}
}
