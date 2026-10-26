package reference

import (
	"testing"

	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestOrganizationRolesAppendWithoutRewritingInstalledHistories(t *testing.T) {
	s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "session_store", global: "deployment"}, organization: &organizationState{teams: true, teamLifecycle: true}}}}
	base, err := s.baseMigrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.organizationMigrationCatalog(t.Context(), append([]migrationHistory(nil), base...))
	if err != nil {
		t.Fatal(err)
	}
	s.state.features.organization.dynamicRoles = true
	after, err := s.organizationMigrationCatalog(t.Context(), append([]migrationHistory(nil), base...))
	if err != nil || len(after) != len(before)+1 {
		t.Fatal("roles did not append separate native history", err)
	}
	for i := range before {
		if before[i].namespace != after[i].namespace || len(before[i].history) != len(after[i].history) {
			t.Fatal("roles changed installed history identity")
		}
		for j := range before[i].history {
			if before[i].history[j] != after[i].history[j] {
				t.Fatal("roles rewrote applied migration bytes")
			}
		}
	}
	roles, err := (organizationpg.DynamicRoleMigrationSource{Version: 1}).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := (organizationpg.DynamicRoleDeleteOperationLookupMigrationSource{Version: 2}).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	added := after[len(after)-1]
	if added.namespace != "identity_organization_roles" || len(added.history) != 2 || added.history[0] != roles[0] || added.history[1] != lookup[0] || added.owners[1] != "organization/postgres" || added.owners[2] != "organization/postgres" || len(added.guards) != 2 {
		t.Fatal("role native ownership or migration bytes changed")
	}
	s.state.features.organization.teamRoleBindings = true
	withTeams, err := s.organizationMigrationCatalog(t.Context(), append([]migrationHistory(nil), base...))
	if err != nil {
		t.Fatal(err)
	}
	team, err := (organizationpg.TeamRoleBindingMigrationSource{Version: 3}).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	last := withTeams[len(withTeams)-1]
	if len(last.history) != 3 || last.history[0] != added.history[0] || last.history[1] != added.history[1] || last.history[2] != team[0] || last.owners[3] != "organization/postgres" || len(last.guards) != 3 {
		t.Fatal("team roles did not append exact optional native suffix")
	}
}
