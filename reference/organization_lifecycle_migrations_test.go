package reference

import (
	"testing"

	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestOrganizationLifecycleRetainsNewerActionHistories(t *testing.T) {
	base, err := (passwordpg.MigrationSource{}).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	action, err := (passwordpg.ActionReauthenticationMigrationSource{Base: fixedMigrationSource(base), Version: 21}).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, namespace := range []string{"", "identity_anonymous_upgrade_password", "identity_passkey_password"} {
		catalog := []migrationHistory{{namespace: "identity_password", history: base, owners: make(map[migrations.Version]ModuleID)}, {namespace: "identity_username_actions", history: action[len(action)-1:], owners: map[migrations.Version]ModuleID{21: "identity/password/postgres"}}}
		for _, step := range base {
			catalog[0].owners[step.Version()] = "identity/password/postgres"
		}
		if namespace != "" {
			var source migrations.Source = passwordpg.AnonymousUpgradeReauthenticationMigrationSource{Base: fixedMigrationSource(action), Version: 30}
			if namespace == "identity_passkey_password" {
				source = passwordpg.PasskeyReauthenticationMigrationSource{Base: fixedMigrationSource(action), Version: 40}
			}
			history, err := source.Load(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			last := history[len(history)-1]
			catalog = append(catalog, migrationHistory{namespace: namespace, history: history[len(history)-1:], owners: map[migrations.Version]ModuleID{last.Version(): "identity/password/postgres"}})
		}
		s := StoreSet{state: &storeState{features: &featureState{organization: &organizationState{lifecycleProofs: &passwordpg.Repository{}}}}}
		got, err := s.organizationActionMigrationCatalog(t.Context(), catalog)
		if err != nil {
			t.Fatal(err)
		}
		want := len(catalog)
		if namespace == "" {
			want++
		}
		if len(got) != want {
			t.Fatal("older lifecycle CHECK scheduled over a newer native history", namespace)
		}
		for i := range catalog {
			if got[i].namespace != catalog[i].namespace || len(got[i].history) != len(catalog[i].history) {
				t.Fatal("installed history changed")
			}
			for j := range catalog[i].history {
				if got[i].history[j] != catalog[i].history[j] {
					t.Fatal("predecessor bytes changed")
				}
			}
		}
	}
}

func TestOrganizationLifecycleKeepsInvitationForwardHistory(t *testing.T) {
	// Only native storage selectors are exercised here, not session or invitation
	// authority. The public HTTPS journey separately applies and uses this DDL.
	s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "session_store", global: "deployment"}, organization: &organizationState{lifecycle: &organizationpg.Service{}}}}}
	base, err := s.baseMigrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	without, err := s.organizationMigrationCatalog(t.Context(), append([]migrationHistory(nil), base...))
	if err != nil {
		t.Fatal(err)
	}
	s.state.features.organization.invitations = &organizationpg.InvitationService{}
	with, err := s.organizationMigrationCatalog(t.Context(), append([]migrationHistory(nil), base...))
	if err != nil {
		t.Fatal(err)
	}
	if len(without) != len(with) {
		t.Fatal("later invitation selection inserted an older physical namespace")
	}
	found := false
	for i := range without {
		if without[i].namespace != with[i].namespace || len(without[i].history) != len(with[i].history) {
			t.Fatal("later invitation selection changed prefix")
		}
		for j := range without[i].history {
			if without[i].history[j] != with[i].history[j] {
				t.Fatal("later invitation selection rewrote physical history")
			}
		}
		if without[i].namespace == "identity_organization" {
			found = true
			if len(without[i].history) != 13 || without[i].history[12].Name() != "organization_archive_restore" {
				t.Fatal("lifecycle precedes complete invitation prefix")
			}
		}
	}
	if !found {
		t.Fatal("lifecycle physical history absent")
	}
}
