package reference

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestOrganizationTeamLifecycleRetainsGraphGuards(t *testing.T) {
	var absent *OrganizationService
	var unavailable identity.UnavailableError
	check := func(h *OrganizationService) {
		t.Helper()
		r := organization.TeamReadRequest{Authentication: organization.Authentication{TenantID: "tenant"}}
		if _, err := h.UpdateTeam(t.Context(), organization.UpdateTeamOperationRequest{Authentication: r.Authentication}, "127.0.0.1"); !errors.As(err, &unavailable) {
			t.Fatal("absent/closed team updater reached native owner", err)
		}
		if _, err := h.DeleteTeam(t.Context(), organization.DeleteTeamOperationRequest{Authentication: r.Authentication}, "127.0.0.1"); !errors.As(err, &unavailable) {
			t.Fatal("absent/closed team deleter reached native owner", err)
		}
		if _, err := h.GetTeam(t.Context(), r); !errors.As(err, &unavailable) {
			t.Fatal("absent/closed exact team read reached native owner", err)
		}
		if _, err := h.ListTeams(t.Context(), r); !errors.As(err, &unavailable) {
			t.Fatal("absent/closed team page reached native owner", err)
		}
	}
	check(absent)
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	state := &storeState{durable: true, lifetime: lifetime, cancel: cancel, drained: drained, tenants: map[string]*tenantRecovery{"tenant": {}}, features: &featureState{composed: true, ready: true, timeout: time.Second, organization: &organizationState{}}}
	handle, err := (FeatureSet{state: state}).Organizations()
	if err != nil {
		t.Fatal(err)
	}
	if err := (StoreSet{state: state}).Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	check(handle)
}

func TestOrganizationTeamLifecycleAppendsNativeSuffix(t *testing.T) {
	s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "session_store", global: "deployment"}, organization: &organizationState{teams: true}}}}
	base, err := s.baseMigrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.organizationMigrationCatalog(t.Context(), append([]migrationHistory(nil), base...))
	if err != nil {
		t.Fatal(err)
	}
	s.state.features.organization.teamLifecycle = true
	after, err := s.organizationMigrationCatalog(t.Context(), append([]migrationHistory(nil), base...))
	if err != nil || len(after) != len(before) {
		t.Fatal("team lifecycle changed installed history namespaces", err)
	}
	for i := range before {
		if before[i].namespace != after[i].namespace || len(after[i].history) < len(before[i].history) {
			t.Fatal("team lifecycle replaced an installed history")
		}
		for j := range before[i].history {
			if before[i].history[j] != after[i].history[j] {
				t.Fatal("team lifecycle rewrote an applied prefix")
			}
		}
	}
	lifecycle, err := (organizationpg.TeamLifecycleMigrationSource{Version: 3}).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := (organizationpg.TeamDeleteOperationLookupMigrationSource{Version: 4}).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	added := after[len(after)-1]
	if added.namespace != "identity_organization_teams" || len(added.history) != 4 || added.history[2] != lifecycle[0] || added.history[3] != lookup[0] || added.owners[3] != "organization/postgres" || added.owners[4] != "organization/postgres" || len(added.guards) != 4 {
		t.Fatal("lifecycle suffix changed native migration ownership or bytes")
	}
}
