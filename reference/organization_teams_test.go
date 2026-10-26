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

func TestOrganizationTeamsRetainGraphGuards(t *testing.T) {
	var absent *OrganizationService
	var unavailable identity.UnavailableError
	a := organization.Authentication{TenantID: "tenant"}
	check := func(h *OrganizationService) {
		t.Helper()
		if _, err := h.CreateTeam(t.Context(), organization.CreateTeamOperationRequest{Authentication: a}, "127.0.0.1"); !errors.As(err, &unavailable) {
			t.Fatal("absent/closed team creator reached native owner", err)
		}
		if _, err := h.AddTeamMember(t.Context(), organization.AddTeamMemberOperationRequest{Authentication: a}, "127.0.0.1"); !errors.As(err, &unavailable) {
			t.Fatal("absent/closed team admission reached native owner", err)
		}
		if _, err := h.RemoveTeamMember(t.Context(), organization.RemoveTeamMemberOperationRequest{Authentication: a}, "127.0.0.1"); !errors.As(err, &unavailable) {
			t.Fatal("absent/closed team removal reached native owner", err)
		}
		if _, err := h.ListMyTeams(t.Context(), organization.TeamReadRequest{Authentication: a}); !errors.As(err, &unavailable) {
			t.Fatal("absent/closed own-team read reached native owner", err)
		}
		if _, err := h.ListTeamMembers(t.Context(), organization.TeamReadRequest{Authentication: a}); !errors.As(err, &unavailable) {
			t.Fatal("absent/closed team-member read reached native owner", err)
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

func TestOrganizationTeamsAppendWithoutChangingLifecycleHistory(t *testing.T) {
	s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "session_store", global: "deployment"}, organization: &organizationState{lifecycle: &organizationpg.Service{}}}}}
	base, err := s.baseMigrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	without, err := s.organizationMigrationCatalog(t.Context(), append([]migrationHistory(nil), base...))
	if err != nil {
		t.Fatal(err)
	}
	s.state.features.organization.teams = true
	with, err := s.organizationMigrationCatalog(t.Context(), append([]migrationHistory(nil), base...))
	if err != nil || len(with) != len(without)+1 {
		t.Fatal("team installation did not append independent history", err)
	}
	for i := range without {
		if with[i].namespace != without[i].namespace || len(with[i].history) != len(without[i].history) {
			t.Fatal("team installation changed installed history identity")
		}
		for j := range without[i].history {
			if with[i].history[j] != without[i].history[j] {
				t.Fatal("team installation rewrote an existing migration")
			}
		}
	}
	teams, err := (organizationpg.TeamMigrationSource{Version: 1}).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := (organizationpg.TeamMemberOperationLookupMigrationSource{Version: 2}).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	added := with[len(with)-1]
	if added.namespace != "identity_organization_teams" || len(added.history) != 2 || added.history[0] != teams[0] || added.history[1] != lookup[0] || added.owners[1] != "organization/postgres" || added.owners[2] != "organization/postgres" || len(added.guards) != 2 {
		t.Fatal("team history changed native owner or migration bytes")
	}
}
