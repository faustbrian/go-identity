package reference

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestOrganizationTeamRoleBindingsRetainGraphGuards(t *testing.T) {
	var unavailable identity.UnavailableError
	a := organization.Authentication{TenantID: "tenant"}
	check := func(h *OrganizationService) {
		t.Helper()
		if _, err := h.AssignTeamDynamicRole(t.Context(), organization.AssignTeamDynamicRoleOperationRequest{Authentication: a}, "127.0.0.1"); !errors.As(err, &unavailable) {
			t.Fatal("absent/closed team assignment reached native owner", err)
		}
		if _, err := h.RevokeTeamDynamicRole(t.Context(), organization.RevokeTeamDynamicRoleOperationRequest{Authentication: a}, "127.0.0.1"); !errors.As(err, &unavailable) {
			t.Fatal("absent/closed team revocation reached native owner", err)
		}
	}
	check(nil)
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	state := &storeState{durable: true, lifetime: lifetime, cancel: cancel, drained: drained, tenants: map[string]*tenantRecovery{"tenant": {}}, features: &featureState{composed: true, ready: true, timeout: time.Second, organization: &organizationState{}}}
	handle, err := (FeatureSet{state: state}).Organizations()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handle.AssignTeamDynamicRole(t.Context(), organization.AssignTeamDynamicRoleOperationRequest{Authentication: a}, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("unselected team assignment reached native owner", err)
	}
	if _, err := handle.RevokeTeamDynamicRole(t.Context(), organization.RevokeTeamDynamicRoleOperationRequest{Authentication: a}, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("unselected team revocation reached native owner", err)
	}
	if err := (StoreSet{state: state}).Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	check(handle)
}

func TestOrganizationTeamBindingLookupHasIndependentNativeHistory(t *testing.T) {
	s := StoreSet{state: &storeState{features: &featureState{organization: &organizationState{dynamicRoles: true, teamRoleBindings: true}}}}
	before, err := s.organizationRoleMigrationCatalog(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s.state.features.organization.teamRoleOperations = true
	after, err := s.organizationRoleMigrationCatalog(t.Context(), nil)
	if err != nil || len(after) != len(before)+1 || !reflect.DeepEqual(after[0], before[0]) {
		t.Fatal("team operation selection rewrote installed native role history", err)
	}
	native, err := (organizationpg.TeamRoleBindingRevokeOperationLookupMigrationSource{Version: 1}).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	lookup := after[len(after)-1]
	if lookup.namespace != "identity_organization_team_bindings" || len(lookup.history) != 1 || lookup.history[0] != native[0] || lookup.owners[1] != "organization/postgres" || len(lookup.guards) != 1 {
		t.Fatal("team operation lookup lost native bytes/ownership")
	}
	s.state.features.organization.directRoleBindings = true
	withDirect, err := s.organizationRoleMigrationCatalog(t.Context(), nil)
	if err != nil || len(withDirect) != len(after)+1 || !reflect.DeepEqual(withDirect[0], before[0]) || !reflect.DeepEqual(withDirect[len(withDirect)-1], lookup) || withDirect[1].namespace != "identity_organization_direct_bindings" {
		t.Fatal("later direct selection changed existing team history", err)
	}
}
