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

func TestOrganizationDirectRoleBindingsRetainGraphGuards(t *testing.T) {
	var absent *OrganizationService
	var unavailable identity.UnavailableError
	a := organization.Authentication{TenantID: "tenant"}
	check := func(h *OrganizationService) {
		t.Helper()
		if _, err := h.AssignDynamicRole(t.Context(), organization.AssignDynamicRoleOperationRequest{Authentication: a}, "127.0.0.1"); !errors.As(err, &unavailable) {
			t.Fatal("absent/closed assignment reached native owner", err)
		}
		if _, err := h.RevokeDynamicRole(t.Context(), organization.RevokeDynamicRoleOperationRequest{Authentication: a}, "127.0.0.1"); !errors.As(err, &unavailable) {
			t.Fatal("absent/closed revocation reached native owner", err)
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
	if _, err := handle.AssignDynamicRole(t.Context(), organization.AssignDynamicRoleOperationRequest{Authentication: a}, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("unselected direct assignment reached native owner", err)
	}
	if _, err := handle.RevokeDynamicRole(t.Context(), organization.RevokeDynamicRoleOperationRequest{Authentication: a}, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("unselected direct revocation reached native owner", err)
	}
	if err := (StoreSet{state: state}).Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	check(handle)
}

func TestOrganizationDirectBindingsKeepIndependentUpgradeHistory(t *testing.T) {
	s := StoreSet{state: &storeState{features: &featureState{organization: &organizationState{dynamicRoles: true}}}}
	before, err := s.organizationRoleMigrationCatalog(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s.state.features.organization.directRoleBindings = true
	direct, err := s.organizationRoleMigrationCatalog(t.Context(), nil)
	if err != nil || len(direct) != len(before)+1 || !reflect.DeepEqual(direct[0], before[0]) {
		t.Fatal("direct bindings changed installed role prefix", err)
	}
	native, err := (organizationpg.RoleBindingRevokeOperationLookupMigrationSource{Version: 1}).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	lookup := direct[len(direct)-1]
	if lookup.namespace != "identity_organization_direct_bindings" || len(lookup.history) != 1 || lookup.history[0] != native[0] || lookup.owners[1] != "organization/postgres" || len(lookup.guards) != 1 {
		t.Fatal("direct binding lookup lost independent native owner")
	}
	// A deployment can select direct bindings before team roles, then enable
	// the existing optional role-history version 3 without inserting version 4
	// past a previously skipped team step.
	s.state.features.organization.teamRoleBindings = true
	withTeams, err := s.organizationRoleMigrationCatalog(t.Context(), nil)
	if err != nil || len(withTeams) != len(direct) || !reflect.DeepEqual(withTeams[1], lookup) || len(withTeams[0].history) != 3 {
		t.Fatal("later team selection rewrote direct lookup history", err)
	}
	for i := range before[0].history {
		if withTeams[0].history[i] != before[0].history[i] {
			t.Fatal("later team selection rewrote installed role migration")
		}
	}
}
