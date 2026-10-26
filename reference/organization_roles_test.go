package reference

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func TestOrganizationRolesRetainGraphGuards(t *testing.T) {
	var absent *OrganizationService
	var unavailable identity.UnavailableError
	a := organization.Authentication{TenantID: "tenant"}
	check := func(h *OrganizationService) {
		t.Helper()
		if _, err := h.CreateDynamicRole(t.Context(), organization.CreateDynamicRoleOperationRequest{Authentication: a}, "127.0.0.1"); !errors.As(err, &unavailable) {
			t.Fatal("absent/closed role creator reached owner", err)
		}
		if _, err := h.UpdateDynamicRole(t.Context(), organization.UpdateDynamicRoleOperationRequest{Authentication: a}, "127.0.0.1"); !errors.As(err, &unavailable) {
			t.Fatal("absent/closed role updater reached owner", err)
		}
		if _, err := h.DeleteDynamicRole(t.Context(), organization.DeleteDynamicRoleOperationRequest{Authentication: a}, "127.0.0.1"); !errors.As(err, &unavailable) {
			t.Fatal("absent/closed role deleter reached owner", err)
		}
		if _, err := h.GetDynamicRole(t.Context(), organization.DynamicRoleReadRequest{Authentication: a}); !errors.As(err, &unavailable) {
			t.Fatal("absent/closed exact role read reached owner", err)
		}
		if _, err := h.ListDynamicRoles(t.Context(), organization.DynamicRoleReadRequest{Authentication: a}); !errors.As(err, &unavailable) {
			t.Fatal("absent/closed role page reached owner", err)
		}
		if _, err := h.CheckPermission(t.Context(), organization.PermissionCheckRequest{Authentication: a}); !errors.As(err, &unavailable) {
			t.Fatal("absent/closed permission read reached owner", err)
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
