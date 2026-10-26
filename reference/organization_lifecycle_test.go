package reference

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func TestOrganizationLifecycleRetainsGraphGuards(t *testing.T) {
	var absent *OrganizationService
	var unavailable identity.UnavailableError
	r := organization.LifecycleOperationRequest{Authentication: organization.Authentication{TenantID: "tenant"}}
	read := organization.ReadRequest{Authentication: r.Authentication}
	check := func(h *OrganizationService) {
		t.Helper()
		if _, err := h.Archive(t.Context(), r, "127.0.0.1"); !errors.As(err, &unavailable) {
			t.Fatal("absent/closed archive reached owner", err)
		}
		if _, err := h.Restore(t.Context(), r, "127.0.0.1"); !errors.As(err, &unavailable) {
			t.Fatal("absent/closed restore reached owner", err)
		}
		if _, err := h.GetLifecycle(t.Context(), read); !errors.As(err, &unavailable) {
			t.Fatal("absent/closed lifecycle read reached owner", err)
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
