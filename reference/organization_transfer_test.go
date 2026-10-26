package reference

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func TestOrganizationTransferRetainsGraphGuards(t *testing.T) {
	var absent *OrganizationService
	var unavailable identity.UnavailableError
	r := organization.OwnerTransferOperationRequest{Authentication: organization.Authentication{TenantID: "tenant"}}
	if _, err := absent.OwnerTransfer(t.Context(), r, "127.0.0.1"); !errors.As(err, &unavailable) {
		t.Fatal("absent transfer handle reached native owner", err)
	}
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
	if _, err := handle.OwnerTransfer(t.Context(), r, "127.0.0.1"); !errors.As(err, &unavailable) {
		t.Fatal("closed transfer handle reached native owner", err)
	}
}
