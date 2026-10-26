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

func TestOrganizationExpiryRetainsGraphLifetime(t *testing.T) {
	var absent *OrganizationInvitationService
	var unavailable identity.UnavailableError
	r := organization.InvitationExpireOperationRequest{Authentication: organization.Authentication{TenantID: "tenant"}}
	if _, err := absent.Expire(t.Context(), r, "127.0.0.1"); !errors.As(err, &unavailable) {
		t.Fatal("absent expiry reached native owner", err)
	}
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	state := &storeState{durable: true, lifetime: lifetime, cancel: cancel, drained: drained, tenants: map[string]*tenantRecovery{"tenant": {}}, features: &featureState{composed: true, ready: true, timeout: time.Second, organization: &organizationState{invitations: &organizationpg.InvitationService{}}}}
	handle, err := (FeatureSet{state: state}).OrganizationInvitations()
	if err != nil {
		t.Fatal(err)
	}
	if err := (StoreSet{state: state}).Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := handle.Expire(t.Context(), r, "127.0.0.1"); !errors.As(err, &unavailable) {
		t.Fatal("closed expiry reached native owner", err)
	}
}
