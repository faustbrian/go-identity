package reference

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func TestOrganizationSelectionAndRetainedHandlesFailClosed(t *testing.T) {
	ctx := t.Context()
	if owner, err := (FeatureSet{}).Organizations(); err == nil || owner != nil {
		t.Fatal("zero graph exposed organization owner")
	}
	if owner, err := (FeatureSet{}).OrganizationInvitations(); err == nil || owner != nil {
		t.Fatal("zero graph exposed invitation owner")
	}
	for _, c := range []StoreConfiguration{{Organization: &OrganizationConfiguration{}}, {HTTPOrganization: &HTTPOrganizationConfiguration{Create: true}}} {
		if graph, err := ComposeStores(c, ReferenceDependencies{}); err == nil || graph.state != nil {
			t.Fatal("selected organization accepted missing native owners")
		}
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
	if err := (StoreSet{state: state}).Close(ctx); err != nil {
		t.Fatal(err)
	}
	var unavailable identity.UnavailableError
	if _, err := handle.Get(ctx, organization.ReadRequest{Authentication: organization.Authentication{TenantID: "tenant"}}); !errors.As(err, &unavailable) {
		t.Fatal("retained closed handle reached native owner", err)
	}
	if _, err := handle.Update(ctx, organization.UpdateOperationRequest{Authentication: organization.Authentication{TenantID: "tenant"}}, "127.0.0.1"); !errors.As(err, &unavailable) {
		t.Fatal("retained closed metadata handle reached native owner", err)
	}
	if _, err := handle.UpdateMember(ctx, organization.UpdateMemberOperationRequest{Authentication: organization.Authentication{TenantID: "tenant"}}, "127.0.0.1"); !errors.As(err, &unavailable) {
		t.Fatal("retained closed member-update handle reached native owner", err)
	}
}
