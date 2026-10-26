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
	var absent *OrganizationService
	leave := organization.LeaveMemberOperationRequest{Authentication: organization.Authentication{TenantID: "tenant"}, OrganizationID: "organization", OrganizationVersion: 1, CorrelationID: "leave"}
	if _, err := absent.LeaveMember(ctx, leave, "127.0.0.1"); !errors.As(err, &unavailable) {
		t.Fatal("absent self-leave handle reached native owner", err)
	}
	if _, err := handle.LeaveMember(ctx, leave, "127.0.0.1"); !errors.As(err, &unavailable) {
		t.Fatal("retained closed self-leave handle reached native owner", err)
	}
	list := organization.ListOrganizationsRequest{Authentication: organization.Authentication{TenantID: "tenant"}, Limit: 1, CorrelationID: "list"}
	if _, err := absent.ListOrganizations(ctx, list); !errors.As(err, &unavailable) {
		t.Fatal("absent list handle reached native owner", err)
	}
	if _, err := handle.ListOrganizations(ctx, list); !errors.As(err, &unavailable) {
		t.Fatal("retained closed list handle reached native owner", err)
	}
	if _, err := absent.SlugAvailable(ctx, organization.SlugAvailableRequest{Authentication: organization.Authentication{TenantID: "tenant"}, Slug: "candidate", CorrelationID: "slug"}); !errors.As(err, &unavailable) {
		t.Fatal("absent slug handle reached native owner", err)
	}
	if _, err := handle.SlugAvailable(ctx, organization.SlugAvailableRequest{Authentication: organization.Authentication{TenantID: "tenant"}, Slug: "candidate", CorrelationID: "slug"}); !errors.As(err, &unavailable) {
		t.Fatal("retained closed slug handle reached native owner", err)
	}
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

func TestOrganizationResendHandlesRetainGraphLifetimeGuards(t *testing.T) {
	var absent *OrganizationInvitationService
	var unavailable identity.UnavailableError
	request := organization.InvitationResendOperationRequest{Authentication: organization.Authentication{TenantID: "tenant"}}
	if _, err := absent.Resend(t.Context(), request, "127.0.0.1"); !errors.As(err, &unavailable) {
		t.Fatal("absent invitation handle reached native owner", err)
	}
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	state := &storeState{durable: true, lifetime: lifetime, cancel: cancel, drained: drained, tenants: map[string]*tenantRecovery{"tenant": {}}, features: &featureState{composed: true, ready: true, timeout: time.Second, organization: &organizationState{}}}
	handle := &OrganizationInvitationService{state: state}
	if err := (StoreSet{state: state}).Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := handle.Resend(t.Context(), request, "127.0.0.1"); !errors.As(err, &unavailable) {
		t.Fatal("retained closed invitation handle reached native owner", err)
	}
}

func TestOrganizationCancelHandlesRetainGraphLifetimeGuards(t *testing.T) {
	var absent *OrganizationInvitationService
	var unavailable identity.UnavailableError
	request := organization.InvitationCancelOperationRequest{Authentication: organization.Authentication{TenantID: "tenant"}}
	if _, err := absent.Cancel(t.Context(), request, "127.0.0.1"); !errors.As(err, &unavailable) {
		t.Fatal("absent cancellation handle reached native owner", err)
	}
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	state := &storeState{durable: true, lifetime: lifetime, cancel: cancel, drained: drained, tenants: map[string]*tenantRecovery{"tenant": {}}, features: &featureState{composed: true, ready: true, timeout: time.Second, organization: &organizationState{}}}
	handle := &OrganizationInvitationService{state: state}
	if err := (StoreSet{state: state}).Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := handle.Cancel(t.Context(), request, "127.0.0.1"); !errors.As(err, &unavailable) {
		t.Fatal("retained closed cancellation handle reached native owner", err)
	}
}

func TestOrganizationRejectHandlesRetainGraphLifetimeGuards(t *testing.T) {
	var absent *OrganizationInvitationService
	var unavailable identity.UnavailableError
	request := organization.InvitationRejectOperationRequest{Authentication: organization.Authentication{TenantID: "tenant"}}
	if _, err := absent.Reject(t.Context(), request, "127.0.0.1"); !errors.As(err, &unavailable) {
		t.Fatal("absent rejection handle reached native owner", err)
	}
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	state := &storeState{durable: true, lifetime: lifetime, cancel: cancel, drained: drained, tenants: map[string]*tenantRecovery{"tenant": {}}, features: &featureState{composed: true, ready: true, timeout: time.Second, organization: &organizationState{}}}
	handle := &OrganizationInvitationService{state: state}
	if err := (StoreSet{state: state}).Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := handle.Reject(t.Context(), request, "127.0.0.1"); !errors.As(err, &unavailable) {
		t.Fatal("retained closed rejection handle reached native owner", err)
	}
}
