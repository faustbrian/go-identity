package reference

import (
	"context"
	"fmt"
	"io"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// OrganizationService exposes selected native organization operations without
// concrete stores. Calls join graph initialization, tenant and shutdown guards;
// independent calls are concurrent-safe. Recovery only reads original outcomes.
type OrganizationService struct{ state *storeState }

// OrganizationInvitationService exposes selected native invitation operations.
// It owns no provider, journal or lifetime separate from this graph. Copies
// share immutable configuration; independent calls are concurrent-safe.
type OrganizationInvitationService struct{ state *storeState }

// Organizations returns the selected explicit-organization membership owner.
// It performs no IO and never enables HTTP.
func (f FeatureSet) Organizations() (*OrganizationService, error) {
	if err := organizationSelected(f.state, false); err != nil {
		return nil, err
	}
	return &OrganizationService{state: f.state}, nil
}

// OrganizationInvitations returns the selected native invitation owner without
// enabling HTTP or exposing capability/delivery stores.
func (f FeatureSet) OrganizationInvitations() (*OrganizationInvitationService, error) {
	if err := organizationSelected(f.state, true); err != nil {
		return nil, err
	}
	return &OrganizationInvitationService{state: f.state}, nil
}

func organizationSelected(s *storeState, invitations bool) error {
	if s == nil {
		return identity.InvalidInputError{Field: "reference_organization"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.organization == nil || invitations && s.features.organization.invitations == nil {
		return identity.UnavailableError{}
	}
	return nil
}
func enterOrganization(ctx context.Context, s *storeState, tenant identity.TenantID, invitations bool) (context.Context, func(), *organizationState, error) {
	if err := organizationSelected(s, invitations); err != nil {
		return nil, nil, nil, err
	}
	bounded, done, err := (composedPasswordReset{state: s}).enter(ctx, tenant)
	if err != nil {
		return nil, nil, nil, err
	}
	return bounded, done, s.features.organization, nil
}

// Format redacts borrowed graph and custody configuration.
func (OrganizationService) Format(s fmt.State, _ rune) {
	io.WriteString(s, "reference.OrganizationService(redacted)")
}

// MarshalJSON prevents serialization of an owning service handle.
func (OrganizationService) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// MarshalText prevents serialization of an owning service handle.
func (OrganizationService) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// Format redacts borrowed invitation and capability owners.
func (OrganizationInvitationService) Format(s fmt.State, _ rune) {
	io.WriteString(s, "reference.OrganizationInvitationService(redacted)")
}

// MarshalJSON prevents serialization of an owning service handle.
func (OrganizationInvitationService) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// MarshalText prevents serialization of an owning service handle.
func (OrganizationInvitationService) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// Create preserves the native original initiating key and current authority.
func (f *OrganizationService) Create(ctx context.Context, r organization.CreateOperationRequest, network string) (organization.StoreResult, error) {
	if f == nil {
		return organization.StoreResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.StoreResult{}, err
	}
	defer done()
	return n.operations.Create(w, r, network)
}

// Update replaces exact-version metadata under native current administrator
// authority, preserving original-key recovery and graph lifetime guards.
func (f *OrganizationService) Update(ctx context.Context, r organization.UpdateOperationRequest, network string) (organization.StoreResult, error) {
	if f == nil {
		return organization.StoreResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.StoreResult{}, err
	}
	defer done()
	return n.operations.Update(w, r, network)
}

// UpdateMember delegates exact-version static-role replacement and native
// last-owner protection without renewing original command or authority custody.
func (f *OrganizationService) UpdateMember(ctx context.Context, r organization.UpdateMemberOperationRequest, network string) (organization.StoreResult, error) {
	if f == nil {
		return organization.StoreResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.StoreResult{}, err
	}
	defer done()
	return n.operations.UpdateMember(w, r, network)
}

// AddMember preserves exact target/version intent and original-key recovery.
func (f *OrganizationService) AddMember(ctx context.Context, r organization.AddMemberOperationRequest, network string) (organization.StoreResult, error) {
	if f == nil {
		return organization.StoreResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.StoreResult{}, err
	}
	defer done()
	return n.operations.AddMember(w, r, network)
}

// RemoveMember delegates repeat removal and native last-owner protection.
func (f *OrganizationService) RemoveMember(ctx context.Context, r organization.RemoveMemberOperationRequest, network string) (organization.StoreResult, error) {
	if f == nil {
		return organization.StoreResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.StoreResult{}, err
	}
	defer done()
	return n.operations.RemoveMember(w, r, network)
}

// Get reads current explicitly scoped organization metadata.
func (f *OrganizationService) Get(ctx context.Context, r organization.ReadRequest) (organization.View, error) {
	if f == nil {
		return organization.View{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.View{}, err
	}
	defer done()
	return n.operations.Get(w, r)
}

// ListMembers reads the native bounded current membership page.
func (f *OrganizationService) ListMembers(ctx context.Context, r organization.ReadRequest) (organization.View, error) {
	if f == nil {
		return organization.View{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.View{}, err
	}
	defer done()
	return n.operations.ListMembers(w, r)
}

// RecoverOperation reads the exact original native command, never resubmits.
func (f *OrganizationService) RecoverOperation(ctx context.Context, r organization.OperationRecoveryRequest) (organization.StoreResult, error) {
	if f == nil {
		return organization.StoreResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.StoreResult{}, err
	}
	defer done()
	return n.operations.RecoverOperation(w, r)
}

// Send uses the existing native original-key invitation/delivery owner.
func (f *OrganizationInvitationService) Send(ctx context.Context, r organization.InvitationSendOperationRequest, network string) (organization.StoreResult, error) {
	if f == nil {
		return organization.StoreResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, true)
	if err != nil {
		return organization.StoreResult{}, err
	}
	defer done()
	return n.sender.Send(w, r, network)
}

// Resend retains the original initiating key, recipient and exclusive deadline
// through the existing native successor/delivery owner. Matching retries return
// original metadata only, including after later resends or acceptance. Graph
// lifetime and tenant guards do not replace native current security checks.
func (f *OrganizationInvitationService) Resend(ctx context.Context, r organization.InvitationResendOperationRequest, network string) (organization.InvitationResendOperationResult, error) {
	if f == nil {
		return organization.InvitationResendOperationResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, true)
	if err != nil {
		return organization.InvitationResendOperationResult{}, err
	}
	defer done()
	return n.sender.Resend(w, r, network)
}

// Cancel uses native exact-version manager cancellation and original natural-
// repeat recovery. It requires no recipient credential or proof. Graph lifetime
// and tenant guards remain separate from current native action authority.
func (f *OrganizationInvitationService) Cancel(ctx context.Context, r organization.InvitationCancelOperationRequest, network string) (organization.StoreResult, error) {
	if f == nil {
		return organization.StoreResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, true)
	if err != nil {
		return organization.StoreResult{}, err
	}
	defer done()
	return n.invitations.Cancel(w, r, network)
}

// Get retains native owner-only current invitation disclosure.
func (f *OrganizationInvitationService) Get(ctx context.Context, r organization.InvitationReadRequest) (organization.InvitationDelivery, error) {
	if f == nil {
		return organization.InvitationDelivery{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, true)
	if err != nil {
		return organization.InvitationDelivery{}, err
	}
	defer done()
	return n.invitations.Get(w, r)
}

// ListMine reads the authenticated verified recipient's bounded invitations.
func (f *OrganizationInvitationService) ListMine(ctx context.Context, r organization.InvitationListMineRequest) (organization.InvitationListMineResult, error) {
	if f == nil {
		return organization.InvitationListMineResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, true)
	if err != nil {
		return organization.InvitationListMineResult{}, err
	}
	defer done()
	return n.invitations.ListMine(w, r)
}

// RecoverAccept queries retained original scope with current authority.
func (f *OrganizationInvitationService) RecoverAccept(ctx context.Context, r organization.InvitationAcceptRecoveryRequest) (organization.StoreResult, error) {
	if f == nil {
		return organization.StoreResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, true)
	if err != nil {
		return organization.StoreResult{}, err
	}
	defer done()
	return n.invitations.RecoverAccept(w, r)
}

// PrepareAcceptance retains the exact native preparation across admission and
// execution. The returned opaque handle must be used serially, not concurrently.
// Admission performs no IO; Execute rejoins the graph without renewing custody.
func (f *OrganizationInvitationService) PrepareAcceptance(ctx context.Context, r organization.InvitationAcceptRequest, network string) (organization.PreparedInvitationAcceptance, error) {
	if f == nil {
		return nil, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, true)
	if err != nil {
		return nil, err
	}
	defer done()
	prepared, err := n.invitations.PrepareAcceptance(w, r, network)
	if err != nil {
		return nil, err
	}
	return &organizationPreparedAcceptance{state: f.state, tenant: r.Authentication.TenantID, native: prepared}, nil
}

type organizationPreparedAcceptance struct {
	state  *storeState
	tenant identity.TenantID
	native organization.PreparedInvitationAcceptance
}

func (p *organizationPreparedAcceptance) Admission() (organization.InvitationAcceptAdmission, error) {
	if p == nil || p.native == nil {
		return organization.InvitationAcceptAdmission{}, identity.UnavailableError{}
	}
	if err := organizationSelected(p.state, true); err != nil {
		return organization.InvitationAcceptAdmission{}, err
	}
	return p.native.Admission()
}
func (p *organizationPreparedAcceptance) Execute(ctx context.Context) (organization.StoreResult, error) {
	if p == nil || p.native == nil {
		return organization.StoreResult{}, identity.UnavailableError{}
	}
	w, done, _, err := enterOrganization(ctx, p.state, p.tenant, true)
	if err != nil {
		return organization.StoreResult{}, err
	}
	defer done()
	return p.native.Execute(w)
}
func (organizationPreparedAcceptance) Format(s fmt.State, _ rune) {
	io.WriteString(s, "reference.PreparedInvitationAcceptance(redacted)")
}
func (organizationPreparedAcceptance) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}
func (organizationPreparedAcceptance) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}
