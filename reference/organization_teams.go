package reference

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// CreateTeam delegates original-key creation of an empty native team. It grants
// no organization roles, and does not select an HTTP team-creation route.
// Configured tenant, initialization, bounded context and graph shutdown guards
// apply before the native current-authority and atomic transaction owners.
func (f *OrganizationService) CreateTeam(ctx context.Context, r organization.CreateTeamOperationRequest, network string) (organization.StoreResult, error) {
	if f == nil {
		return organization.StoreResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.StoreResult{}, err
	}
	defer done()
	return n.operations.CreateTeam(w, r, network)
}

// AddTeamMember delegates exact original-key admission through the selected
// native owner. Current team-write/session authority and protected effects stay
// native-owned; matching recovery never renews authority or executes again.
func (f *OrganizationService) AddTeamMember(ctx context.Context, r organization.AddTeamMemberOperationRequest, network string) (organization.StoreResult, error) {
	if f == nil {
		return organization.StoreResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.StoreResult{}, err
	}
	defer done()
	return n.operations.AddTeamMember(w, r, network)
}

// RemoveTeamMember delegates naturally repeated exact-binding removal. Only
// original correlated native history establishes success; missing bindings do
// not. Organization readmission cannot revive old team authority. The graph
// retains its tenant, initialization and lifetime guards on every call.
func (f *OrganizationService) RemoveTeamMember(ctx context.Context, r organization.RemoveTeamMemberOperationRequest, network string) (organization.StoreResult, error) {
	if f == nil {
		return organization.StoreResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.StoreResult{}, err
	}
	defer done()
	return n.operations.RemoveTeamMember(w, r, network)
}

// ListMyTeams returns the authenticated human's current bounded native page.
// It accepts no alternate subject and grants no cached authorization lease.
// Calls join graph tenant, initialization, cancellation and shutdown guards.
func (f *OrganizationService) ListMyTeams(ctx context.Context, r organization.TeamReadRequest) (organization.View, error) {
	if f == nil {
		return organization.View{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.View{}, err
	}
	defer done()
	return n.operations.ListMyTeams(w, r)
}

// ListTeamMembers delegates current native team authorization and exact
// organization-admission filtering, retaining bounded pagination and graph
// lifetime/tenant guards. Failures return no page and never extend freshness.
func (f *OrganizationService) ListTeamMembers(ctx context.Context, r organization.TeamReadRequest) (organization.View, error) {
	if f == nil {
		return organization.View{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.View{}, err
	}
	defer done()
	return n.operations.ListTeamMembers(w, r)
}
