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

// UpdateTeam delegates original-key exact-epoch rename without changing team
// bindings. Native current action/session/query authority and transaction
// ownership remain authoritative; calls retain graph tenant/lifetime guards.
func (f *OrganizationService) UpdateTeam(ctx context.Context, r organization.UpdateTeamOperationRequest, network string) (organization.StoreResult, error) {
	if f == nil {
		return organization.StoreResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.StoreResult{}, err
	}
	defer done()
	return n.operations.UpdateTeam(w, r, network)
}

// DeleteTeam delegates naturally repeated exact-version terminal deletion.
// Only native original history proves prior success; retired IDs and bindings
// cannot revive. Current authority and graph guards apply to every recovery.
func (f *OrganizationService) DeleteTeam(ctx context.Context, r organization.DeleteTeamOperationRequest, network string) (organization.StoreResult, error) {
	if f == nil {
		return organization.StoreResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.StoreResult{}, err
	}
	defer done()
	return n.operations.DeleteTeam(w, r, network)
}

// GetTeam returns the selected exact manager-only native snapshot. It exposes
// no HTTP route or reusable authority. Native team-read/session/lifecycle
// policy and graph initialization, tenant, cancellation and drain guards apply.
func (f *OrganizationService) GetTeam(ctx context.Context, r organization.TeamReadRequest) (organization.View, error) {
	if f == nil {
		return organization.View{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.View{}, err
	}
	defer done()
	return n.operations.GetTeam(w, r)
}

// ListTeams returns a bounded current manager-only native page, not a cached
// authorization lease. Current team-read policy and graph tenant/lifetime
// guards remain required; failures disclose no partial page.
func (f *OrganizationService) ListTeams(ctx context.Context, r organization.TeamReadRequest) (organization.View, error) {
	if f == nil {
		return organization.View{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.View{}, err
	}
	defer done()
	if n.teamsNative == nil {
		return organization.View{}, identity.UnavailableError{}
	}
	return n.teamsNative.ListTeams(w, r)
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
