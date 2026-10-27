package reference

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// AssignTeamDynamicRole preserves the native original key and exact team/role
// epochs under current human manager authority. Select TeamRoleBindings before
// use. Network is the trusted canonical client IP; no HTTP mutation is enabled.
func (f *OrganizationService) AssignTeamDynamicRole(ctx context.Context, r organization.AssignTeamDynamicRoleOperationRequest, network string) (organization.StoreResult, error) {
	if f == nil {
		return organization.StoreResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.StoreResult{}, err
	}
	defer done()
	if !n.teamRoleOperations {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	return n.operations.AssignTeamDynamicRole(w, r, network)
}

// RevokeTeamDynamicRole delegates natural exact-binding revocation and original
// recovery without caller commands, keys or team impersonation. TeamRoleBindings
// selects its independent native lookup history; current human/query authority
// and graph lifetime/tenant guards remain mandatory. Absence is not success.
func (f *OrganizationService) RevokeTeamDynamicRole(ctx context.Context, r organization.RevokeTeamDynamicRoleOperationRequest, network string) (organization.StoreResult, error) {
	if f == nil {
		return organization.StoreResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.StoreResult{}, err
	}
	defer done()
	if !n.teamRoleOperations {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	return n.operations.RevokeTeamDynamicRole(w, r, network)
}
