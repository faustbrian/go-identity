package reference

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// AssignDynamicRole preserves the native original key, exact role/member epochs
// and current manager/session authority. Select DirectRoleBindings before use.
// Network is the trusted canonical client IP; this enables no HTTP mutation.
func (f *OrganizationService) AssignDynamicRole(ctx context.Context, r organization.AssignDynamicRoleOperationRequest, network string) (organization.StoreResult, error) {
	if f == nil {
		return organization.StoreResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.StoreResult{}, err
	}
	defer done()
	if !n.directRoleBindings {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	return n.operations.AssignDynamicRole(w, r, network)
}

// RevokeDynamicRole delegates natural exact-binding revocation and original
// recovery without caller commands or keys. DirectRoleBindings installs the
// optional native lookup history; absence alone never proves prior success.
// Native current authority and graph tenant/lifetime guards remain mandatory.
func (f *OrganizationService) RevokeDynamicRole(ctx context.Context, r organization.RevokeDynamicRoleOperationRequest, network string) (organization.StoreResult, error) {
	if f == nil {
		return organization.StoreResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.StoreResult{}, err
	}
	defer done()
	if !n.directRoleBindings {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	return n.operations.RevokeDynamicRole(w, r, network)
}
