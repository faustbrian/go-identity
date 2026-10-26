package reference

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// CreateDynamicRole delegates original-key role creation and immutable catalog
// validation to the native owner. Graph tenant, cancellation and drain guards
// apply before current native authorization and atomic effects.
func (f *OrganizationService) CreateDynamicRole(ctx context.Context, r organization.CreateDynamicRoleOperationRequest, network string) (organization.StoreResult, error) {
	if f == nil {
		return organization.StoreResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.StoreResult{}, err
	}
	defer done()
	return n.operations.CreateDynamicRole(w, r, network)
}

// UpdateDynamicRole delegates original-key replacement at exact role and
// organization epochs. Native catalog, deny precedence and history remain owned
// by the native service, not a second Reference policy engine.
func (f *OrganizationService) UpdateDynamicRole(ctx context.Context, r organization.UpdateDynamicRoleOperationRequest, network string) (organization.StoreResult, error) {
	if f == nil {
		return organization.StoreResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.StoreResult{}, err
	}
	defer done()
	return n.operations.UpdateDynamicRole(w, r, network)
}

// DeleteDynamicRole delegates natural terminal deletion and current-authorized
// original recovery. Absence never proves success; role IDs cannot revive.
func (f *OrganizationService) DeleteDynamicRole(ctx context.Context, r organization.DeleteDynamicRoleOperationRequest, network string) (organization.StoreResult, error) {
	if f == nil {
		return organization.StoreResult{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.StoreResult{}, err
	}
	defer done()
	return n.operations.DeleteDynamicRole(w, r, network)
}

// GetDynamicRole returns the selected current manager-only native snapshot,
// retaining native policy/session and graph lifetime/tenant guards.
func (f *OrganizationService) GetDynamicRole(ctx context.Context, r organization.DynamicRoleReadRequest) (organization.View, error) {
	if f == nil {
		return organization.View{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.View{}, err
	}
	defer done()
	return n.operations.GetDynamicRole(w, r)
}

// ListDynamicRoles returns a bounded current native role page. No snapshot or
// cursor extends authority; failures disclose no partial page.
func (f *OrganizationService) ListDynamicRoles(ctx context.Context, r organization.DynamicRoleReadRequest) (organization.View, error) {
	if f == nil {
		return organization.View{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return organization.View{}, err
	}
	defer done()
	return n.operations.ListDynamicRoles(w, r)
}

// CheckPermission evaluates only the authenticated native member's effective
// custom roles at the exact organization epoch. Static management roles grant
// no implicit application access; selected team bindings and deny precedence
// remain native-owned. This selects no HTTP permission endpoint.
func (f *OrganizationService) CheckPermission(ctx context.Context, r organization.PermissionCheckRequest) (authorization.Decision, error) {
	if f == nil {
		return authorization.Decision{}, identity.UnavailableError{}
	}
	w, done, n, err := enterOrganization(ctx, f.state, r.Authentication.TenantID, false)
	if err != nil {
		return authorization.Decision{}, err
	}
	defer done()
	return n.operations.CheckPermission(w, r)
}
