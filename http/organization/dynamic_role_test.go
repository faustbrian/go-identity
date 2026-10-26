package organizationhttp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	organization "github.com/faustbrian/go-organization"
)

type roleCRUDPort struct {
	*teamMembershipPort
	create   organization.CreateDynamicRoleOperationRequest
	update   organization.UpdateDynamicRoleOperationRequest
	delete   organization.DeleteDynamicRoleOperationRequest
	roleRead organization.DynamicRoleReadRequest
}

func (p *roleCRUDPort) CreateDynamicRole(ctx context.Context, r organization.CreateDynamicRoleOperationRequest, network string) (organization.StoreResult, error) {
	p.create, p.native.network = r, network
	return p.mutate(ctx, organization.CreateDynamicRole, r.Authentication, r.OrganizationID, "user-a", r.OrganizationVersion)
}
func (p *roleCRUDPort) UpdateDynamicRole(ctx context.Context, r organization.UpdateDynamicRoleOperationRequest, network string) (organization.StoreResult, error) {
	p.update, p.native.network = r, network
	return p.mutate(ctx, organization.UpdateDynamicRole, r.Authentication, r.OrganizationID, "user-a", r.OrganizationVersion)
}
func (p *roleCRUDPort) DeleteDynamicRole(ctx context.Context, r organization.DeleteDynamicRoleOperationRequest, network string) (organization.StoreResult, error) {
	p.delete, p.native.network = r, network
	return p.mutate(ctx, organization.DeleteDynamicRole, r.Authentication, r.OrganizationID, "user-a", r.OrganizationVersion)
}

const roleCreateBody = `{"organizationID":"organization-a","roleID":"reader","organizationVersion":7,"name":"Reader","statements":[{"permissionID":"read","resourceID":"document-a","effect":"allow"},{"permissionID":"read","resourceID":"document-b","effect":"deny"}]}`
const roleUpdateBody = `{"organizationID":"organization-a","roleID":"reader","organizationVersion":7,"roleVersion":3,"name":"Restricted reader","statements":[]}`
const roleDeleteBody = `{"organizationID":"organization-a","roleID":"reader","organizationVersion":7,"roleVersion":3}`

func roleCRUDSelection(c organizationhttp.Config, p *roleCRUDPort, op organization.Operation) organizationhttp.FeatureConfig {
	out := organizationhttp.FeatureConfig{Config: c}
	switch op {
	case organization.CreateDynamicRole:
		out.RoleCreate, out.Config.RoleCreator = true, p
	case organization.UpdateDynamicRole:
		out.RoleUpdate, out.Config.RoleUpdater = true, p
	case organization.DeleteDynamicRole:
		out.RoleDelete, out.Config.RoleDeleter = true, p
	}
	return out
}

func roleCRUDFixture(t testing.TB, op organization.Operation, configure ...func(*fixture, *roleCRUDPort)) (*fixture, *roleCRUDPort, http.Handler) {
	t.Helper()
	f := newFixture(t)
	p := &roleCRUDPort{teamMembershipPort: &teamMembershipPort{native: f.port}}
	f.c.Service, f.c.Invitations, f.c.SafeRate = nil, nil, nil
	for _, setup := range configure {
		setup(f, p)
	}
	feature, err := organizationhttp.NewFeature(roleCRUDSelection(f.c, p, op))
	if err != nil {
		t.Fatal(err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return f, p, h
}

func roleCRUDRequest(f *fixture, op organization.Operation, body string) *http.Request {
	path, keyed := "/v1/organization/role/create", true
	if op == organization.UpdateDynamicRole {
		path = "/v1/organization/role/update"
	}
	if op == organization.DeleteDynamicRole {
		path, keyed = "/v1/organization/role/delete", false
	}
	return request(f, path, body, keyed)
}

func TestRoleCRUDExactNativeIntentAndIndependentSelection(t *testing.T) {
	for _, tc := range []struct {
		op   organization.Operation
		body string
	}{{organization.CreateDynamicRole, roleCreateBody}, {organization.UpdateDynamicRole, roleUpdateBody}, {organization.DeleteDynamicRole, roleDeleteBody}} {
		t.Run(string(tc.op), func(t *testing.T) {
			f, p, h := roleCRUDFixture(t, tc.op)
			r := roleCRUDRequest(f, tc.op, tc.body)
			key, err := identity.NewIdempotencyKey([]byte(r.Header.Get("Idempotency-Key")))
			if tc.op != organization.DeleteDynamicRole && err != nil {
				t.Fatal(err)
			}
			sameKey := func(actual identity.IdempotencyKey) bool {
				left, leftErr := actual.Digest([32]byte{91})
				right, rightErr := key.Digest([32]byte{91})
				return leftErr == nil && rightErr == nil && left == right
			}
			w := serve(t, h, r)
			var out organizationhttp.MutationResponse
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.OrganizationID != "organization-a" || out.MemberID != "" || out.BeforeVersion != 7 || out.AfterVersion != 8 || out.Recovery == nil || out.Recovery.UserID != "user-a" {
				t.Fatal("native role outcome lost or fabricated a membership", tc.op, w.Code)
			}
			if p.native.calls != 1 || f.rate.calls != 1 || p.native.network != "198.51.100.7" {
				t.Fatal("wrong role admission/dispatch")
			}
			switch tc.op {
			case organization.CreateDynamicRole:
				want := []organization.RoleStatement{{PermissionID: "read", ResourceID: "document-a", Effect: authorization.Allow}, {PermissionID: "read", ResourceID: "document-b", Effect: authorization.Deny}}
				if p.create.Validate() != nil || p.create.RoleID != "reader" || p.create.OrganizationID != "organization-a" || p.create.OrganizationVersion != 7 || p.create.Name != "Reader" || !sameKey(p.create.IdempotencyKey) || p.create.Authentication.Bearer.Token() != f.wire || !reflect.DeepEqual(p.create.Statements, want) {
					t.Fatal("role creation changed exact intent")
				}
			case organization.UpdateDynamicRole:
				if p.update.Validate() != nil || p.update.RoleID != "reader" || p.update.OrganizationVersion != 7 || p.update.RoleVersion != 3 || p.update.Name != "Restricted reader" || p.update.Statements == nil || len(p.update.Statements) != 0 || !sameKey(p.update.IdempotencyKey) || p.update.Authentication.Bearer.Token() != f.wire {
					t.Fatal("role replacement changed deny-all intent")
				}
			case organization.DeleteDynamicRole:
				if p.delete.Validate() != nil || p.delete.RoleID != "reader" || p.delete.OrganizationVersion != 7 || p.delete.RoleVersion != 3 || p.delete.Authentication.Bearer.Token() != f.wire {
					t.Fatal("role deletion changed exact selectors")
				}
			}
		})
	}
}
