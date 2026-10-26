package organizationhttp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	organization "github.com/faustbrian/go-organization"
)

func (p *roleCRUDPort) GetDynamicRole(ctx context.Context, r organization.DynamicRoleReadRequest) (organization.View, error) {
	return p.roleView(ctx, r, false)
}

func TestRoleReadRejectsClosedQueryBeforeAuthority(t *testing.T) {
	for _, op := range []organization.Operation{organization.GetDynamicRole, organization.ListDynamicRoles} {
		queries := []string{"", "organizationID=organization-a", "organizationID=organization-a&roleID=owner", "organizationID=organization-a&roleID=reader&roleID=other", "organizationID=organization-a&limit=0", "organizationID=organization-a&limit=01", "organizationID=organization-a&limit=101", "organizationID=organization-a&limit=1&limit=2", "organizationID=organization-a&limit=1&cursor=", "organizationID=organization-a&limit=1&targetUserID=other", "organizationID=organization-a&limit=1&tenantID=other", "organizationID=organization-a&roleID=reader&commandID=other", "organizationID=organization-a&roleID=reader&limit=1", "organizationID=organization-a&limit=1&roleID=reader", "organizationID=organization-a&limit=+1", "organizationID=organization-a&limit=1&cursor=%00", "organizationID=organization-a&limit=1&bad=%xx"}
		for _, query := range queries {
			f, p, h := roleReadFixture(t, op)
			r := roleReadRequest(f, op)
			r.URL.RawQuery = query
			r.RequestURI = r.URL.RequestURI()
			if w := serve(t, h, r); w.Code != 400 || p.native.calls != 0 || f.reads.Load() != 0 {
				t.Fatal("invalid role query reached authority", op, query, w.Code)
			}
		}
	}
}

func TestRoleReadWithholdsEntireMalformedOrLateResult(t *testing.T) {
	for _, op := range []organization.Operation{organization.GetDynamicRole, organization.ListDynamicRoles} {
		for _, mode := range []string{"tenant", "organization", "actor", "inactive", "nonmanager", "org-epoch", "role-tenant", "role-org", "static", "role-epoch", "name", "effect", "resource", "duplicate", "budget", "count", "wrong-id", "order", "cursor", "expired", "cancelled", "forbidden", "unavailable"} {
			t.Run(string(op)+"/"+mode, func(t *testing.T) {
				f, p, h := roleReadFixture(t, op)
				r := roleReadRequest(f, op)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				r = r.WithContext(ctx)
				p.changeView = func(v *organization.View) {
					role := &v.DynamicRole
					if op == organization.ListDynamicRoles {
						role = &v.DynamicRoles[0]
					}
					switch mode {
					case "tenant":
						v.Organization.TenantID = "other"
					case "organization":
						v.Organization.ID = "other"
					case "actor":
						v.Actor.UserID = "other"
					case "inactive":
						v.Actor.Active = false
					case "nonmanager":
						v.Actor.Role = organization.RoleMember
					case "org-epoch":
						v.Organization.Version = 0
					case "role-tenant":
						role.TenantID = "other"
					case "role-org":
						role.OrganizationID = "other"
					case "static":
						role.ID = "owner"
					case "role-epoch":
						role.Version = 0
					case "name":
						role.Name = "bad\nname"
					case "effect":
						role.Statements[0].Effect = authorization.NotApplicable
					case "resource":
						role.Statements[0].ResourceID = "*"
					case "duplicate":
						role.Statements = append(role.Statements, role.Statements[0])
					case "budget":
						role.Statements = nil
						for i := 0; i < 64; i++ {
							role.Statements = append(role.Statements, organization.RoleStatement{PermissionID: "permission-" + strings.Repeat("p", 110), ResourceID: authorization.ResourceID("resource-" + strings.Repeat("r", 110) + strconv.Itoa(i)), Effect: authorization.Allow})
						}
					case "count":
						role.Statements = make([]organization.RoleStatement, 65)
					case "wrong-id":
						if op == organization.ListDynamicRoles {
							role.ID = "a"
						} else {
							role.ID = "other"
						}
					case "order":
						if op == organization.ListDynamicRoles {
							v.DynamicRoles = append(v.DynamicRoles, *role)
						} else {
							role.ID = "other"
						}
					case "cursor":
						if op == organization.ListDynamicRoles {
							v.NextRoleCursor = "foreign"
						} else {
							role.ID = "other"
						}
					case "expired":
						f.now = f.now.Add(20 * time.Second)
					case "cancelled":
						cancel()
					case "forbidden":
						p.native.err = organization.ErrForbidden
					case "unavailable":
						p.native.err = organization.ErrUnavailable
					}
				}
				// Native errors are captured before the projection callback runs.
				if mode == "forbidden" {
					p.native.err = organization.ErrForbidden
				}
				if mode == "unavailable" {
					p.native.err = organization.ErrUnavailable
				}
				w := serve(t, h, r)
				want := 503
				if mode == "forbidden" {
					want = 403
				}
				if w.Code != want || p.native.calls != 1 || strings.Contains(w.Body.String(), `"role"`) || strings.Contains(w.Body.String(), `"roles"`) || strings.Contains(w.Body.String(), "document-a") {
					t.Fatal("malformed or late role result disclosed", w.Code)
				}
			})
		}
	}
}

func TestRoleReadEmptyStatementsAndEmptyPageAreArrays(t *testing.T) {
	for _, op := range []organization.Operation{organization.GetDynamicRole, organization.ListDynamicRoles} {
		f, p, h := roleReadFixture(t, op)
		p.changeView = func(v *organization.View) { v.DynamicRole.Statements = nil; v.DynamicRoles, v.NextRoleCursor = nil, "" }
		w := serve(t, h, roleReadRequest(f, op))
		field := `"statements":[]`
		if op == organization.ListDynamicRoles {
			field = `"roles":[]`
		}
		if w.Code != 200 || !strings.Contains(w.Body.String(), field) {
			t.Fatal("empty role data was not an array", w.Code)
		}
	}
}
func (p *roleCRUDPort) ListDynamicRoles(ctx context.Context, r organization.DynamicRoleReadRequest) (organization.View, error) {
	return p.roleView(ctx, r, true)
}
func (p *roleCRUDPort) roleView(ctx context.Context, r organization.DynamicRoleReadRequest, page bool) (organization.View, error) {
	p.roleRead = r
	out, err := p.native.read(ctx, organization.ReadRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID})
	role := organization.DynamicRole{ID: "reader", OrganizationID: r.OrganizationID, TenantID: r.Authentication.TenantID, Name: "Reader", Version: 3, Statements: []organization.RoleStatement{{PermissionID: "read", ResourceID: "document-a", Effect: authorization.Allow}, {PermissionID: "read", ResourceID: "document-b", Effect: authorization.Deny}}}
	if page {
		out.DynamicRoles, out.NextRoleCursor = []organization.DynamicRole{role}, "reader"
	} else {
		out.DynamicRole = role
	}
	if p.changeView != nil {
		p.changeView(&out)
	}
	return out, err
}

func roleReadFixture(t testing.TB, op organization.Operation) (*fixture, *roleCRUDPort, http.Handler) {
	t.Helper()
	f := newFixture(t)
	p := &roleCRUDPort{teamMembershipPort: &teamMembershipPort{native: f.port}}
	f.c.Service, f.c.Invitations, f.c.AdminRate = nil, nil, nil
	c := organizationhttp.FeatureConfig{Config: f.c}
	if op == organization.GetDynamicRole {
		c.RoleGet, c.Config.RoleGetter = true, p
	} else {
		c.RoleList, c.Config.RoleLister = true, p
	}
	feature, err := organizationhttp.NewFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return f, p, h
}

func roleReadRequest(f *fixture, op organization.Operation) *http.Request {
	path := "/v1/organization/role/get?organizationID=organization-a&roleID=reader"
	if op == organization.ListDynamicRoles {
		path = "/v1/organization/role/list?organizationID=organization-a&limit=1&cursor=a"
	}
	return request(f, path, "", false)
}

func TestRoleReadExactNativeProjectionAndSelection(t *testing.T) {
	for _, op := range []organization.Operation{organization.GetDynamicRole, organization.ListDynamicRoles} {
		t.Run(string(op), func(t *testing.T) {
			f, p, h := roleReadFixture(t, op)
			w := serve(t, h, roleReadRequest(f, op))
			var role organizationhttp.DynamicRoleView
			if op == organization.GetDynamicRole {
				var out organizationhttp.RoleResponse
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.OrganizationVersion != 3 {
					t.Fatal("native role read projection", w.Code)
				}
				role = out.Role
				if p.roleRead.RoleID != "reader" || p.roleRead.Limit != 0 || p.roleRead.Cursor != "" {
					t.Fatal("exact role selector changed")
				}
			} else {
				var out organizationhttp.RoleListResponse
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.OrganizationVersion != 3 || len(out.Roles) != 1 || out.NextCursor != "reader" {
					t.Fatal("native role page projection", w.Code)
				}
				role = out.Roles[0]
				if p.roleRead.RoleID != "" || p.roleRead.Limit != 1 || p.roleRead.Cursor != "a" {
					t.Fatal("role page bounds changed")
				}
			}
			if role.ID != "reader" || role.Name != "Reader" || role.Version != 3 || len(role.Statements) != 2 || role.Statements[0].PermissionID != "read" || role.Statements[0].ResourceID != "document-a" || role.Statements[0].Effect != "allow" || role.Statements[1].Effect != "deny" {
				t.Fatal("role statements/order changed")
			}
			if p.native.calls != 1 || f.rate.calls != 0 || p.roleRead.OrganizationID != "organization-a" || p.roleRead.Authentication.Bearer.Token() != f.wire || p.roleRead.TargetUserID != "" || p.roleRead.TargetTeamID != "" {
				t.Fatal("role read owner/scope changed")
			}
		})
	}
}
