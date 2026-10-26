package organizationhttp_test

import (
	"encoding/json"
	"strings"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	organization "github.com/faustbrian/go-organization"
)

func TestRoleCRUDWireMatchesActualNativeOutcomes(t *testing.T) {
	for _, tc := range []struct {
		op   organization.Operation
		body string
	}{{organization.CreateDynamicRole, roleCreateBody}, {organization.UpdateDynamicRole, roleUpdateBody}, {organization.DeleteDynamicRole, roleDeleteBody}, {organization.GetDynamicRole, ""}, {organization.ListDynamicRoles, ""}} {
		t.Run(string(tc.op), func(t *testing.T) {
			f := newFixture(t)
			p := &roleCRUDPort{teamMembershipPort: &teamMembershipPort{native: f.port}}
			c := roleCRUDSelection(f.c, p, tc.op)
			if tc.op == organization.GetDynamicRole {
				c.RoleGet, c.Config.RoleGetter = true, p
			}
			if tc.op == organization.ListDynamicRoles {
				c.RoleList, c.Config.RoleLister = true, p
			}
			feature, err := organizationhttp.NewFeature(c)
			if err != nil {
				t.Fatal(err)
			}
			h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Role CRUD", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
			if err != nil {
				t.Fatal(err)
			}
			r := roleCRUDRequest(f, tc.op, tc.body)
			if tc.op == organization.GetDynamicRole || tc.op == organization.ListDynamicRoles {
				r = roleReadRequest(f, tc.op)
			}
			w := serve(t, h, r)
			if w.Code != 200 || len(doc.Operations()) != 1 {
				t.Fatal("selected role operation missing", w.Code)
			}
			var wire struct {
				Paths map[string]map[string]struct {
					Parameters []struct {
						Name, In string
						Required bool
					}
					Description string
				}
			}
			if json.Unmarshal(doc.JSON(), &wire) != nil {
				t.Fatal("invalid role wire document")
			}
			operation := wire.Paths[r.URL.Path][strings.ToLower(r.Method)]
			keyed := tc.op == organization.CreateDynamicRole || tc.op == organization.UpdateDynamicRole
			found := false
			for _, p := range operation.Parameters {
				if p.In == "header" && p.Name == "Idempotency-Key" {
					if !p.Required {
						t.Fatal("optional key advertised")
					}
					found = true
				}
			}
			if found != keyed || strings.Contains(operation.Description, "Idempotency-Key and all alternate request-key channels are forbidden.") == keyed {
				t.Fatal("role wire key requirement contradicts runtime", tc.op)
			}
			if tc.body != "" && !requestConforms(t, doc.JSON(), r.URL.Path, tc.body) {
				t.Fatal("actual role request violates selected wire")
			}
			assertWireResponse(t, doc.JSON(), r, w)
		})
	}
}
