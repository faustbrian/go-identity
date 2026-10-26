package organizationhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	organization "github.com/faustbrian/go-organization"
)

func TestRoleCRUDClosedMutationInputs(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"tenant", strings.Replace(roleCreateBody, "{", `{"tenantID":"tenant-b",`, 1)},
		{"actor", strings.Replace(roleCreateBody, "{", `{"actorID":"other-user",`, 1)},
		{"command", strings.Replace(roleCreateBody, "{", `{"commandID":"abcdefghijklmnopqrstuv",`, 1)},
		{"key-body", strings.Replace(roleCreateBody, "{", `{"idempotencyKey":"other-key",`, 1)},
		{"external-statements", strings.Replace(roleCreateBody, `"statements":`, `"statementIDs":`, 1)},
		{"missing-name", strings.Replace(roleCreateBody, `"name":"Reader",`, "", 1)},
		{"null-statements", strings.Replace(roleUpdateBody, `"statements":[]`, `"statements":null`, 1)},
		{"object-statements", strings.Replace(roleUpdateBody, `"statements":[]`, `"statements":{}`, 1)},
		{"static-role", strings.Replace(roleCreateBody, `"roleID":"reader"`, `"roleID":"owner"`, 1)},
		{"zero-org", strings.Replace(roleCreateBody, `"organizationVersion":7`, `"organizationVersion":0`, 1)},
		{"overflow-org", strings.Replace(roleCreateBody, `"organizationVersion":7`, `"organizationVersion":18446744073709551616`, 1)},
		{"terminal-org", strings.Replace(roleCreateBody, `"organizationVersion":7`, `"organizationVersion":18446744073709551615`, 1)},
		{"float-org", strings.Replace(roleCreateBody, `"organizationVersion":7`, `"organizationVersion":7.0`, 1)},
		{"duplicate-nested", strings.Replace(roleCreateBody, `"effect":"allow"`, `"effect":"allow","Effect":"deny"`, 1)},
		{"unknown-nested", strings.Replace(roleCreateBody, `"effect":"allow"`, `"effect":"allow","condition":"always"`, 1)},
		{"null-nested", strings.Replace(roleCreateBody, `"permissionID":"read"`, `"permissionID":null`, 1)},
		{"numeric-effect", strings.Replace(roleCreateBody, `"effect":"allow"`, `"effect":1`, 1)},
		{"default-effect", strings.Replace(roleCreateBody, `"effect":"allow"`, `"effect":"not-applicable"`, 1)},
		{"wildcard-resource", strings.Replace(roleCreateBody, `"resourceID":"document-a"`, `"resourceID":"*"`, 1)},
		{"trailing", roleCreateBody + `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op := organization.CreateDynamicRole
			if strings.Contains(tc.body, `"roleVersion"`) {
				op = organization.UpdateDynamicRole
			}
			f, p, h := roleCRUDFixture(t, op)
			w := serve(t, h, roleCRUDRequest(f, op, tc.body))
			if w.Code != 400 || p.native.calls != 0 || f.reads.Load() != 0 || f.rate.calls != 0 {
				t.Fatal("invalid role intent crossed decoding boundary", w.Code)
			}
		})
	}
}

func roleSelection(c organizationhttp.Config, p *roleCRUDPort, op organization.Operation) organizationhttp.FeatureConfig {
	out := roleCRUDSelection(c, p, op)
	if op == organization.GetDynamicRole {
		out.RoleGet, out.Config.RoleGetter = true, p
	}
	if op == organization.ListDynamicRoles {
		out.RoleList, out.Config.RoleLister = true, p
	}
	return out
}

func TestRoleFeaturesRequireSelectedOwnersAndCurrentAdmission(t *testing.T) {
	for _, op := range []organization.Operation{organization.CreateDynamicRole, organization.UpdateDynamicRole, organization.DeleteDynamicRole, organization.GetDynamicRole, organization.ListDynamicRoles} {
		for _, mode := range []string{"nil-port", "typed-port", "session", "rate"} {
			f := newFixture(t)
			p := &roleCRUDPort{teamMembershipPort: &teamMembershipPort{native: f.port}}
			if mode == "typed-port" {
				p = nil
			}
			c := roleSelection(f.c, p, op)
			switch mode {
			case "nil-port":
				c.Config.RoleCreator, c.Config.RoleUpdater, c.Config.RoleDeleter, c.Config.RoleGetter, c.Config.RoleLister = nil, nil, nil, nil, nil
			case "session":
				c.Config.Sessions = nil
			case "rate":
				c.Config.AdminRate, c.Config.SafeRate = nil, nil
			}
			if _, err := organizationhttp.NewFeature(c); err == nil {
				t.Fatal("selected role dependency missing", op, mode)
			}
		}
		for _, mode := range []string{"inactive", "closed-rate", "limited"} {
			read := op == organization.GetDynamicRole || op == organization.ListDynamicRoles
			if read && mode == "limited" {
				continue
			}
			var f *fixture
			var p *roleCRUDPort
			var h http.Handler
			if read {
				f, p, h = roleReadFixture(t, op)
			} else {
				f, p, h = roleCRUDFixture(t, op)
			}
			body := roleCreateBody
			if op == organization.UpdateDynamicRole {
				body = roleUpdateBody
			}
			if op == organization.DeleteDynamicRole {
				body = roleDeleteBody
			}
			r := roleCRUDRequest(f, op, body)
			if read {
				r = roleReadRequest(f, op)
			}
			want := 403
			switch mode {
			case "inactive":
				f.inactive = true
			case "closed-rate":
				want = 503
				if read {
					f.c.SafeRate.Close()
				} else {
					f.c.AdminRate.Close()
				}
			case "limited":
				want, f.rate.mode = 429, 1
			}
			if w := serve(t, h, r); w.Code != want || p.native.calls != 0 {
				t.Fatal("role authority/admission bypass", op, mode, w.Code)
			}
		}
	}
}

func TestRoleDisabledFeaturesExposeNoRoutesOrMetadata(t *testing.T) {
	f := newFixture(t)
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, MemberAdd: true})
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "No roles", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(doc.JSON()), "/v1/organization/role/") {
		t.Fatal("disabled role metadata exposed")
	}
	for _, op := range []organization.Operation{organization.CreateDynamicRole, organization.UpdateDynamicRole, organization.DeleteDynamicRole, organization.GetDynamicRole, organization.ListDynamicRoles} {
		r := roleCRUDRequest(f, op, `{}`)
		if op == organization.GetDynamicRole || op == organization.ListDynamicRoles {
			r = roleReadRequest(f, op)
		}
		if w := serve(t, h, r); w.Code != 404 {
			t.Fatal("disabled role route exposed", op, w.Code)
		}
	}
}

func FuzzRoleClosedInput(f *testing.F) {
	for _, seed := range []string{roleCreateBody, roleUpdateBody, roleDeleteBody, "organizationID=organization-a&roleID=reader", "organizationID=organization-a&limit=1", `{}`, `{"statements":[{"effect":null}]}`} {
		for mode := uint8(0); mode < 5; mode++ {
			f.Add(seed, mode)
		}
	}
	f.Fuzz(func(t *testing.T, raw string, mode uint8) {
		if len(raw) > 4096 {
			return
		}
		op := []organization.Operation{organization.CreateDynamicRole, organization.UpdateDynamicRole, organization.DeleteDynamicRole, organization.GetDynamicRole, organization.ListDynamicRoles}[mode%5]
		var x *fixture
		var p *roleCRUDPort
		var h http.Handler
		var r *http.Request
		if op == organization.GetDynamicRole || op == organization.ListDynamicRoles {
			x, p, h = roleReadFixture(t, op)
			r = roleReadRequest(x, op)
			r.URL.RawQuery, r.RequestURI = raw, r.URL.Path+"?"+raw
		} else {
			x, p, h = roleCRUDFixture(t, op)
			r = roleCRUDRequest(x, op, raw)
		}
		w := serve(t, h, r)
		if p.native.calls > 1 || w.Code == 200 && p.native.calls != 1 || strings.Contains(w.Body.String(), x.wire) {
			t.Fatal("role owner bypass, repeat or secret disclosure")
		}
		if p.native.calls == 1 {
			var err error
			switch op {
			case organization.CreateDynamicRole:
				err = p.create.Validate()
			case organization.UpdateDynamicRole:
				err = p.update.Validate()
			case organization.DeleteDynamicRole:
				err = p.delete.Validate()
			default:
				q, queryErr := url.ParseQuery(raw)
				if queryErr != nil || string(p.roleRead.OrganizationID) != q.Get("organizationID") || p.roleRead.Authentication.TenantID != "tenant-a" || p.roleRead.Authentication.Bearer.Token() != x.wire {
					t.Fatal("role read scope changed")
				}
				if p.roleRead.TargetUserID != "" || p.roleRead.TargetTeamID != "" || op == organization.GetDynamicRole && (p.roleRead.RoleID == "" || p.roleRead.Limit != 0 || p.roleRead.Cursor != "") || op == organization.ListDynamicRoles && (p.roleRead.RoleID != "" || p.roleRead.Limit < 1 || p.roleRead.Limit > 100) {
					t.Fatal("invalid role read dispatched")
				}
			}
			if err != nil {
				t.Fatal("invalid role mutation dispatched")
			}
		}
	})
}

func roleStatementBody(t *testing.T, count, resourceBytes int, duplicate bool) string {
	t.Helper()
	statements := make([]map[string]string, count)
	for i := range statements {
		resource := strings.Repeat("r", resourceBytes) + strconv.Itoa(i)
		if duplicate {
			resource = "same-resource"
		}
		statements[i] = map[string]string{"permissionID": "read", "resourceID": resource, "effect": "allow"}
	}
	wire, err := json.Marshal(statements)
	if err != nil {
		t.Fatal(err)
	}
	return `{"organizationID":"organization-a","roleID":"reader","organizationVersion":7,"name":"Reader","statements":` + string(wire) + `}`
}

func TestRoleCRUDStatementBudgetsAndDenyAll(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		count, bytes, status int
		duplicate            bool
	}{{"empty", 0, 0, 200, false}, {"maximum-count", 64, 1, 200, false}, {"excess-count", 65, 1, 400, false}, {"encoding-budget", 64, 120, 400, false}, {"duplicate", 2, 1, 400, true}} {
		t.Run(tc.name, func(t *testing.T) {
			f, p, h := roleCRUDFixture(t, organization.CreateDynamicRole, func(f *fixture, _ *roleCRUDPort) {
				f.c.Network.Limits.MaximumBodyBytes, f.c.Network.Limits.MaximumDecodedBytes, f.c.Network.Limits.MaximumFields = 16384, 16384, 512
			})
			w := serve(t, h, roleCRUDRequest(f, organization.CreateDynamicRole, roleStatementBody(t, tc.count, tc.bytes, tc.duplicate)))
			if w.Code != tc.status {
				t.Fatal("role statement bound/deny-all changed", w.Code)
			}
			if tc.status == 200 {
				if p.native.calls != 1 || p.create.Statements == nil || len(p.create.Statements) != tc.count {
					t.Fatal("statements were dropped, truncated or default-granted")
				}
			} else if p.native.calls != 0 || f.reads.Load() != 0 {
				t.Fatal("invalid statement budget reached authority")
			}
		})
	}
}

func TestRoleCRUDHeadersAndChannelCustody(t *testing.T) {
	for _, op := range []organization.Operation{organization.CreateDynamicRole, organization.UpdateDynamicRole, organization.DeleteDynamicRole} {
		for _, mode := range []string{"wrong-key", "duplicate-bearer", "query", "cookie-only", "wrong-method", "plaintext", "wrong-host", "body-read-error"} {
			t.Run(string(op)+"/"+mode, func(t *testing.T) {
				f, p, h := roleCRUDFixture(t, op)
				body := roleCreateBody
				if op == organization.UpdateDynamicRole {
					body = roleUpdateBody
				}
				if op == organization.DeleteDynamicRole {
					body = roleDeleteBody
				}
				r := roleCRUDRequest(f, op, body)
				switch mode {
				case "wrong-key":
					if op == organization.DeleteDynamicRole {
						r.Header.Set("Idempotency-Key", "forbidden")
					} else {
						r.Header.Del("Idempotency-Key")
					}
				case "duplicate-bearer":
					r.Header.Add("Authorization", r.Header.Get("Authorization"))
				case "query":
					r.URL.RawQuery = "actorID=other-user"
					r.RequestURI = r.URL.RequestURI()
				case "cookie-only":
					r.Header.Del("Authorization")
					r.AddCookie(&http.Cookie{Name: "session", Value: f.wire})
				case "wrong-method":
					r.Method = http.MethodPut
				case "plaintext":
					r.TLS = nil
				case "wrong-host":
					r.Host = "unknown.example"
				case "body-read-error":
					r.Body = roleFailBody{}
				}
				w := serve(t, h, r)
				if w.Code == 200 || p.native.calls != 0 || f.reads.Load() != 0 || f.rate.calls != 0 {
					t.Fatal("invalid role channel reached native authority", w.Code)
				}
			})
		}
	}
}

type roleFailBody struct{}

func (roleFailBody) Read([]byte) (int, error) { return 0, errors.New("private body diagnostic") }
func (roleFailBody) Close() error             { return nil }

func TestRoleCRUDNativeOutcomesAndFinalObservation(t *testing.T) {
	for _, mode := range []string{"unknown", "committed-error", "expired-after-commit", "cancelled-after-commit", "foreign-binding", "wrong-epoch"} {
		t.Run(mode, func(t *testing.T) {
			f, p, h := roleCRUDFixture(t, organization.CreateDynamicRole)
			r := roleCRUDRequest(f, organization.CreateDynamicRole, roleCreateBody)
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			r = r.WithContext(ctx)
			switch mode {
			case "unknown":
				p.native.outcome = identity.CommitOutcomeUnknown
				p.native.err = errors.New("private unknown diagnostic")
			case "committed-error":
				p.native.err = identityhttp.ErrUnavailable
			case "expired-after-commit":
				p.native.beforeCall = func() { f.now = f.now.Add(30 * time.Second) }
			case "cancelled-after-commit":
				p.native.beforeCall = cancel
			case "foreign-binding":
				p.change = func(out *organization.StoreResult) { out.Receipt.Binding.TenantID = "tenant-b" }
			case "wrong-epoch":
				p.change = func(out *organization.StoreResult) {
					out.Receipt.Feature.BeforeVersion = 3
					out.Receipt.Feature.AfterVersion = 4
				}
			}
			w := serve(t, h, r)
			var out organizationhttp.MutationResponse
			if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || p.native.calls != 1 || strings.Contains(w.Body.String(), "private") {
				t.Fatal("unsafe role outcome delivery", w.Code)
			}
			if mode == "unknown" {
				if out.Committed || out.CommitOutcome != "unknown" || out.Recovery == nil {
					t.Fatal("unknown became success or lost recovery")
				}
			} else if mode == "foreign-binding" || mode == "wrong-epoch" {
				if out.Committed || out.Recovery != nil || out.CommandID != "" {
					t.Fatal("foreign role outcome correlation disclosed")
				}
			} else if !out.Committed || out.CommitOutcome != "committed" || out.Recovery == nil {
				t.Fatal("known role commitment lost after delivery failure")
			}
		})
	}
}
