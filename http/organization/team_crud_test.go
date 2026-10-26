package organizationhttp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	organization "github.com/faustbrian/go-organization"
)

type teamCRUDPort struct {
	*teamMembershipPort
	create organization.CreateTeamOperationRequest
	update organization.UpdateTeamOperationRequest
	delete organization.DeleteTeamOperationRequest
}

func (p *teamCRUDPort) CreateTeam(ctx context.Context, r organization.CreateTeamOperationRequest, network string) (organization.StoreResult, error) {
	p.create, p.native.network = r, network
	return p.mutate(ctx, organization.CreateTeam, r.Authentication, r.OrganizationID, "user-a", r.OrganizationVersion)
}
func (p *teamCRUDPort) UpdateTeam(ctx context.Context, r organization.UpdateTeamOperationRequest, network string) (organization.StoreResult, error) {
	p.update, p.native.network = r, network
	return p.mutate(ctx, organization.UpdateTeam, r.Authentication, r.OrganizationID, "user-a", r.OrganizationVersion)
}
func (p *teamCRUDPort) DeleteTeam(ctx context.Context, r organization.DeleteTeamOperationRequest, network string) (organization.StoreResult, error) {
	p.delete, p.native.network = r, network
	return p.mutate(ctx, organization.DeleteTeam, r.Authentication, r.OrganizationID, "user-a", r.OrganizationVersion)
}
func (p *teamCRUDPort) ListTeams(ctx context.Context, r organization.TeamReadRequest) (organization.View, error) {
	return p.readTeams(ctx, r, false)
}

const teamCreateBody = `{"organizationID":"organization-a","teamID":"team-a","organizationVersion":7,"name":"Engineering"}`
const teamUpdateBody = `{"organizationID":"organization-a","teamID":"team-a","organizationVersion":7,"teamVersion":5,"name":"Platform"}`
const teamDeleteBody = `{"organizationID":"organization-a","teamID":"team-a","organizationVersion":7,"teamVersion":5}`

func teamCRUDSelection(c organizationhttp.Config, p *teamCRUDPort, op organization.Operation) organizationhttp.FeatureConfig {
	out := organizationhttp.FeatureConfig{Config: c}
	switch op {
	case organization.CreateTeam:
		out.TeamCreate, out.Config.TeamCreator = true, p
	case organization.UpdateTeam:
		out.TeamUpdate, out.Config.TeamUpdater = true, p
	case organization.DeleteTeam:
		out.TeamDelete, out.Config.TeamDeleter = true, p
	case organization.ListTeams:
		out.TeamList, out.Config.TeamLister = true, p
	}
	return out
}
func teamCRUDFixture(t testing.TB, op organization.Operation) (*fixture, *teamCRUDPort, http.Handler) {
	t.Helper()
	f := newFixture(t)
	p := &teamCRUDPort{teamMembershipPort: &teamMembershipPort{native: f.port}}
	f.c.Service, f.c.Invitations = nil, nil
	if op == organization.ListTeams {
		f.c.AdminRate = nil
	} else {
		f.c.SafeRate = nil
	}
	feature, err := organizationhttp.NewFeature(teamCRUDSelection(f.c, p, op))
	if err != nil {
		t.Fatal(err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return f, p, h
}
func teamCRUDRequest(f *fixture, op organization.Operation, body string) *http.Request {
	path, keyed := "/v1/organization/team/create", true
	switch op {
	case organization.UpdateTeam:
		path = "/v1/organization/team/update"
	case organization.DeleteTeam:
		path, keyed = "/v1/organization/team/delete", false
	case organization.ListTeams:
		path, keyed = "/v1/organization/team/list?organizationID=organization-a&limit=1", false
	}
	r := request(f, path, body, keyed)
	if op == organization.ListTeams {
		r.Method, r.Body, r.ContentLength = http.MethodGet, http.NoBody, 0
	}
	return r
}

func TestTeamCRUDExactNativeIntentAndIndependentSelection(t *testing.T) {
	for _, tc := range []struct {
		op   organization.Operation
		body string
	}{{organization.CreateTeam, teamCreateBody}, {organization.UpdateTeam, teamUpdateBody}, {organization.DeleteTeam, teamDeleteBody}} {
		t.Run(string(tc.op), func(t *testing.T) {
			f, p, h := teamCRUDFixture(t, tc.op)
			w := serve(t, h, teamCRUDRequest(f, tc.op, tc.body))
			var out organizationhttp.MutationResponse
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.OrganizationID != "organization-a" || out.MemberID != "" || out.BeforeVersion != 7 || out.AfterVersion != 8 || out.Recovery == nil || out.Recovery.UserID != "user-a" {
				t.Fatal("native team CRUD outcome lost or fabricated membership", tc.op, w.Code)
			}
			if p.native.calls != 1 || f.rate.calls != 1 || p.native.network != "198.51.100.7" {
				t.Fatal("wrong team CRUD admission/dispatch")
			}
			switch tc.op {
			case organization.CreateTeam:
				if p.create.Validate() != nil || p.create.OrganizationID != "organization-a" || p.create.TeamID != "team-a" || p.create.OrganizationVersion != 7 || p.create.Name != "Engineering" || p.create.Authentication.Bearer.Token() != f.wire {
					t.Fatal("create intent changed")
				}
			case organization.UpdateTeam:
				if p.update.Validate() != nil || p.update.OrganizationID != "organization-a" || p.update.TeamID != "team-a" || p.update.OrganizationVersion != 7 || p.update.TeamVersion != 5 || p.update.Name != "Platform" || p.update.Authentication.Bearer.Token() != f.wire {
					t.Fatal("update intent changed")
				}
			case organization.DeleteTeam:
				if p.delete.Validate() != nil || p.delete.OrganizationID != "organization-a" || p.delete.TeamID != "team-a" || p.delete.OrganizationVersion != 7 || p.delete.TeamVersion != 5 || p.delete.Authentication.Bearer.Token() != f.wire {
					t.Fatal("delete intent changed")
				}
			}
		})
	}
	f, p, h := teamCRUDFixture(t, organization.ListTeams)
	w := serve(t, h, teamCRUDRequest(f, organization.ListTeams, ""))
	var page organizationhttp.TeamListResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Teams) != 1 || page.Teams[0].ID != "team-a" || p.read.OrganizationID != "organization-a" || p.read.TeamID != "" || p.read.Limit != 1 || p.native.calls != 1 || page.OrganizationVersion != 3 {
		t.Fatal("current native all-team page missing", w.Code)
	}
}

func TestTeamCRUDWireMatchesSelection(t *testing.T) {
	for _, tc := range []struct {
		op   organization.Operation
		body string
	}{{organization.CreateTeam, teamCreateBody}, {organization.UpdateTeam, teamUpdateBody}, {organization.DeleteTeam, teamDeleteBody}, {organization.ListTeams, ""}} {
		t.Run(string(tc.op), func(t *testing.T) {
			f, p, _ := teamCRUDFixture(t, tc.op)
			feature, err := organizationhttp.NewFeature(teamCRUDSelection(f.c, p, tc.op))
			if err != nil {
				t.Fatal(err)
			}
			h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Team CRUD", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
			if err != nil {
				t.Fatal(err)
			}
			r := teamCRUDRequest(f, tc.op, tc.body)
			w := serve(t, h, r)
			if w.Code != 200 || len(doc.Operations()) != 1 {
				t.Fatal("selected team CRUD wire missing", w.Code)
			}
			assertWireResponse(t, doc.JSON(), r, w)
		})
	}
}

func TestTeamCRUDClosedIntentAndChannels(t *testing.T) {
	for _, tc := range []struct {
		op   organization.Operation
		body string
	}{{organization.CreateTeam, teamCreateBody}, {organization.UpdateTeam, teamUpdateBody}, {organization.DeleteTeam, teamDeleteBody}} {
		invalid := []string{`{}`, `null`, strings.Replace(tc.body, `"teamID":"team-a"`, `"teamID":"team-a","teamID":"other"`, 1), strings.Replace(tc.body, `"teamID":"team-a"`, `"teamID":"bad id"`, 1), strings.Replace(tc.body, `"organizationVersion":7`, `"organizationVersion":0`, 1), strings.Replace(tc.body, `"organizationVersion":7`, `"organizationVersion":7e0`, 1), strings.Replace(tc.body, `"organizationVersion":7`, `"organizationVersion":18446744073709551615`, 1)}
		for _, field := range []string{"commandID", "actorID", "tenantID", "userID"} {
			invalid = append(invalid, strings.TrimSuffix(tc.body, "}")+`,"`+field+`":"override"}`)
		}
		if tc.op == organization.DeleteTeam {
			invalid = append(invalid, strings.TrimSuffix(tc.body, "}")+`,"name":"forbidden"}`)
		} else {
			name := "Engineering"
			if tc.op == organization.UpdateTeam {
				name = "Platform"
			}
			for _, value := range []string{"", " padded ", "bad\nname", strings.Repeat("x", 257)} {
				wire, _ := json.Marshal(value)
				invalid = append(invalid, strings.Replace(tc.body, `"name":"`+name+`"`, `"name":`+string(wire), 1))
			}
		}
		if tc.op != organization.CreateTeam {
			invalid = append(invalid, strings.Replace(tc.body, `"teamVersion":5`, `"teamVersion":0`, 1), strings.Replace(tc.body, `"teamVersion":5`, `"teamVersion":5.0`, 1))
		}
		for _, body := range invalid {
			f, p, h := teamCRUDFixture(t, tc.op)
			if w := serve(t, h, teamCRUDRequest(f, tc.op, body)); w.Code != 400 || p.native.calls != 0 || f.reads.Load() != 0 {
				t.Fatal("invalid team CRUD reached authority", tc.op, w.Code)
			}
		}
		for _, mode := range []string{"key", "duplicate-key", "duplicate-bearer", "cookie-only", "query", "method"} {
			f, p, h := teamCRUDFixture(t, tc.op)
			r, want := teamCRUDRequest(f, tc.op, tc.body), 400
			switch mode {
			case "key":
				if tc.op == organization.DeleteTeam {
					r.Header.Set("Idempotency-Key", "forbidden")
				} else {
					r.Header.Del("Idempotency-Key")
				}
			case "duplicate-key":
				r.Header.Add("Idempotency-Key", "another")
			case "duplicate-bearer":
				r.Header.Add("Authorization", r.Header.Get("Authorization"))
			case "cookie-only":
				r.Header.Del("Authorization")
				r.AddCookie(&http.Cookie{Name: "__Host-session", Value: fakedCookie})
			case "query":
				r.URL.RawQuery = "actorID=other"
				r.RequestURI = r.URL.RequestURI()
			case "method":
				r.Method, want = http.MethodDelete, 405
			}
			if w := serve(t, h, r); w.Code != want || p.native.calls != 0 || f.reads.Load() != 0 {
				t.Fatal("alternate CRUD channel reached authority", tc.op, mode, w.Code)
			}
		}
	}
}

func TestTeamCRUDRequiresOwnDependenciesAndAdmission(t *testing.T) {
	for _, op := range []organization.Operation{organization.CreateTeam, organization.UpdateTeam, organization.DeleteTeam, organization.ListTeams} {
		for _, mode := range []string{"nil-port", "typed-port", "session", "rate"} {
			f, p, _ := teamCRUDFixture(t, op)
			if mode == "typed-port" {
				p = nil
			}
			c := teamCRUDSelection(f.c, p, op)
			switch mode {
			case "nil-port":
				c.Config.TeamCreator, c.Config.TeamUpdater, c.Config.TeamDeleter, c.Config.TeamLister = nil, nil, nil, nil
			case "session":
				c.Config.Sessions = nil
			case "rate":
				c.Config.AdminRate, c.Config.SafeRate = nil, nil
			}
			if _, err := organizationhttp.NewFeature(c); err == nil {
				t.Fatal("missing selected CRUD dependency accepted", op, mode)
			}
		}
		for _, mode := range []string{"inactive", "closed-rate", "limited"} {
			if mode == "limited" && op == organization.ListTeams {
				continue
			}
			f, p, h := teamCRUDFixture(t, op)
			body, want := teamCreateBody, 403
			if op == organization.UpdateTeam {
				body = teamUpdateBody
			}
			if op == organization.DeleteTeam {
				body = teamDeleteBody
			}
			if op == organization.ListTeams {
				body = ""
			}
			switch mode {
			case "inactive":
				f.inactive = true
			case "closed-rate":
				want = 503
				if op == organization.ListTeams {
					f.c.SafeRate.Close()
				} else {
					f.c.AdminRate.Close()
				}
			case "limited":
				want, f.rate.mode = 429, 1
			}
			if w := serve(t, h, teamCRUDRequest(f, op, body)); w.Code != want || p.native.calls != 0 {
				t.Fatal("CRUD admission bypass", op, mode, w.Code)
			}
		}
	}
}

func TestTeamCRUDOriginalReceiptAndLateOutcome(t *testing.T) {
	for _, tc := range []struct {
		op   organization.Operation
		body string
	}{{organization.CreateTeam, teamCreateBody}, {organization.UpdateTeam, teamUpdateBody}, {organization.DeleteTeam, teamDeleteBody}} {
		for _, mode := range []string{"actor", "tenant", "record", "epoch", "schema", "unknown", "expired", "cancelled"} {
			t.Run(string(tc.op)+"/"+mode, func(t *testing.T) {
				f, p, h := teamCRUDFixture(t, tc.op)
				r := teamCRUDRequest(f, tc.op, tc.body)
				switch mode {
				case "actor":
					p.change = func(o *organization.StoreResult) { o.Receipt.Binding.ActorID = "other" }
				case "tenant":
					p.change = func(o *organization.StoreResult) { o.Receipt.Binding.TenantID = "other" }
				case "record":
					p.change = func(o *organization.StoreResult) { o.OrganizationID = "other"; o.Receipt.Binding.RecordID = "other" }
				case "epoch":
					p.change = func(o *organization.StoreResult) {
						o.Receipt.Feature.BeforeVersion, o.Receipt.Feature.AfterVersion = 8, 9
					}
				case "schema":
					p.change = func(o *organization.StoreResult) { o.Receipt.Binding.SchemaID = "organization-membership" }
				case "unknown":
					p.native.outcome = identity.CommitOutcomeUnknown
				case "expired":
					p.native.beforeCall = func() { f.now = f.now.Add(20 * time.Second) }
				case "cancelled":
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					r = r.WithContext(ctx)
					p.native.beforeCall = cancel
				}
				w := serve(t, h, r)
				var out organizationhttp.MutationResponse
				if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.MemberID != "" || p.native.calls != 1 {
					t.Fatal("unsafe CRUD outcome", tc.op, mode, w.Code)
				}
				if mode == "unknown" {
					if out.CommitOutcome != "unknown" || out.Committed || out.Recovery == nil {
						t.Fatal("unknown custody erased or committed")
					}
				} else if mode == "expired" || mode == "cancelled" {
					if !out.Committed || out.CommitOutcome != "committed" || out.Recovery == nil || out.BeforeVersion != 7 || out.AfterVersion != 8 {
						t.Fatal("late failure erased original commitment")
					}
				} else if out.Committed || out.CommandID != "" || out.Recovery != nil {
					t.Fatal("foreign original metadata exported")
				}
			})
		}
	}
}

func TestTeamCRUDListWithholdsMalformedOrLatePage(t *testing.T) {
	for _, mode := range []string{"actor", "tenant", "nonmanager", "epoch", "name", "order", "cursor", "expired"} {
		t.Run(mode, func(t *testing.T) {
			f, p, h := teamCRUDFixture(t, organization.ListTeams)
			p.changeView = func(v *organization.View) {
				switch mode {
				case "actor":
					v.Actor.UserID = "other"
				case "tenant":
					v.Teams[0].TenantID = "other"
				case "nonmanager":
					v.Actor.Role = organization.RoleMember
				case "epoch":
					v.Organization.Version = 0
				case "name":
					v.Teams[0].Name = "bad\nname"
				case "order":
					v.Teams = append(v.Teams, v.Teams[0])
				case "cursor":
					v.NextTeamCursor = "foreign"
				case "expired":
					f.now = f.now.Add(20 * time.Second)
				}
			}
			w := serve(t, h, teamCRUDRequest(f, organization.ListTeams, ""))
			if w.Code != 503 || strings.Contains(w.Body.String(), `"teams"`) || strings.Contains(w.Body.String(), "team-a") {
				t.Fatal("malformed or expired manager page escaped", mode, w.Code)
			}
		})
	}
}

func TestTeamCRUDDisabledRoutesAndClosedListInput(t *testing.T) {
	for _, query := range []string{"", "organizationID=organization-a", "organizationID=organization-a&limit=01", "organizationID=organization-a&limit=101", "organizationID=organization-a&limit=1&cursor=", "organizationID=organization-a&limit=1&teamID=team-a", "organizationID=organization-a&limit=1&userID=other", "organizationID=organization-a&limit=1&limit=2"} {
		f, p, h := teamCRUDFixture(t, organization.ListTeams)
		r := teamCRUDRequest(f, organization.ListTeams, "")
		r.URL.RawQuery = query
		r.RequestURI = r.URL.RequestURI()
		if w := serve(t, h, r); w.Code != 400 || p.native.calls != 0 || f.reads.Load() != 0 {
			t.Fatal("invalid all-team query reached owner", w.Code)
		}
	}
	f := newFixture(t)
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, MemberAdd: true})
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "No team CRUD", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(doc.JSON()), "/v1/organization/team/") {
		t.Fatal("disabled CRUD metadata exposed")
	}
	for _, op := range []organization.Operation{organization.CreateTeam, organization.UpdateTeam, organization.DeleteTeam, organization.ListTeams} {
		if w := serve(t, h, teamCRUDRequest(f, op, `{}`)); w.Code != 404 {
			t.Fatal("disabled team CRUD route exposed", op, w.Code)
		}
	}
}

func FuzzTeamCRUDClosedInput(f *testing.F) {
	for _, seed := range []string{teamCreateBody, teamUpdateBody, teamDeleteBody, "organizationID=organization-a&limit=1", `{}`} {
		for mode := uint8(0); mode < 4; mode++ {
			f.Add(seed, mode)
		}
	}
	f.Fuzz(func(t *testing.T, raw string, mode uint8) {
		if len(raw) > 4096 {
			return
		}
		op := []organization.Operation{organization.CreateTeam, organization.UpdateTeam, organization.DeleteTeam, organization.ListTeams}[mode%4]
		x, p, h := teamCRUDFixture(t, op)
		r := teamCRUDRequest(x, op, raw)
		if op == organization.ListTeams {
			r.URL.RawQuery = raw
			r.RequestURI = r.URL.RequestURI()
		}
		w := serve(t, h, r)
		if p.native.calls > 1 || w.Code == 200 && p.native.calls != 1 {
			t.Fatal("CRUD dispatch repeated or bypassed native owner")
		}
		if p.native.calls == 1 {
			switch op {
			case organization.CreateTeam:
				if p.create.Validate() != nil {
					t.Fatal("invalid create dispatched")
				}
			case organization.UpdateTeam:
				if p.update.Validate() != nil {
					t.Fatal("invalid update dispatched")
				}
			case organization.DeleteTeam:
				if p.delete.Validate() != nil {
					t.Fatal("invalid delete dispatched")
				}
			case organization.ListTeams:
				if p.read.Limit < 1 || p.read.Limit > 100 || p.read.TeamID != "" || p.read.OrganizationID == "" {
					t.Fatal("invalid list dispatched")
				}
			}
		}
	})
}
