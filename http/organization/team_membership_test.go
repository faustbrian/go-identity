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

type teamMembershipPort struct {
	native     *nativePort
	add        organization.AddTeamMemberOperationRequest
	remove     organization.RemoveTeamMemberOperationRequest
	read       organization.TeamReadRequest
	change     func(*organization.StoreResult)
	changeView func(*organization.View)
}

func (p *teamMembershipPort) AddTeamMember(ctx context.Context, r organization.AddTeamMemberOperationRequest, network string) (organization.StoreResult, error) {
	p.add, p.native.network = r, network
	return p.mutate(ctx, organization.AddTeamMember, r.Authentication, r.OrganizationID, r.UserID, r.OrganizationVersion)
}
func (p *teamMembershipPort) RemoveTeamMember(ctx context.Context, r organization.RemoveTeamMemberOperationRequest, network string) (organization.StoreResult, error) {
	p.remove, p.native.network = r, network
	return p.mutate(ctx, organization.RemoveTeamMember, r.Authentication, r.OrganizationID, r.UserID, r.OrganizationVersion)
}
func (p *teamMembershipPort) mutate(ctx context.Context, op organization.Operation, a organization.Authentication, org organization.ID, user identity.UserID, version uint64) (organization.StoreResult, error) {
	out, err := p.native.mutation(ctx, op, a, org, user)
	if out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		out.Receipt.Feature.BeforeVersion, out.Receipt.Feature.AfterVersion = version, version+1
	}
	if p.change != nil {
		p.change(&out)
	}
	return out, err
}
func (p *teamMembershipPort) ListMyTeams(ctx context.Context, r organization.TeamReadRequest) (organization.View, error) {
	return p.readTeams(ctx, r, false)
}
func (p *teamMembershipPort) ListTeamMembers(ctx context.Context, r organization.TeamReadRequest) (organization.View, error) {
	return p.readTeams(ctx, r, true)
}
func (p *teamMembershipPort) readTeams(ctx context.Context, r organization.TeamReadRequest, members bool) (organization.View, error) {
	p.read = r
	out, err := p.native.read(ctx, organization.ReadRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID})
	if members {
		out.Team = organization.Team{ID: r.TeamID, OrganizationID: r.OrganizationID, TenantID: r.Authentication.TenantID, Name: "Native team", Version: 5}
		out.TeamMembers = []organization.TeamMember{{TeamID: r.TeamID, OrganizationID: r.OrganizationID, TenantID: r.Authentication.TenantID, UserID: "other-user", Version: 3, OrganizationMemberVersion: 2, Active: true}}
		out.NextTeamCursor = "other-user"
	} else {
		out.Teams = []organization.Team{{ID: "team-a", OrganizationID: r.OrganizationID, TenantID: r.Authentication.TenantID, Name: "Native team", Version: 5}}
		out.NextTeamCursor = "team-a"
	}
	if p.changeView != nil {
		p.changeView(&out)
	}
	return out, err
}

const teamAddBody = `{"organizationID":"organization-a","teamID":"team-a","userID":"other-user","organizationVersion":7,"teamVersion":5,"organizationMemberVersion":2,"membershipVersion":0}`
const teamRemoveBody = `{"organizationID":"organization-a","teamID":"team-a","userID":"other-user","organizationVersion":7,"teamVersion":5,"organizationMemberVersion":2,"membershipVersion":3}`

func teamMembershipFixture(t testing.TB, op organization.Operation) (*fixture, *teamMembershipPort, http.Handler) {
	t.Helper()
	f := newFixture(t)
	p := &teamMembershipPort{native: f.port}
	f.c.Service, f.c.Invitations = nil, nil
	c := organizationhttp.FeatureConfig{Config: f.c}
	switch op {
	case organization.AddTeamMember:
		c.TeamMemberAdd, c.Config.TeamMemberAdder = true, p
		c.Config.SafeRate = nil
	case organization.RemoveTeamMember:
		c.TeamMemberRemove, c.Config.TeamMemberRemover = true, p
		c.Config.SafeRate = nil
	case organization.ListMyTeams:
		c.TeamListMine, c.Config.MyTeamLister = true, p
		c.Config.AdminRate = nil
	case organization.ListTeamMembers:
		c.TeamMemberList, c.Config.TeamMemberLister = true, p
		c.Config.AdminRate = nil
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
func teamMembershipRequest(f *fixture, op organization.Operation, body string) *http.Request {
	path := "/v1/organization/team/member-add"
	key := true
	if op == organization.RemoveTeamMember {
		path, key = "/v1/organization/team/member-remove", false
	}
	return request(f, path, body, key)
}

func TestTeamMembershipCarriesExactIntentWithoutReadOwner(t *testing.T) {
	for _, op := range []organization.Operation{organization.AddTeamMember, organization.RemoveTeamMember} {
		t.Run(string(op), func(t *testing.T) {
			f, p, h := teamMembershipFixture(t, op)
			body := teamAddBody
			if op == organization.RemoveTeamMember {
				body = teamRemoveBody
			}
			w := serve(t, h, teamMembershipRequest(f, op, body))
			var out organizationhttp.MutationResponse
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.MemberID != "other-user" || out.BeforeVersion != 7 || out.AfterVersion != 8 || out.Recovery == nil {
				t.Fatal("team membership receipt lost", w.Code)
			}
			if p.native.network != "198.51.100.7" || p.native.calls != 1 || f.rate.calls != 1 {
				t.Fatal("wrong native or shared admission")
			}
			if op == organization.AddTeamMember {
				r := p.add
				if r.Validate() != nil || r.Authentication.Bearer.Token() != f.wire || r.OrganizationID != "organization-a" || r.TeamID != "team-a" || r.UserID != "other-user" || r.OrganizationVersion != 7 || r.TeamVersion != 5 || r.OrganizationMemberVersion != 2 || r.MembershipVersion != 0 {
					t.Fatal("add intent changed")
				}
				k, _ := identity.NewIdempotencyKey([]byte("original-key"))
				a, _ := k.Digest([32]byte{1})
				b, _ := r.IdempotencyKey.Digest([32]byte{1})
				if a != b {
					t.Fatal("key rewritten")
				}
			} else {
				r := p.remove
				if r.Validate() != nil || r.Authentication.Bearer.Token() != f.wire || r.OrganizationID != "organization-a" || r.TeamID != "team-a" || r.UserID != "other-user" || r.OrganizationVersion != 7 || r.TeamVersion != 5 || r.OrganizationMemberVersion != 2 || r.MembershipVersion != 3 {
					t.Fatal("remove intent changed")
				}
			}
			if strings.Contains(w.Body.String(), f.wire) {
				t.Fatal("credential escaped")
			}
		})
	}
}
func TestTeamMembershipRequiresSelectedOwnerAndAdmission(t *testing.T) {
	for _, op := range []organization.Operation{organization.AddTeamMember, organization.RemoveTeamMember, organization.ListMyTeams, organization.ListTeamMembers} {
		for _, missing := range []string{"port", "typed-port", "sessions", "rate"} {
			f, p, _ := teamMembershipFixture(t, op)
			c := organizationhttp.FeatureConfig{Config: f.c}
			var owner *teamMembershipPort = p
			if missing == "typed-port" {
				owner = nil
			}
			switch op {
			case organization.AddTeamMember:
				c.TeamMemberAdd, c.Config.TeamMemberAdder = true, owner
			case organization.RemoveTeamMember:
				c.TeamMemberRemove, c.Config.TeamMemberRemover = true, owner
			case organization.ListMyTeams:
				c.TeamListMine, c.Config.MyTeamLister = true, owner
			case organization.ListTeamMembers:
				c.TeamMemberList, c.Config.TeamMemberLister = true, owner
			}
			switch missing {
			case "port":
				c.Config.TeamMemberAdder, c.Config.TeamMemberRemover, c.Config.MyTeamLister, c.Config.TeamMemberLister = nil, nil, nil, nil
			case "sessions":
				c.Config.Sessions = nil
			case "rate":
				c.Config.AdminRate, c.Config.SafeRate = nil, nil
			}
			if _, err := organizationhttp.NewFeature(c); err == nil {
				t.Fatal("selected team dependency missing", op, missing)
			}
		}
		for _, mode := range []string{"inactive", "closed-rate"} {
			f, p, h := teamMembershipFixture(t, op)
			var r *http.Request
			if op == organization.AddTeamMember {
				r = teamMembershipRequest(f, op, teamAddBody)
			} else if op == organization.RemoveTeamMember {
				r = teamMembershipRequest(f, op, teamRemoveBody)
			} else if op == organization.ListMyTeams {
				r = teamPageRequest(f, op, "organizationID=organization-a&limit=1")
			} else {
				r = teamPageRequest(f, op, "organizationID=organization-a&teamID=team-a&limit=1")
			}
			want := 403
			if mode == "inactive" {
				f.inactive = true
			} else {
				want = 503
				if op == organization.AddTeamMember || op == organization.RemoveTeamMember {
					f.c.AdminRate.Close()
				} else {
					f.c.SafeRate.Close()
				}
			}
			if w := serve(t, h, r); w.Code != want || p.native.calls != 0 {
				t.Fatal("team authority/admission fence bypassed", op, mode, w.Code)
			}
		}
	}
}
func TestTeamMembershipRejectsClosedChannelsBeforeAuthority(t *testing.T) {
	for _, op := range []organization.Operation{organization.AddTeamMember, organization.RemoveTeamMember} {
		body := teamAddBody
		if op == organization.RemoveTeamMember {
			body = teamRemoveBody
		}
		for _, invalid := range []string{`{}`, strings.Replace(body, `"teamVersion":5`, `"teamVersion":0`, 1), strings.Replace(body, `"teamVersion":5`, `"teamVersion":5e0`, 1), strings.Replace(body, `"organizationMemberVersion":2`, `"organizationMemberVersion":0`, 1), strings.Replace(body, `"userID":"other-user"`, `"userID":"other-user","commandID":"override"`, 1), strings.Replace(body, `"teamID":"team-a"`, `"teamID":"team-a","teamID":"other"`, 1)} {
			f, p, h := teamMembershipFixture(t, op)
			w := serve(t, h, teamMembershipRequest(f, op, invalid))
			if w.Code != 400 || p.native.calls != 0 || f.reads.Load() != 0 {
				t.Fatal("invalid team intent reached authority", op, w.Code)
			}
		}
		for _, mode := range []string{"key", "bearer", "cookie", "query", "method"} {
			f, p, h := teamMembershipFixture(t, op)
			r := teamMembershipRequest(f, op, body)
			want := 400
			switch mode {
			case "key":
				if op == organization.AddTeamMember {
					r.Header.Del("Idempotency-Key")
				} else {
					r.Header.Set("Idempotency-Key", "forbidden")
				}
			case "bearer":
				r.Header.Add("Authorization", r.Header.Get("Authorization"))
			case "cookie":
				r.Header.Del("Authorization")
				r.AddCookie(&http.Cookie{Name: "__Host-session", Value: fakedCookie})
			case "query":
				r.URL.RawQuery = "actor=other"
			case "method":
				r.Method = http.MethodDelete
				want = 405
			}
			w := serve(t, h, r)
			if w.Code != want || p.native.calls != 0 || f.reads.Load() != 0 {
				t.Fatal("alternate team channel reached authority", mode, w.Code)
			}
		}
	}
}
func TestTeamMembershipReceiptBindingAndLateOutcome(t *testing.T) {
	for _, op := range []organization.Operation{organization.AddTeamMember, organization.RemoveTeamMember} {
		for _, mode := range []string{"actor", "target", "org", "epoch", "unknown", "expired", "cancelled"} {
			t.Run(string(op)+mode, func(t *testing.T) {
				f, p, h := teamMembershipFixture(t, op)
				body := teamAddBody
				if op == organization.RemoveTeamMember {
					body = teamRemoveBody
				}
				r := teamMembershipRequest(f, op, body)
				switch mode {
				case "actor":
					p.change = func(o *organization.StoreResult) { o.Receipt.Binding.ActorID = "other" }
				case "target":
					p.change = func(o *organization.StoreResult) { o.MemberID = "other"; o.Receipt.Binding.UserID = "other" }
				case "org":
					p.change = func(o *organization.StoreResult) { o.OrganizationID = "other"; o.Receipt.Binding.RecordID = "other" }
				case "epoch":
					p.change = func(o *organization.StoreResult) {
						o.Receipt.Feature.BeforeVersion = 8
						o.Receipt.Feature.AfterVersion = 9
					}
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
				if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
					t.Fatal("unsafe team receipt", w.Code)
				}
				if mode == "unknown" {
					if out.CommitOutcome != "unknown" || out.Committed || out.Recovery == nil {
						t.Fatal("unknown correlation erased")
					}
				} else if mode == "expired" || mode == "cancelled" {
					if !out.Committed || out.CommitOutcome != "committed" || out.Recovery == nil || out.BeforeVersion != 7 || out.AfterVersion != 8 {
						t.Fatal("late team failure erased commitment")
					}
				} else if out.CommandID != "" || out.Recovery != nil || out.Committed {
					t.Fatal("foreign team history exported")
				}
			})
		}
	}
}
func TestTeamMembershipPagesUseOnlyCurrentScopedNativeView(t *testing.T) {
	for _, op := range []organization.Operation{organization.ListMyTeams, organization.ListTeamMembers} {
		t.Run(string(op), func(t *testing.T) {
			f, p, h := teamMembershipFixture(t, op)
			path := "/v1/organization/team/list-mine?organizationID=organization-a&limit=1"
			if op == organization.ListTeamMembers {
				path = "/v1/organization/team/member-list?organizationID=organization-a&teamID=team-a&limit=1"
			}
			r := request(f, path, "", false)
			r.Method = http.MethodGet
			r.Body = http.NoBody
			r.ContentLength = 0
			w := serve(t, h, r)
			if w.Code != 200 || p.read.OrganizationID != "organization-a" || p.read.Limit != 1 || p.read.Authentication.Bearer.Token() != f.wire || p.native.calls != 1 || f.rate.calls != 0 {
				t.Fatal("team read custody/admission", op, w.Code)
			}
			if op == organization.ListMyTeams {
				var out organizationhttp.TeamListResponse
				if json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out.Teams) != 1 || out.Teams[0].ID != "team-a" || out.NextCursor != "team-a" || out.OrganizationVersion != 3 {
					t.Fatal("team page malformed")
				}
			} else {
				var out organizationhttp.TeamMemberListResponse
				if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.TeamVersion != 5 || out.OrganizationVersion != 3 || len(out.Members) != 1 || out.Members[0].UserID != "other-user" || out.Members[0].Version != 3 || out.Members[0].OrganizationMemberVersion != 2 || out.NextCursor != "other-user" {
					t.Fatal("team member page malformed")
				}
			}
		})
	}
}

func teamPageRequest(f *fixture, op organization.Operation, query string) *http.Request {
	path := "/v1/organization/team/list-mine"
	if op == organization.ListTeamMembers {
		path = "/v1/organization/team/member-list"
	}
	r := request(f, path, "", false)
	r.Method = http.MethodGet
	r.Body = http.NoBody
	r.ContentLength = 0
	r.URL.RawQuery = query
	r.RequestURI = r.URL.RequestURI()
	return r
}
func TestTeamMembershipReadRejectsClosedQueries(t *testing.T) {
	for _, op := range []organization.Operation{organization.ListMyTeams, organization.ListTeamMembers} {
		valid := "organizationID=organization-a&limit=1"
		if op == organization.ListTeamMembers {
			valid += "&teamID=team-a"
		}
		for _, raw := range []string{"", valid + "&userID=other", valid + "&organizationID=other", strings.Replace(valid, "limit=1", "limit=01", 1), strings.Replace(valid, "limit=1", "limit=101", 1), strings.Replace(valid, "limit=1", "limit=1e0", 1), valid + "&cursor=", valid + "&cursor=a&cursor=b", strings.Replace(valid, "organizationID=organization-a", "organizationID=bad+id", 1)} {
			f, p, h := teamMembershipFixture(t, op)
			w := serve(t, h, teamPageRequest(f, op, raw))
			if w.Code != 400 || p.native.calls != 0 || f.reads.Load() != 0 {
				t.Fatal("invalid team query reached authority", op, w.Code)
			}
		}
	}
}
func TestTeamMembershipMalformedOrLateReadDisclosesNoPage(t *testing.T) {
	for _, op := range []organization.Operation{organization.ListMyTeams, organization.ListTeamMembers} {
		for _, mode := range []string{"tenant", "actor", "epoch", "order", "cursor", "name", "expired"} {
			t.Run(string(op)+mode, func(t *testing.T) {
				f, p, h := teamMembershipFixture(t, op)
				p.changeView = func(v *organization.View) {
					switch mode {
					case "tenant":
						v.Organization.TenantID = "other"
					case "actor":
						v.Actor.UserID = "other"
					case "epoch":
						v.Organization.Version = 0
					case "cursor":
						v.NextTeamCursor = "unrelated"
					case "expired":
						f.now = f.now.Add(20 * time.Second)
					case "name":
						if op == organization.ListMyTeams {
							v.Teams[0].Name = "bad\nname"
						} else {
							v.Team.Name = "bad\nname"
						}
					case "order":
						if op == organization.ListMyTeams {
							v.Teams = append(v.Teams, v.Teams[0])
						} else {
							v.TeamMembers[0].Active = false
						}
					}
				}
				query := "organizationID=organization-a&limit=1"
				if op == organization.ListTeamMembers {
					query += "&teamID=team-a"
				}
				w := serve(t, h, teamPageRequest(f, op, query))
				if w.Code != 503 || strings.Contains(w.Body.String(), `"teams"`) || strings.Contains(w.Body.String(), `"members"`) || strings.Contains(w.Body.String(), "other-user") {
					t.Fatal("unsafe team page escaped", op, mode, w.Code)
				}
			})
		}
	}
}
func TestTeamMembershipWireAndDisabledSelection(t *testing.T) {
	for _, op := range []organization.Operation{organization.AddTeamMember, organization.RemoveTeamMember, organization.ListMyTeams, organization.ListTeamMembers} {
		f, p, _ := teamMembershipFixture(t, op)
		c := organizationhttp.FeatureConfig{Config: f.c}
		switch op {
		case organization.AddTeamMember:
			c.TeamMemberAdd, c.Config.TeamMemberAdder = true, p
		case organization.RemoveTeamMember:
			c.TeamMemberRemove, c.Config.TeamMemberRemover = true, p
		case organization.ListMyTeams:
			c.TeamListMine, c.Config.MyTeamLister = true, p
		case organization.ListTeamMembers:
			c.TeamMemberList, c.Config.TeamMemberLister = true, p
		}
		feature, err := organizationhttp.NewFeature(c)
		if err != nil {
			t.Fatal(err)
		}
		h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Team membership", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal(err)
		}
		r := teamMembershipRequest(f, op, teamAddBody)
		if op == organization.RemoveTeamMember {
			r = teamMembershipRequest(f, op, teamRemoveBody)
		}
		if op == organization.ListMyTeams {
			r = teamPageRequest(f, op, "organizationID=organization-a&limit=1")
		}
		if op == organization.ListTeamMembers {
			r = teamPageRequest(f, op, "organizationID=organization-a&teamID=team-a&limit=1")
		}
		w := serve(t, h, r)
		if w.Code != 200 || len(doc.Operations()) != 1 {
			t.Fatal("selected team wire missing", op, w.Code)
		}
		assertWireResponse(t, doc.JSON(), r, w)
		f.c.Service = f.port
		feature, err = organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, MemberAdd: true})
		if err != nil {
			t.Fatal(err)
		}
		h, doc, err = identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "No teams", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(doc.JSON()), "/v1/organization/team/") || serve(t, h, r).Code != 404 {
			t.Fatal("disabled team route exposed")
		}
	}
}
func FuzzTeamMembershipClosedInput(f *testing.F) {
	for _, seed := range []string{teamAddBody, teamRemoveBody, `{}`, "organizationID=organization-a&limit=1", "organizationID=organization-a&teamID=team-a&limit=1"} {
		for mode := uint8(0); mode < 4; mode++ {
			f.Add(seed, mode)
		}
	}
	f.Fuzz(func(t *testing.T, raw string, mode uint8) {
		if len(raw) > 4096 {
			return
		}
		ops := []organization.Operation{organization.AddTeamMember, organization.RemoveTeamMember, organization.ListMyTeams, organization.ListTeamMembers}
		op := ops[mode%4]
		x, p, h := teamMembershipFixture(t, op)
		r := teamMembershipRequest(x, op, raw)
		if mode%4 >= 2 {
			r = teamPageRequest(x, op, raw)
		}
		w := serve(t, h, r)
		if p.native.calls > 1 {
			t.Fatal("native dispatch repeated")
		}
		if p.native.calls == 1 {
			switch op {
			case organization.AddTeamMember:
				if p.add.Validate() != nil {
					t.Fatal("invalid add dispatched")
				}
			case organization.RemoveTeamMember:
				if p.remove.Validate() != nil {
					t.Fatal("invalid removal dispatched")
				}
			default:
				if p.read.Limit < 1 || p.read.Limit > 100 || p.read.OrganizationID == "" {
					t.Fatal("invalid page dispatched")
				}
			}
		}
		if w.Code == 200 && p.native.calls != 1 {
			t.Fatal("team success bypassed native owner")
		}
	})
}
