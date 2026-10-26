package organizationhttp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	organization "github.com/faustbrian/go-organization"
)

// This transport seam proves projection and request custody. Real owner-only
// PostgreSQL authority is exercised by the Reference consumer journey.
type invitationLister struct {
	request organization.InvitationReadRequest
	calls   int
	page    organization.InvitationPage
	err     error
	before  func()
}

func (p *invitationLister) List(_ context.Context, r organization.InvitationReadRequest) (organization.InvitationPage, error) {
	p.request, p.calls = r, p.calls+1
	if p.before != nil {
		p.before()
	}
	return p.page, p.err
}

func ownerListFixture(t testing.TB) (*fixture, *invitationLister, identityhttp.Feature) {
	t.Helper()
	f := newFixture(t)
	p := &invitationLister{page: organization.InvitationPage{
		Organization: organization.Organization{ID: "organization-a", TenantID: "tenant-a", Name: "Organization", Slug: "organization", Version: 1, Active: true},
		Actor:        organization.Member{OrganizationID: "organization-a", TenantID: "tenant-a", UserID: "user-a", Role: organization.RoleOwner, Version: 1, AuthorizationVersion: 1, Active: true},
	}}
	f.c.Service, f.c.AdminRate, f.c.Invitations, f.c.InvitationLister = nil, nil, nil, p
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, InvitationList: true})
	if err != nil {
		t.Fatal(err)
	}
	return f, p, feature
}
func listHandler(t testing.TB, feature identityhttp.Feature) http.Handler {
	t.Helper()
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func TestInvitationListClosedQuery(t *testing.T) {
	for _, query := range []string{"", "organizationID=organization-a", "limit=1", "organizationID=organization-a&limit=0", "organizationID=organization-a&limit=101", "organizationID=organization-a&limit=01", "organizationID=organization-a&limit=1e1", "organizationID=organization-a&limit=1&limit=2", "organizationID=organization-a&limit=1&cursor=", "organizationID=organization-a&limit=1&cursor=" + strings.Repeat("a", 129), "organizationID=organization-a&limit=1&cursor=%00", "organizationID=organization-a&limit=1&actorID=other", "organizationID=organization-a&limit=1&invitationID=invitation-a", "organizationID=organization-a&organizationID=other&limit=1"} {
		t.Run(query, func(t *testing.T) {
			f, p, feature := ownerListFixture(t)
			w := serve(t, listHandler(t, feature), request(f, "/v1/organization/invitation/list?"+query, "", false))
			if w.Code != 400 || p.calls != 0 || f.reads.Load() != 0 {
				t.Fatal("hostile page reached owner", w.Code)
			}
		})
	}
}
func TestInvitationListPagesAndWithholdsMalformedOutput(t *testing.T) {
	for name, mutate := range map[string]func(*invitationLister){
		"foreign-tenant":         func(p *invitationLister) { p.page.Invitations[0].Invitation.TenantID = "other" },
		"foreign-org":            func(p *invitationLister) { p.page.Invitations[0].Invitation.OrganizationID = "other" },
		"foreign-actor":          func(p *invitationLister) { p.page.Actor.UserID = "other" },
		"non-owner":              func(p *invitationLister) { p.page.Actor.Role = organization.RoleAdministrator },
		"inactive-org":           func(p *invitationLister) { p.page.Organization.Active = false },
		"inactive-member":        func(p *invitationLister) { p.page.Actor.Active = false },
		"unknown-status":         func(p *invitationLister) { p.page.Invitations[0].Invitation.Status = 99 },
		"cursor-mismatch":        func(p *invitationLister) { p.page.NextCursor = "unreturned" },
		"cursor-with-empty-page": func(p *invitationLister) { p.page.Invitations = nil; p.page.NextCursor = "invitation-a" },
		"oversized":              func(p *invitationLister) { p.page.Invitations = append(p.page.Invitations, p.page.Invitations[0]) },
		"preceding-cursor":       func(p *invitationLister) { p.page.Invitations[0].Invitation.ID = "invitation-0" },
		"expired-authority":      func(p *invitationLister) { p.err = organization.ErrUnavailable },
	} {
		t.Run(name, func(t *testing.T) {
			f, p, feature := ownerListFixture(t)
			p.page.Invitations = []organization.InvitationDelivery{{Invitation: new(invitationReader).invitation()}}
			mutate(p)
			w := serve(t, listHandler(t, feature), request(f, "/v1/organization/invitation/list?organizationID=organization-a&limit=1&cursor=invitation-0", "", false))
			if w.Code != 503 || strings.Contains(w.Body.String(), "invitation-a") {
				t.Fatal("malformed or partial page disclosed", w.Code)
			}
		})
	}
	f, p, feature := ownerListFixture(t)
	h := listHandler(t, feature)
	i := new(invitationReader).invitation()
	p.page.Invitations = []organization.InvitationDelivery{{Invitation: i}}
	p.page.NextCursor = i.ID
	w := serve(t, h, request(f, "/v1/organization/invitation/list?organizationID=organization-a&limit=1", "", false))
	var page organizationhttp.InvitationListResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.NextCursor != i.ID {
		t.Fatal("continuation lost", w.Code)
	}
	p.page.Invitations = nil
	p.page.NextCursor = ""
	w = serve(t, h, request(f, "/v1/organization/invitation/list?organizationID=organization-a&limit=1&cursor="+url.QueryEscape(string(page.NextCursor)), "", false))
	if w.Code != 200 || p.request.Cursor != i.ID || !strings.Contains(w.Body.String(), `"invitations":[]`) || strings.Contains(w.Body.String(), "nextCursor") {
		t.Fatal("terminal empty page or cursor changed", w.Code)
	}
}
func TestInvitationListSessionRateAndLateFences(t *testing.T) {
	for _, mode := range []string{"inactive", "forbidden", "rate", "closed", "expired", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			f, p, feature := ownerListFixture(t)
			h := listHandler(t, feature)
			r := request(f, "/v1/organization/invitation/list?organizationID=organization-a&limit=1", "", false)
			want, calls := 503, 1
			switch mode {
			case "inactive":
				f.inactive = true
				want, calls = 403, 0
			case "forbidden":
				p.err = organization.ErrForbidden
				want = 403
			case "rate":
				for n := 0; n < 100; n++ {
					if w := serve(t, h, request(f, r.URL.String(), "", false)); w.Code != 200 {
						t.Fatal(w.Code)
					}
				}
				p.calls = 0
				want, calls = 429, 0
			case "closed":
				f.c.SafeRate.Close()
				calls = 0
			case "expired":
				p.before = func() { f.now = f.now.Add(20 * time.Second) }
			case "cancelled":
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				r = r.WithContext(ctx)
				p.before = cancel
			}
			w := serve(t, h, r)
			if w.Code != want || p.calls != calls || strings.Contains(w.Body.String(), "invitations") {
				t.Fatal("current session/rate/final authority fence", mode, w.Code, p.calls)
			}
		})
	}
}
func TestInvitationListSelectionAndWire(t *testing.T) {
	f, p, feature := ownerListFixture(t)
	h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Invitations", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	r := request(f, "/v1/organization/invitation/list?organizationID=organization-a&limit=1", "", false)
	w := serve(t, h, r)
	assertWireResponse(t, doc.JSON(), r, w)
	if len(doc.Operations()) != 1 || strings.Contains(string(doc.JSON()), `"/v1/organization/invitation/get"`) {
		t.Fatal("unselected neighboring route advertised")
	}
	var absent *invitationLister
	f.c.InvitationLister = absent
	if _, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, InvitationList: true}); err == nil {
		t.Fatal("nil native list owner admitted")
	}
	f.c.InvitationLister = p
	// Existing recipient/Get implementation is not forced to grow List.
	f.c.Invitations = new(invitationReader)
	other, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, InvitationGet: true, InvitationListMine: true})
	if err != nil {
		t.Fatal(err)
	}
	if w := serve(t, listHandler(t, other), r); w.Code != 404 {
		t.Fatal("disabled owner-list route exposed", w.Code)
	}
}
func FuzzInvitationListClosedQuery(f *testing.F) {
	for _, s := range []string{"organizationID=organization-a&limit=1", "", "organizationID=organization-a&limit=101", "organizationID=organization-a&limit=01", "organizationID=organization-a&limit=1&cursor=%FF", "organizationID=organization-a&limit=1&limit=2", "organizationID=organization-a&limit=1&tenantID=other"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			return
		}
		x, p, feature := ownerListFixture(t)
		r := request(x, "/v1/organization/invitation/list?organizationID=organization-a&limit=1", "", false)
		r.URL.RawQuery = raw
		w := serve(t, listHandler(t, feature), r)
		if p.calls != 0 {
			q, err := url.ParseQuery(raw)
			n, e := strconv.ParseUint(q.Get("limit"), 10, 32)
			if err != nil || e != nil || n < 1 || n > 100 || strconv.FormatUint(n, 10) != q.Get("limit") || p.request.Limit != uint32(n) || p.request.OrganizationID != organization.ID(q.Get("organizationID")) {
				t.Fatal("hostile bound reached owner")
			}
			for k, vs := range q {
				if len(vs) != 1 || k != "organizationID" && k != "cursor" && k != "limit" {
					t.Fatal("alternate selector reached owner")
				}
				if k != "limit" {
					v := vs[0]
					if len(v) < 1 || len(v) > 128 || !utf8.ValidString(v) {
						t.Fatal("unbounded ID")
					}
					for _, r := range v {
						if r <= ' ' || r == 127 {
							t.Fatal("control-bearing ID")
						}
					}
				}
			}
		}
		if w.Code == 200 && p.calls != 1 {
			t.Fatal("list bypassed owner")
		}
	})
}
func TestInvitationListIndependentOwnerPage(t *testing.T) {
	f := newFixture(t)
	p := &invitationLister{}
	f.c.Service, f.c.AdminRate, f.c.Invitations, f.c.InvitationLister = nil, nil, nil, p
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, InvitationList: true})
	if err != nil {
		t.Fatal("independent owner list selection", err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	i := new(invitationReader).invitation()
	p.page.Organization = organization.Organization{ID: "organization-a", TenantID: "tenant-a", Name: "Organization", Slug: "organization", Version: 1, Active: true}
	p.page.Actor = organization.Member{OrganizationID: "organization-a", TenantID: "tenant-a", UserID: "user-a", Role: organization.RoleOwner, Version: 1, AuthorizationVersion: 1, Active: true}
	p.page.Invitations = []organization.InvitationDelivery{{Invitation: i}}
	w := serve(t, h, request(f, "/v1/organization/invitation/list?organizationID=organization-a&limit=1", "", false))
	if w.Code != http.StatusOK || p.calls != 1 || p.request.OrganizationID != "organization-a" || p.request.ID != "" || p.request.Limit != 1 || p.request.Authentication.Bearer.Token() != f.wire || p.request.CorrelationID == "" {
		t.Fatal("owner list request or response", w.Code)
	}
	var out organizationhttp.InvitationListResponse
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out.Invitations) != 1 || out.Invitations[0].ID != i.ID {
		t.Fatal("owner page missing")
	}
	for _, secret := range []string{f.wire, "identifier-a", "owner-a", "user-a", "recipientIdentifier", "EffectID"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("private invitation metadata escaped")
		}
	}
}
