package organizationhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	organization "github.com/faustbrian/go-organization"
)

type organizationListPort struct {
	t      testing.TB
	calls  int
	last   organization.ListOrganizationsRequest
	result organization.ListOrganizationsResult
	err    error
	before func()
}

func (p *organizationListPort) ListOrganizations(ctx context.Context, r organization.ListOrganizationsRequest) (organization.ListOrganizationsResult, error) {
	if _, ok := ctx.Deadline(); !ok {
		p.t.Fatal("unbounded native organization page")
	}
	p.calls, p.last = p.calls+1, r
	if p.before != nil {
		p.before()
	}
	return p.result, p.err
}

func newOrganizationListPort(t testing.TB) *organizationListPort {
	return &organizationListPort{t: t, result: organization.ListOrganizationsResult{Organizations: []organization.Organization{
		{ID: "org-a", TenantID: "tenant-a", Name: "Visible first", Slug: "first", Version: 1, Active: true},
		{ID: "org-b", TenantID: "tenant-a", Name: "Visible second", Slug: "second", Version: 2, Active: true},
	}, NextCursor: "bmV4dC1wYWdl"}}
}

func organizationListFeature(t testing.TB, f *fixture, p *organizationListPort) identityhttp.Feature {
	t.Helper()
	f.c.Service, f.c.Invitations, f.c.AdminRate = nil, nil, nil
	f.c.OrganizationLister = p
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, List: true})
	if err != nil {
		t.Fatal("independent current-user list selection", err)
	}
	return feature
}

func organizationListHandler(t testing.TB, f *fixture, p *organizationListPort) http.Handler {
	t.Helper()
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{organizationListFeature(t, f, p)}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func organizationListRequest(f *fixture, query string) *http.Request {
	r := request(f, "/v1/organization/list?"+query, "", false)
	r.Method = http.MethodGet
	return r
}

func TestOrganizationListPreservesSelfPageAndOpaqueContinuation(t *testing.T) {
	f := newFixture(t)
	p := newOrganizationListPort(t)
	h := organizationListHandler(t, f, p)
	w := serve(t, h, organizationListRequest(f, "limit=2&cursor=cHJldmlvdXM"))
	var out struct {
		Organizations []organizationhttp.OrganizationView
		NextCursor    organization.OrganizationCursor
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out.Organizations) != 2 || out.Organizations[0].ID != "org-a" || out.Organizations[1].Name != "Visible second" || out.NextCursor != p.result.NextCursor {
		t.Fatal("current-user page lost native projection or continuation", w.Code)
	}
	if p.calls != 1 || p.last.Authentication.TenantID != "tenant-a" || p.last.Authentication.Bearer.Token() != f.wire || p.last.Limit != 2 || p.last.Cursor != "cHJldmlvdXM" || p.last.CorrelationID == "" || f.port.calls != 0 || f.rate.calls != 0 {
		t.Fatal("list substituted an arbitrary actor, membership or administrator owner")
	}
	for _, hidden := range []string{f.wire, "tenantID", "userID", "membership", "authority", "Active"} {
		if strings.Contains(w.Body.String(), hidden) {
			t.Fatal("list exported private or unselected metadata")
		}
	}
	p.result = organization.ListOrganizationsResult{}
	w = serve(t, h, organizationListRequest(f, "limit=1"))
	var empty map[string]json.RawMessage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &empty) != nil || len(empty) != 1 || string(empty["organizations"]) != "[]" {
		t.Fatal("empty final page was null, invented a cursor or omitted array", w.Code)
	}
}

func TestOrganizationListRejectsClosedQueriesBeforeAuthority(t *testing.T) {
	for _, query := range []string{"", "limit=0", "limit=201", "limit=01", "limit=1e2", "limit=%2B1", "limit=2&limit=1", "limit=2&cursor=", "limit=2&cursor=one&cursor=two", "limit=2&cursor=" + strings.Repeat("a", 513), "limit=2&userID=other", "limit=2&tenantID=other", "limit=2&organizationID=other", "limit=2&idempotencyKey=other"} {
		f := newFixture(t)
		p := newOrganizationListPort(t)
		w := serve(t, organizationListHandler(t, f, p), organizationListRequest(f, query))
		if w.Code != 400 || p.calls != 0 || f.reads.Load() != 0 {
			t.Fatal("noncanonical page query reached authority", w.Code)
		}
	}
	for name, change := range map[string]func(*http.Request){
		"key": func(r *http.Request) { r.Header.Set("Idempotency-Key", "forbidden") },
		"cookie": func(r *http.Request) {
			r.Header.Del("Authorization")
			r.AddCookie(&http.Cookie{Name: "__Host-session", Value: "ambient"})
		},
		"duplicate-auth": func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) },
		"body":           func(r *http.Request) { r.ContentLength = 1; r.Body = http.NoBody },
		"method":         func(r *http.Request) { r.Method = http.MethodPost },
		"host":           func(r *http.Request) { r.Host = "foreign.example" },
		"plaintext":      func(r *http.Request) { r.TLS = nil },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			p := newOrganizationListPort(t)
			h := organizationListHandler(t, f, p)
			r := organizationListRequest(f, "limit=2")
			change(r)
			w := serve(t, h, r)
			if w.Code < 400 || p.calls != 0 || f.reads.Load() != 0 {
				t.Fatal("alternate page channel reached authority", w.Code)
			}
		})
	}
}

func TestOrganizationListRejectsUnsafeNativePages(t *testing.T) {
	for _, mode := range []string{"tenant", "inactive", "version", "duplicate", "unordered", "over-limit", "name", "slug", "id", "cursor", "empty-cursor"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			p := newOrganizationListPort(t)
			switch mode {
			case "tenant":
				p.result.Organizations[0].TenantID = "other"
			case "inactive":
				p.result.Organizations[0].Active = false
			case "version":
				p.result.Organizations[0].Version = 0
			case "duplicate":
				p.result.Organizations[1].ID = "org-a"
			case "unordered":
				p.result.Organizations[1].ID = "org-0"
			case "over-limit":
				p.result.Organizations = append(p.result.Organizations, p.result.Organizations[1])
			case "name":
				p.result.Organizations[0].Name = string([]byte{255})
			case "slug":
				p.result.Organizations[0].Slug = "invalid/slug"
			case "id":
				p.result.Organizations[0].ID = "bad id"
			case "cursor":
				p.result.NextCursor = organization.OrganizationCursor(strings.Repeat("a", 513))
			case "empty-cursor":
				p.result.Organizations = nil
			}
			w := serve(t, organizationListHandler(t, f, p), organizationListRequest(f, "limit=2"))
			var fields map[string]string
			if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &fields) != nil || len(fields) != 1 || fields["error"] != "unavailable" {
				t.Fatal("unsafe source page disclosed partial metadata", w.Code)
			}
		})
	}
}

func TestOrganizationListRequiresOwnersAndWithholdsLateOutput(t *testing.T) {
	for _, mode := range []string{"owner", "typed-owner", "session", "safe"} {
		f := newFixture(t)
		f.c.OrganizationLister = newOrganizationListPort(t)
		switch mode {
		case "owner":
			f.c.OrganizationLister = nil
		case "typed-owner":
			f.c.OrganizationLister = (*organizationListPort)(nil)
		case "session":
			f.c.Sessions = nil
		case "safe":
			f.c.SafeRate = nil
		}
		if _, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, List: true}); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("list accepted missing selected owner", mode, err)
		}
	}
	for _, mode := range []string{"forbidden", "unavailable", "expired", "cancelled", "rate", "revoked", "panic"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			p := newOrganizationListPort(t)
			h := organizationListHandler(t, f, p)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := 503
			switch mode {
			case "forbidden":
				p.err = organization.ErrForbidden
				want = 403
			case "unavailable":
				p.err = organization.ErrUnavailable
			case "expired":
				p.before = func() { f.now = f.now.Add(20 * time.Second) }
			case "cancelled":
				p.before = cancel
			case "rate":
				if err := f.c.SafeRate.Close(); err != nil {
					t.Fatal(err)
				}
			case "revoked":
				f.inactive = true
				want = 403
			case "panic":
				p.before = func() { panic("private page failure") }
			}
			w := serve(t, h, organizationListRequest(f, "limit=2").WithContext(ctx))
			var fields map[string]string
			if w.Code != want || json.Unmarshal(w.Body.Bytes(), &fields) != nil || len(fields) != 1 || fields["error"] == "" {
				t.Fatal("failed page exposed partial output", w.Code)
			}
			if (mode == "rate" || mode == "revoked") && p.calls != 0 {
				t.Fatal("withdrawn admission reached list owner")
			}
		})
	}
}

func TestOrganizationListWireAndDisabledSurface(t *testing.T) {
	f := newFixture(t)
	p := newOrganizationListPort(t)
	h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Organization list", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{organizationListFeature(t, f, p)}})
	if err != nil {
		t.Fatal(err)
	}
	r := organizationListRequest(f, "limit=2")
	w := serve(t, h, r)
	assertWireResponse(t, doc.JSON(), r, w)
	if w.Code != 200 || p.calls != 1 {
		t.Fatal("documented list did not reach native owner", w.Code)
	}
	var shape struct {
		Paths map[string]struct {
			Get struct {
				Parameters []struct {
					Name     string
					Required bool
					Schema   map[string]json.RawMessage
				}
			}
		}
	}
	if json.Unmarshal(doc.JSON(), &shape) != nil || len(shape.Paths) != 1 {
		t.Fatal("list advertised sibling features")
	}
	params := shape.Paths["/v1/organization/list"].Get.Parameters
	if len(params) != 2 {
		t.Fatal("list wire added identity or key selector")
	}
	foundLimit := false
	for _, param := range params {
		if param.Name == "limit" {
			foundLimit = true
			if !param.Required || param.Schema["default"] != nil || string(param.Schema["maximum"]) != "200" {
				t.Fatal("list wire invented a limit default or wrong bound")
			}
		} else if param.Name != "cursor" {
			t.Fatal("unexpected list selector")
		}
	}
	if !foundLimit {
		t.Fatal("list wire omitted required limit")
	}
	base := newFixture(t)
	legacy, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: base.c, Get: true})
	if err != nil {
		t.Fatal(err)
	}
	disabled, off, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "No list", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{legacy}})
	if err != nil || strings.Contains(string(off.JSON()), `"/v1/organization/list"`) {
		t.Fatal("disabled list exposed metadata", err)
	}
	if out := serve(t, disabled, organizationListRequest(base, "limit=2")); out.Code != 404 {
		t.Fatal("disabled list exposed route", out.Code)
	}
}

func FuzzOrganizationListClosedQuery(f *testing.F) {
	for _, seed := range []string{"limit=1", "limit=200&cursor=cHJldmlvdXM", "", "limit=01", "limit=2&limit=1", "limit=2&cursor=", "limit=2&cursor=%FF", "limit=1&userID=other", "limit=201", "limit=2&cursor=" + strings.Repeat("a", 513)} {
		f.Add(seed)
	}
	decimal := regexp.MustCompile(`^[1-9][0-9]{0,2}$`)
	cursor := regexp.MustCompile(`^[A-Za-z0-9_-]{1,512}$`)
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			return
		}
		x := newFixture(t)
		p := newOrganizationListPort(t)
		p.result = organization.ListOrganizationsResult{}
		r := organizationListRequest(x, "limit=1")
		r.URL.RawQuery = raw
		w := serve(t, organizationListHandler(t, x, p), r)
		if p.calls != 0 {
			q, err := url.ParseQuery(raw)
			if err != nil || len(q["limit"]) != 1 || !decimal.MatchString(q.Get("limit")) {
				t.Fatal("hostile limit reached native listing")
			}
			n, err := strconv.Atoi(q.Get("limit"))
			if err != nil || n > 200 || p.last.Limit != uint32(n) || p.last.Authentication.TenantID != "tenant-a" || p.calls != 1 {
				t.Fatal("query altered native bound or tenant")
			}
			for key, values := range q {
				if key != "limit" && key != "cursor" || len(values) != 1 || key == "cursor" && !cursor.MatchString(values[0]) {
					t.Fatal("alternate selector or hostile cursor reached native listing")
				}
			}
			if string(p.last.Cursor) != q.Get("cursor") {
				t.Fatal("transport rewrote native continuation")
			}
		}
		if w.Code == 200 && p.calls != 1 {
			t.Fatal("successful listing bypassed native owner")
		}
	})
}
