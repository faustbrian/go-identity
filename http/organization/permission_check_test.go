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

	"github.com/faustbrian/go-authorization/v3"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	organization "github.com/faustbrian/go-organization"
)

type permissionCheckPort struct {
	native   *nativePort
	request  organization.PermissionCheckRequest
	decision authorization.Decision
}

func (p *permissionCheckPort) CheckPermission(ctx context.Context, r organization.PermissionCheckRequest) (authorization.Decision, error) {
	p.native.calls++
	p.request = r
	if _, ok := ctx.Deadline(); !ok {
		p.native.t.Fatal("unbounded native permission check")
	}
	if p.native.beforeCall != nil {
		p.native.beforeCall()
	}
	return p.decision, p.native.err
}

const permissionQuery = "organizationID=organization-a&organizationVersion=3&action=document.read&resourceType=document&resourceID=document-a"

func permissionFixture(t testing.TB) (*fixture, *permissionCheckPort, http.Handler) {
	t.Helper()
	f := newFixture(t)
	p := &permissionCheckPort{native: f.port, decision: authorization.Decision{Outcome: authorization.Allow, Revision: 3}}
	f.c.Service, f.c.Invitations, f.c.AdminRate = nil, nil, nil
	f.c.PermissionChecker = p
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, PermissionCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return f, p, h
}
func permissionRequest(f *fixture, query string) *http.Request {
	r := request(f, "/v1/organization/permission-check", "", false)
	r.Method = http.MethodGet
	r.URL.RawQuery = query
	r.RequestURI = r.URL.RequestURI()
	return r
}

func TestPermissionCheckUsesCurrentNativeMemberDecision(t *testing.T) {
	for _, outcome := range []authorization.Outcome{authorization.Allow, authorization.Deny} {
		f, p, h := permissionFixture(t)
		p.decision.Outcome = outcome
		r := permissionRequest(f, permissionQuery)
		w := serve(t, h, r)
		var out struct {
			Decision            string `json:"decision"`
			OrganizationVersion uint64 `json:"organizationVersion"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Decision != outcome.String() || out.OrganizationVersion != 3 || p.native.calls != 1 || f.rate.calls != 0 {
			t.Fatal("native permission decision changed", outcome, w.Code)
		}
		if p.request.Authentication.TenantID != "tenant-a" || p.request.Authentication.Bearer.Token() != f.wire || p.request.OrganizationID != "organization-a" || p.request.OrganizationVersion != 3 || p.request.Action != "document.read" || p.request.ResourceType != "document" || p.request.ResourceID != "document-a" || p.request.CorrelationID == "" {
			t.Fatal("permission check changed trusted scope or exact intent")
		}
	}
}

func TestPermissionCheckRejectsClosedInputBeforeAuthority(t *testing.T) {
	queries := []string{"", strings.Replace(permissionQuery, "organizationVersion=3&", "", 1), strings.Replace(permissionQuery, "organizationVersion=3", "organizationVersion=0", 1), strings.Replace(permissionQuery, "organizationVersion=3", "organizationVersion=03", 1), strings.Replace(permissionQuery, "organizationVersion=3", "organizationVersion=+3", 1), strings.Replace(permissionQuery, "organizationVersion=3", "organizationVersion=3.0", 1), strings.Replace(permissionQuery, "organizationVersion=3", "organizationVersion=18446744073709551616", 1), strings.Replace(permissionQuery, "action=document.read", "action=document.*", 1), strings.Replace(permissionQuery, "resourceID=document-a", "resourceID=", 1), strings.Replace(permissionQuery, "resourceType=document", "resourceType=%00", 1)}
	for _, suffix := range []string{"&actorID=other", "&tenantID=other", "&userID=other", "&context=grant", "&commandID=other", "&limit=1", "&organizationID=other", "&resourceID=other", "&OrganizationID=other", "&bad=%xx"} {
		queries = append(queries, permissionQuery+suffix)
	}
	for _, query := range queries {
		f, p, h := permissionFixture(t)
		if w := serve(t, h, permissionRequest(f, query)); w.Code != 400 || p.native.calls != 0 || f.reads.Load() != 0 {
			t.Fatal("invalid permission selector reached authority", query, w.Code)
		}
	}
	for _, mode := range []string{"key", "alternate-key", "duplicate-bearer", "cookie-only", "body", "method", "plaintext", "host"} {
		t.Run(mode, func(t *testing.T) {
			f, p, h := permissionFixture(t)
			r := permissionRequest(f, permissionQuery)
			switch mode {
			case "key":
				r.Header.Set("Idempotency-Key", "forbidden-key")
			case "alternate-key":
				r.AddCookie(&http.Cookie{Name: "Idempotency-Key", Value: "forbidden-key"})
			case "duplicate-bearer":
				r.Header.Add("Authorization", r.Header.Get("Authorization"))
			case "cookie-only":
				r.Header.Del("Authorization")
				r.AddCookie(&http.Cookie{Name: "session", Value: f.wire})
			case "body":
				r.Body = http.NoBody
				r.ContentLength = 1
			case "method":
				r.Method = http.MethodPost
			case "plaintext":
				r.TLS = nil
			case "host":
				r.Host = "other.example"
			}
			if w := serve(t, h, r); w.Code == 200 || p.native.calls != 0 || f.reads.Load() != 0 {
				t.Fatal("permission channel bypass", mode, w.Code)
			}
		})
	}
}

func TestPermissionCheckWithholdsInvalidOrLateNativeDecision(t *testing.T) {
	for _, mode := range []string{"revision", "zero-revision", "undefined", "not-applicable", "forbidden", "unavailable", "expired", "cancelled", "panic", "inactive", "closed-rate"} {
		t.Run(mode, func(t *testing.T) {
			f, p, h := permissionFixture(t)
			r := permissionRequest(f, permissionQuery)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			r = r.WithContext(ctx)
			want, calls := 503, 1
			switch mode {
			case "revision":
				p.decision.Revision = 4
			case "zero-revision":
				p.decision.Revision = 0
			case "undefined":
				p.decision.Outcome = 0
			case "not-applicable":
				p.decision.Outcome = authorization.NotApplicable
			case "forbidden":
				p.native.err = organization.ErrForbidden
				want = 403
			case "unavailable":
				p.native.err = organization.ErrUnavailable
			case "expired":
				p.native.beforeCall = func() { f.now = f.now.Add(20 * time.Second) }
			case "cancelled":
				p.native.beforeCall = cancel
			case "panic":
				p.native.beforeCall = func() { panic("private permission diagnostic") }
			case "inactive":
				f.inactive = true
				want, calls = 403, 0
			case "closed-rate":
				f.c.SafeRate.Close()
				calls = 0
			}
			w := serve(t, h, r)
			if w.Code != want || p.native.calls != calls || strings.Contains(w.Body.String(), `"decision"`) || strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), f.wire) {
				t.Fatal("unsafe permission decision escaped", mode, w.Code)
			}
		})
	}
}

func TestPermissionCheckRequiresSelectedOwnersAndNoDisabledMetadata(t *testing.T) {
	for _, mode := range []string{"nil-port", "typed-port", "session", "rate"} {
		f, p, _ := permissionFixture(t)
		switch mode {
		case "nil-port":
			f.c.PermissionChecker = nil
		case "typed-port":
			p = nil
			f.c.PermissionChecker = p
		case "session":
			f.c.Sessions = nil
		case "rate":
			f.c.SafeRate = nil
		}
		if _, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, PermissionCheck: true}); err == nil {
			t.Fatal("missing permission dependency accepted", mode)
		}
	}
	f := newFixture(t)
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, Get: true})
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "No permission check", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(doc.JSON()), "/v1/organization/permission-check") {
		t.Fatal("disabled permission metadata escaped")
	}
	if w := serve(t, h, permissionRequest(f, permissionQuery)); w.Code != 404 {
		t.Fatal("disabled permission route escaped", w.Code)
	}
}

func TestPermissionCheckTerminalReadEpochAndConcreteWire(t *testing.T) {
	f, p, _ := permissionFixture(t)
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, PermissionCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Member permission", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	for _, epoch := range []uint64{3, ^uint64(0)} {
		p.decision.Revision = authorization.Revision(epoch)
		r := permissionRequest(f, strings.Replace(permissionQuery, "organizationVersion=3", "organizationVersion="+strconv.FormatUint(epoch, 10), 1))
		w := serve(t, h, r)
		var out organizationhttp.PermissionCheckResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.OrganizationVersion != epoch || out.Decision != "allow" {
			t.Fatal("read-only terminal epoch changed", w.Code)
		}
		assertWireResponse(t, doc.JSON(), r, w)
	}
}

func FuzzPermissionCheckClosedQuery(f *testing.F) {
	for _, seed := range []string{permissionQuery, "", permissionQuery + "&tenantID=other", strings.Replace(permissionQuery, "Version=3", "Version=18446744073709551615", 1), permissionQuery + "&action=duplicate"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			return
		}
		x, p, h := permissionFixture(t)
		r := permissionRequest(x, raw)
		w := serve(t, h, r)
		if p.native.calls > 1 || w.Code == 200 && p.native.calls != 1 || strings.Contains(w.Body.String(), x.wire) {
			t.Fatal("permission owner bypass, repeat or custody disclosure")
		}
		if p.native.calls == 1 {
			q, err := url.ParseQuery(raw)
			n, e := strconv.ParseUint(q.Get("organizationVersion"), 10, 64)
			if err != nil || len(q) != 5 || e != nil || n == 0 || strconv.FormatUint(n, 10) != q.Get("organizationVersion") || p.request.OrganizationVersion != n || string(p.request.OrganizationID) != q.Get("organizationID") || string(p.request.Action) != q.Get("action") || string(p.request.ResourceType) != q.Get("resourceType") || string(p.request.ResourceID) != q.Get("resourceID") || p.request.Authentication.TenantID != "tenant-a" || p.request.Authentication.Bearer.Token() != x.wire {
				t.Fatal("permission query changed native scope")
			}
		}
	})
}
