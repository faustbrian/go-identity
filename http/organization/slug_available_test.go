package organizationhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	organization "github.com/faustbrian/go-organization"
)

type slugAvailabilityPort struct {
	t         testing.TB
	last      organization.SlugAvailableRequest
	calls     int
	available bool
	err       error
	before    func()
}

func (p *slugAvailabilityPort) SlugAvailable(ctx context.Context, r organization.SlugAvailableRequest) (organization.SlugAvailableResult, error) {
	if _, ok := ctx.Deadline(); !ok {
		p.t.Fatal("unbounded native slug read")
	}
	p.last, p.calls = r, p.calls+1
	if p.before != nil {
		p.before()
	}
	return organization.SlugAvailableResult{Available: p.available}, p.err
}

func slugAvailabilityFeature(t testing.TB, f *fixture, p *slugAvailabilityPort) identityhttp.Feature {
	t.Helper()
	f.c.Service, f.c.Invitations, f.c.AdminRate = nil, nil, nil
	f.c.SlugAvailability = p
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, SlugAvailable: true})
	if err != nil {
		t.Fatal("independent slug selection", err)
	}
	return feature
}

func slugAvailabilityHandler(t testing.TB, f *fixture, p *slugAvailabilityPort) http.Handler {
	t.Helper()
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{slugAvailabilityFeature(t, f, p)}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func slugRequest(f *fixture, query string) *http.Request {
	r := request(f, "/v1/organization/slug-available?"+query, "", false)
	r.Method = http.MethodGet
	return r
}

func TestSlugAvailabilityUsesOnlyAuthenticatedCandidateRead(t *testing.T) {
	f := newFixture(t)
	p := &slugAvailabilityPort{t: t, available: true}
	h := slugAvailabilityHandler(t, f, p)
	for _, available := range []bool{true, false} {
		p.available = available
		w := serve(t, h, slugRequest(f, "slug=candidate-slug"))
		var fields map[string]bool
		decodeErr := json.Unmarshal(w.Body.Bytes(), &fields)
		value, present := fields["available"]
		if w.Code != 200 || decodeErr != nil || len(fields) != 1 || !present || value != available {
			t.Fatal("advisory response changed or disclosed organization metadata", w.Code, w.Body.String())
		}
		if p.last.Authentication.TenantID != "tenant-a" || p.last.Authentication.Bearer.Token() != f.wire || p.last.Slug != "candidate-slug" || p.last.CorrelationID == "" {
			t.Fatal("candidate read replaced authenticated scope")
		}
	}
	if p.calls != 2 || f.port.calls != 0 || f.rate.calls != 0 {
		t.Fatal("slug selection invoked membership, mutation or administrator admission")
	}
}

func TestSlugAvailabilityRejectsAlternateChannelsBeforeOwners(t *testing.T) {
	for name, change := range map[string]func(*http.Request){
		"missing":          func(r *http.Request) { r.URL.RawQuery = "" },
		"duplicate":        func(r *http.Request) { r.URL.RawQuery = "slug=one&slug=two" },
		"empty":            func(r *http.Request) { r.URL.RawQuery = "slug=" },
		"uppercase":        func(r *http.Request) { r.URL.RawQuery = "slug=Upper" },
		"path":             func(r *http.Request) { r.URL.RawQuery = "slug=one%2Ftwo" },
		"overlong":         func(r *http.Request) { r.URL.RawQuery = "slug=" + strings.Repeat("a", 64) },
		"tenant":           func(r *http.Request) { r.URL.RawQuery += "&tenantID=other" },
		"organization":     func(r *http.Request) { r.URL.RawQuery += "&organizationID=private" },
		"key":              func(r *http.Request) { r.Header.Set("Idempotency-Key", "forbidden") },
		"duplicate-bearer": func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) },
		"cookie-only": func(r *http.Request) {
			r.Header.Del("Authorization")
			r.AddCookie(&http.Cookie{Name: "__Host-session", Value: "ambient"})
		},
		"body":      func(r *http.Request) { r.Body = http.NoBody; r.ContentLength = 1 },
		"method":    func(r *http.Request) { r.Method = http.MethodPost },
		"host":      func(r *http.Request) { r.Host = "other.example" },
		"plaintext": func(r *http.Request) { r.TLS = nil },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			p := &slugAvailabilityPort{t: t, available: true}
			h := slugAvailabilityHandler(t, f, p)
			r := slugRequest(f, "slug=candidate-slug")
			change(r)
			w := serve(t, h, r)
			if w.Code < 400 || p.calls != 0 || f.reads.Load() != 0 {
				t.Fatal("malformed request reached an authority owner", w.Code)
			}
		})
	}
}

func TestSlugAvailabilityWithholdsSuccessOnOwnerFailureAndExpiry(t *testing.T) {
	for _, mode := range []string{"forbidden", "unavailable", "expired", "cancelled", "panic"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			p := &slugAvailabilityPort{t: t, available: true}
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
			case "panic":
				p.before = func() { panic("private slug failure") }
			}
			w := serve(t, slugAvailabilityHandler(t, f, p), slugRequest(f, "slug=candidate").WithContext(ctx))
			var fields map[string]string
			decodeErr := json.Unmarshal(w.Body.Bytes(), &fields)
			if w.Code != want || decodeErr != nil || len(fields) != 1 || fields["error"] == "" || strings.Contains(w.Body.String(), "private") {
				t.Fatal("failed read exported availability or private details", w.Code, w.Body.String())
			}
		})
	}
}

func TestSlugAvailabilityRequiresSelectedOwnersAndSafeAdmission(t *testing.T) {
	for _, mode := range []string{"nil-owner", "typed-nil-owner", "session", "safe"} {
		f := newFixture(t)
		p := &slugAvailabilityPort{t: t}
		f.c.SlugAvailability = p
		switch mode {
		case "nil-owner":
			f.c.SlugAvailability = nil
		case "typed-nil-owner":
			f.c.SlugAvailability = (*slugAvailabilityPort)(nil)
		case "session":
			f.c.Sessions = nil
		case "safe":
			f.c.SafeRate = nil
		}
		if _, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, SlugAvailable: true}); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("selected feature accepted missing owner", mode, err)
		}
	}
	f := newFixture(t)
	p := &slugAvailabilityPort{t: t, available: true}
	h := slugAvailabilityHandler(t, f, p)
	if err := f.c.SafeRate.Close(); err != nil {
		t.Fatal(err)
	}
	if w := serve(t, h, slugRequest(f, "slug=candidate")); w.Code != 503 || p.calls != 0 {
		t.Fatal("safe-rate outage reached candidate read", w.Code)
	}
}

func TestSlugAvailabilityWireAndDisabledSurface(t *testing.T) {
	f := newFixture(t)
	p := &slugAvailabilityPort{t: t, available: true}
	h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Slug availability", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{slugAvailabilityFeature(t, f, p)}})
	if err != nil {
		t.Fatal(err)
	}
	r := slugRequest(f, "slug=candidate")
	w := serve(t, h, r)
	assertWireResponse(t, doc.JSON(), r, w)
	if w.Code != 200 || p.calls != 1 {
		t.Fatal("documented candidate read failed", w.Code)
	}
	var shape struct {
		Paths map[string]struct {
			Get struct {
				Parameters  []struct{ Name string }
				RequestBody json.RawMessage
			}
		}
	}
	if json.Unmarshal(doc.JSON(), &shape) != nil || len(shape.Paths) != 1 {
		t.Fatal("slug option advertised sibling features")
	}
	op := shape.Paths["/v1/organization/slug-available"].Get
	if len(op.Parameters) != 1 || op.Parameters[0].Name != "slug" || len(op.RequestBody) != 0 {
		t.Fatal("wire accepted identity/key/body selectors")
	}
	base := newFixture(t)
	disabledFeature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: base.c, Get: true})
	if err != nil {
		t.Fatal(err)
	}
	disabled, disabledDoc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "No slug option", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{disabledFeature}})
	if err != nil || strings.Contains(string(disabledDoc.JSON()), "/v1/organization/slug-available") {
		t.Fatal("disabled slug feature exposed metadata", err)
	}
	if out := serve(t, disabled, slugRequest(base, "slug=candidate")); out.Code != 404 {
		t.Fatal("disabled slug feature exposed route", out.Code)
	}
}

func FuzzSlugAvailabilityClosedQuery(f *testing.F) {
	for _, seed := range []string{"slug=candidate", "slug=a--b", "slug=", "slug=one&slug=two", "slug=%FF", "slug=one%2Ftwo", "slug=a&tenantID=other", "slug=" + strings.Repeat("a", 64)} {
		f.Add(seed)
	}
	grammar := regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			return
		}
		x := newFixture(t)
		p := &slugAvailabilityPort{t: t, available: true}
		r := slugRequest(x, "slug=candidate")
		r.URL.RawQuery = raw
		w := serve(t, slugAvailabilityHandler(t, x, p), r)
		if p.calls != 0 {
			q, err := url.ParseQuery(raw)
			if err != nil || len(q) != 1 || len(q["slug"]) != 1 || !grammar.MatchString(q.Get("slug")) || p.last.Slug != q.Get("slug") || p.last.Authentication.TenantID != "tenant-a" || p.calls != 1 {
				t.Fatal("hostile query changed the admitted candidate scope")
			}
		}
		if w.Code == 200 && p.calls != 1 {
			t.Fatal("successful availability bypassed its native owner")
		}
	})
}
