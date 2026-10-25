package organizationhttp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	organization "github.com/faustbrian/go-organization"
)

// This transport-port fixture does not establish native recipient authority;
// the tagged genuine-consumer test exercises that separate owner boundary.
type invitationReader struct {
	get    organization.InvitationReadRequest
	mine   organization.InvitationListMineRequest
	calls  int
	err    error
	change func(*organization.Invitation)
}

func (p *invitationReader) invitation() organization.Invitation {
	i := organization.Invitation{ID: "invitation-a", OrganizationID: "organization-a", TenantID: "tenant-a", RecipientUserID: "user-a", RecipientIdentifierID: "identifier-a", RecipientIdentifierVersion: 1, CreatedBy: "owner-a", Role: organization.RoleMember, Status: organization.InvitationPending, Version: 1, IssuedVersion: 1, ExpiresAt: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)}
	if p.change != nil {
		p.change(&i)
	}
	return i
}
func (p *invitationReader) Get(ctx context.Context, r organization.InvitationReadRequest) (organization.InvitationDelivery, error) {
	p.calls++
	p.get = r
	return organization.InvitationDelivery{Invitation: p.invitation()}, p.err
}
func (p *invitationReader) ListMine(ctx context.Context, r organization.InvitationListMineRequest) (organization.InvitationListMineResult, error) {
	p.calls++
	p.mine = r
	return organization.InvitationListMineResult{Invitations: []organization.Invitation{p.invitation()}}, p.err
}
func invitationHandler(t testing.TB, f *fixture, p *invitationReader) http.Handler {
	t.Helper()
	f.c.Service, f.c.AdminRate, f.c.Invitations = nil, nil, p
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, InvitationGet: true, InvitationListMine: true})
	if err != nil {
		t.Fatal("invitation-only feature requires unrelated owner", err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func TestInvitationReadsUseIndependentNativePort(t *testing.T) {
	f := newFixture(t)
	p := new(invitationReader)
	h := invitationHandler(t, f, p)
	w := serve(t, h, request(f, "/v1/organization/invitation/list-mine?limit=1", "", false))
	if w.Code != 200 || p.calls != 1 || p.mine.Limit != 1 || p.mine.Authentication.TenantID != "tenant-a" || p.mine.Authentication.Bearer.Token() != f.wire || p.mine.CorrelationID == "" {
		t.Fatal("recipient discovery lost current native scope", w.Code)
	}
	var page struct {
		Invitations []organizationhttp.InvitationView `json:"invitations"`
	}
	if json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Invitations) != 1 || page.Invitations[0].Status != "pending" {
		t.Fatal("safe invitation projection missing")
	}
	for _, private := range []string{f.wire, "identifier-a", "owner-a", "user-a", "EffectID", "email", "capability", "recipientIdentifier"} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatal("invitation private data escaped")
		}
	}
	w = serve(t, h, request(f, "/v1/organization/invitation/get?organizationID=organization-a&invitationID=invitation-a", "", false))
	if w.Code != 200 || p.get.OrganizationID != "organization-a" || p.get.ID != "invitation-a" || p.get.CorrelationID == "" {
		t.Fatal("owner get lost exact native request", w.Code)
	}
	p.err = organization.ErrForbidden
	if w = serve(t, h, request(f, "/v1/organization/invitation/get?organizationID=organization-a&invitationID=invitation-a", "", false)); w.Code != 403 {
		t.Fatal("native owner-only denial changed", w.Code)
	}
}
func TestInvitationRejectsHostileInputBeforeOwner(t *testing.T) {
	for name, mutate := range map[string]func(*http.Request){
		"subject-override":   func(r *http.Request) { r.URL.RawQuery = "recipientID=other" },
		"tenant-override":    func(r *http.Request) { r.URL.RawQuery = "tenantID=other" },
		"duplicate-limit":    func(r *http.Request) { r.URL.RawQuery = "limit=1&limit=2" },
		"zero":               func(r *http.Request) { r.URL.RawQuery = "limit=0" },
		"over-limit":         func(r *http.Request) { r.URL.RawQuery = "limit=201" },
		"noncanonical-limit": func(r *http.Request) { r.URL.RawQuery = "limit=01" },
		"oversized-cursor":   func(r *http.Request) { r.URL.RawQuery = "cursor=" + strings.Repeat("x", 513) },
		"empty-cursor":       func(r *http.Request) { r.URL.RawQuery = "cursor=" },
		"key":                func(r *http.Request) { r.Header.Set("Idempotency-Key", "forbidden") },
		"duplicate-bearer":   func(r *http.Request) { r.Header.Add("authorization", r.Header.Get("Authorization")) },
		"cookie-only": func(r *http.Request) {
			r.Header.Del("Authorization")
			r.AddCookie(&http.Cookie{Name: "__Host-session", Value: fallbackToken})
		},
		"body":        func(r *http.Request) { r.Body = http.NoBody; r.ContentLength = 1 },
		"force-query": func(r *http.Request) { r.URL.ForceQuery = true },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			p := new(invitationReader)
			h := invitationHandler(t, f, p)
			r := request(f, "/v1/organization/invitation/list-mine", "", false)
			mutate(r)
			w := serve(t, h, r)
			if w.Code != 400 || p.calls != 0 || f.reads.Load() != 0 {
				t.Fatal("hostile input reached current owner", w.Code)
			}
		})
	}
}

const fallbackToken = "ambient-is-never-authority"

func TestInvitationCurrentSessionAndOutputFence(t *testing.T) {
	for name, change := range map[string]func(*organization.Invitation){
		"foreign-tenant":    func(i *organization.Invitation) { i.TenantID = "other" },
		"foreign-recipient": func(i *organization.Invitation) { i.RecipientUserID = "other" },
		"unknown-status":    func(i *organization.Invitation) { i.Status = 99 },
		"invalid-id":        func(i *organization.Invitation) { i.ID = "bad id" },
		"invalid-role":      func(i *organization.Invitation) { i.Role = "unexpected" },
		"zero-version":      func(i *organization.Invitation) { i.Version = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			p := &invitationReader{change: change}
			h := invitationHandler(t, f, p)
			w := serve(t, h, request(f, "/v1/organization/invitation/list-mine", "", false))
			if w.Code != 503 || strings.Contains(w.Body.String(), "invitation-a") {
				t.Fatal("unsafe native metadata disclosed", w.Code)
			}
		})
	}
	f := newFixture(t)
	p := new(invitationReader)
	h := invitationHandler(t, f, p)
	f.inactive = true
	if w := serve(t, h, request(f, "/v1/organization/invitation/list-mine", "", false)); w.Code != 403 || p.calls != 0 {
		t.Fatal("revoked session reached invitation owner", w.Code)
	}
}
func TestInvitationSelectionOmitsUnselectedRoutesAndMetadata(t *testing.T) {
	f := newFixture(t)
	f.c.Service = nil
	f.c.AdminRate = nil
	f.c.Invitations = new(invitationReader)
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, InvitationListMine: true})
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: f.c.Network, HandlerTimeout: 3 * time.Second, Document: identityhttp.DocumentConfig{Title: "Invitation", Version: "1"}}, ops, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Operations()) != 1 || strings.Contains(string(doc.JSON()), `"/v1/organization/invitation/get"`) || strings.Contains(string(doc.JSON()), `"/v1/organization/create"`) {
		t.Fatal("unselected invitation operations advertised")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(f, "/v1/organization/invitation/get?organizationID=organization-a&invitationID=invitation-a", "", false))
	if w.Code != 404 {
		t.Fatal("unselected invitation get exposed", w.Code)
	}
}

func TestInvitationSharesCanonicalSafeRateAcrossReads(t *testing.T) {
	f := newFixture(t)
	p := new(invitationReader)
	h := invitationHandler(t, f, p)
	for n := 0; n < 100; n++ {
		path := "/v1/organization/invitation/list-mine"
		if n%2 == 0 {
			path = "/v1/organization/invitation/get?organizationID=organization-a&invitationID=invitation-a"
		}
		if w := serve(t, h, request(f, path, "", false)); w.Code != 200 {
			t.Fatal("safe read denied below shared IP budget", n, w.Code)
		}
	}
	w := serve(t, h, request(f, "/v1/organization/invitation/list-mine", "", false))
	if w.Code != 429 || p.calls != 100 || w.Header().Get("Retry-After") == "" {
		t.Fatal("invitation reads bypassed shared canonical safe budget", w.Code, p.calls)
	}
}

func TestInvitationGetRejectsIncompleteOrAlternateScope(t *testing.T) {
	for _, query := range []string{"", "organizationID=organization-a", "invitationID=invitation-a", "organizationID=organization-a&invitationID=", "organizationID=organization-a&invitationID=invitation-a&limit=1", "organizationID=organization-a&invitationID=invitation-a&recipientID=other", "organizationID=organization-a&invitationID=invitation-a&invitationID=other"} {
		t.Run(query, func(t *testing.T) {
			f := newFixture(t)
			p := new(invitationReader)
			h := invitationHandler(t, f, p)
			w := serve(t, h, request(f, "/v1/organization/invitation/get?"+query, "", false))
			if w.Code != 400 || p.calls != 0 || f.reads.Load() != 0 {
				t.Fatal("invalid invitation get scope reached owner", w.Code)
			}
		})
	}
}

func FuzzInvitationHTTPBoundary(f *testing.F) {
	fixture := newFixture(f)
	port := new(invitationReader)
	h := invitationHandler(f, fixture, port)
	for _, seed := range []struct {
		query, auth string
		kind        uint8
	}{
		{"", "valid", 0},
		{"limit=1", "valid", 0},
		{"limit=200&cursor=opaque_Continuation-1", "valid", 0},
		{"organizationID=organization-a&invitationID=invitation-a", "valid", 1},
		{"limit=1&limit=2", "valid", 0},
		{"limit=01", "valid", 0},
		{"limit=0", "valid", 0},
		{"limit=201", "valid", 0},
		{"limit=4294967296", "valid", 0},
		{"limit=18446744073709551616", "valid", 0},
		{"limit=1e2", "valid", 0},
		{"cursor=", "valid", 0},
		{"cursor=" + strings.Repeat("x", 513), "valid", 0},
		{"cursor=first&cursor=second", "valid", 0},
		{"cursor=%ZZ", "valid", 0},
		{"cursor=%00", "valid", 0},
		{"cursor=a%2Fb%3D", "valid", 0},
		{"cursor=a;limit=1", "valid", 0},
		{"Limit=1", "valid", 0},
		{"recipientID=other&tenantID=other&bearer=alternate", "valid", 0},
		{"organizationID=organization-a&invitationID=invitation-a&invitationID=other", "valid", 1},
		{"organizationID=organization-a&invitationID=%00", "valid", 1},
		{"organizationID=" + strings.Repeat("x", 129) + "&invitationID=invitation-a", "valid", 1},
		{"organizationID=organization-a&invitationID=invitation-a&actorID=other", "valid", 1},
		{"limit=1", "Bearer  malformed", 0},
		{"limit=1", "Basic alternate", 0},
		{"limit=1", "", 0},
		{"limit=1", "valid", 2},                                                   // Duplicate bearer.
		{"limit=1", "valid", 4},                                                   // Cookie-only alternate authority.
		{"limit=1", "valid", 8},                                                   // Forbidden idempotency channel.
		{"limit=1", "valid", 16},                                                  // Caller cancellation.
		{"limit=1", "valid", 32},                                                  // Noncanonical forced query.
		{"limit=1", "valid", 64},                                                  // Forbidden body.
		{"organizationID=organization-a&invitationID=invitation-a", "valid", 129}, // Wrong method.
	} {
		f.Add(seed.query, seed.auth, seed.kind)
	}
	f.Fuzz(func(t *testing.T, query, auth string, kind uint8) {
		if len(query) > 4096 || len(auth) > 8192 {
			return
		}
		path := "/v1/organization/invitation/list-mine"
		if kind&1 != 0 {
			path = "/v1/organization/invitation/get"
		}
		r := request(fixture, path, "", false)
		r.URL.RawQuery = query
		if auth != "valid" {
			r.Header.Set("Authorization", auth)
		}
		if kind&2 != 0 {
			r.Header.Add("authorization", r.Header.Get("Authorization"))
		}
		if kind&4 != 0 {
			r.Header.Del("Authorization")
			r.AddCookie(&http.Cookie{Name: "__Host-session", Value: fallbackToken})
		}
		if kind&8 != 0 {
			r.Header.Set("Idempotency-Key", "forbidden-alternate-key")
		}
		if kind&16 != 0 {
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			r = r.WithContext(ctx)
		}
		r.URL.ForceQuery = kind&32 != 0
		if kind&64 != 0 {
			r.Body, r.ContentLength = http.NoBody, 1
		}
		if kind&128 != 0 {
			r.Method = http.MethodPost
		}
		reads, calls := fixture.reads.Load(), port.calls
		w := serve(t, h, r)
		switch w.Code {
		case 200, 400, 403, 404, 405, 421, 429, 503:
		default:
			t.Fatal("invitation boundary returned an undeclared status", w.Code)
		}
		if port.calls-calls > 1 || fixture.reads.Load()-reads > 1 {
			t.Fatal("hostile invitation input repeated an owned stage")
		}
		if (w.Code == 400 || w.Code == 404 || w.Code == 405 || w.Code == 421) && (port.calls != calls || fixture.reads.Load() != reads) {
			t.Fatal("rejected invitation envelope reached native owners")
		}
		// These deliberately forbidden channels must not become a syntactically
		// accepted shape, even after the shared rate budget has been exhausted.
		if kind&(2|4|8|32|64|128) != 0 && (port.calls != calls || fixture.reads.Load() != reads) {
			t.Fatal("alternate invitation input reached native authority")
		}
		if w.Body.Len() > 1<<20 || !json.Valid(w.Body.Bytes()) {
			t.Fatal("invitation response exceeded its bounded JSON contract")
		}
		for _, private := range []string{fixture.wire, fallbackToken, "forbidden-alternate-key", "identifier-a", "owner-a"} {
			if strings.Contains(w.Body.String(), private) {
				t.Fatal("hostile invitation request disclosed private custody")
			}
		}
	})
}
