package sessionhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
	"github.com/felixge/httpsnoop"
)

type guestReadFixture struct {
	base        *fixture
	wire        string
	observation session.SessionObservation
	reads       atomic.Int32
}

func newGuestReadFixture(t *testing.T) *guestReadFixture {
	t.Helper()
	f := newFixture(t, session.CredentialCookie)
	g := &guestReadFixture{base: f}
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	g.wire, err = token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	key, err := session.NewDigestKey(1, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := f.observation.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	spec.SessionID, spec.FamilyID, spec.UserID = "guest-session", "guest-family", "guest-user"
	spec.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationAnonymous, AnonymousAt: spec.IssuedAt}
	spec.Lookup, err = token.Digest(key, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	g.observation = session.SessionObservation{Session: record, Current: spec.Authority, Active: true, ReadStartedAt: f.config.Now(), ValidUntil: f.config.Now().Add(20 * time.Second)}
	owner, err := session.NewAnonymousSessionService(reader(func(ctx context.Context, lookup session.SessionLookup) (session.SessionObservation, error) {
		g.reads.Add(1)
		if _, bounded := ctx.Deadline(); !bounded || lookup.TenantID != "tenant-a" {
			t.Fatal("guest read lost bounded tenant custody")
		}
		return g.observation, nil
	}), session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "identity-service", Clock: clock(f.config.Now), MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_guest", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	f.config.Anonymous = &sessionhttp.AnonymousGetConfig{Sessions: owner, Cookie: cookie}
	return g
}

func (g *guestReadFixture) request() *http.Request {
	r := request(g.base, false)
	r.AddCookie(&http.Cookie{Name: "__Host-identity_guest", Value: g.wire})
	return r
}

func TestGetHTTPAnonymousRecognitionIsNeverVerifiedAuthentication(t *testing.T) {
	g := newGuestReadFixture(t)
	w := serve(t, g.base, g.request())
	var got struct {
		Authenticated bool
		Principal     *json.RawMessage
		Session       *json.RawMessage
		NeedsRefresh  bool
		Anonymous     *struct {
			Recognized bool
			Principal  sessionhttp.Principal
			Session    sessionhttp.Session
		}
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Authenticated || got.NeedsRefresh || got.Principal != nil || got.Session != nil || got.Anonymous == nil || !got.Anonymous.Recognized || got.Anonymous.Principal.TenantID != "tenant-a" || got.Anonymous.Principal.UserID != "guest-user" || got.Anonymous.Session.ID != "guest-session" {
		t.Fatal("anonymous session was absent, mis-scoped or represented as verified authentication")
	}
	lifetime, err := g.observation.Session.Lifetime(g.base.config.Now())
	if err != nil || !got.Anonymous.Session.ExpiresAt.Equal(lifetime.ExpiresAt) || !got.Anonymous.Session.AbsoluteExpiresAt.Equal(lifetime.AbsoluteExpiresAt) {
		t.Fatal("anonymous read renewed or lost the original session lifetime")
	}
	for _, private := range []string{g.wire, "guest-family", "lookup", "digest", "authority", "proof", "credential"} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatal("anonymous read disclosed private owner state")
		}
	}
	if g.reads.Load() != 1 || g.base.calls.Load() != 0 {
		t.Fatal("selected guest credential entered the verified owner or was read more than once")
	}

	// With both valid, separately named cookies present the permanent channel
	// wins explicitly. A failed permanent read must never fall back to a guest.
	r := g.request()
	r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: g.base.wire})
	w = serve(t, g.base, r)
	got.Anonymous = nil
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || !got.Authenticated || got.Anonymous != nil || g.reads.Load() != 1 {
		t.Fatal("dual-cookie read changed the selected permanent identity or acquired guest fallback")
	}
	g.base.observation.Active = false
	w = serve(t, g.base, r)
	if w.Code != 200 || w.Body.String() != "{\"authenticated\":false,\"needsRefresh\":false}\n" || g.reads.Load() != 1 {
		t.Fatal("inactive permanent credential fell back to a guest identity")
	}
	g.base.fail.Store(true)
	w = serve(t, g.base, r)
	if w.Code != 503 || g.reads.Load() != 1 || strings.Contains(w.Body.String(), "guest-user") {
		t.Fatal("failed permanent authority read fell back to guest disclosure")
	}

	g.base.config.Anonymous = nil
	w = serve(t, g.base, g.request())
	if w.Code != 200 || w.Body.String() != "{\"authenticated\":false,\"needsRefresh\":false}\n" || g.reads.Load() != 1 {
		t.Fatal("unselected anonymous profile advertised or acquired guest authority")
	}
}

func TestGetHTTPAnonymousSelectionRejectsAmbiguousOwnersAndCookies(t *testing.T) {
	for _, mode := range []string{"nil-owner", "zero-owner", "same-cookie", "bearer-profile"} {
		t.Run(mode, func(t *testing.T) {
			g := newGuestReadFixture(t)
			switch mode {
			case "nil-owner":
				g.base.config.Anonymous.Sessions = nil
			case "zero-owner":
				g.base.config.Anonymous.Sessions = &session.AnonymousSessionService{}
			case "same-cookie":
				g.base.config.Anonymous.Cookie = g.base.config.Cookie
			case "bearer-profile":
				g.base.config.Transport = session.CredentialBearer
			}
			if _, err := sessionhttp.NewGetHandler(g.base.config); err == nil || g.reads.Load() != 0 || g.base.calls.Load() != 0 {
				t.Fatal("ambiguous guest profile constructed or performed owner IO")
			}
		})
	}
	g := newGuestReadFixture(t)
	r := g.request()
	r.AddCookie(&http.Cookie{Name: "__Host-identity_guest", Value: g.wire})
	w := httptest.NewRecorder()
	h, err := sessionhttp.NewGetHandler(g.base.config)
	if err != nil {
		t.Fatal(err)
	}
	h.ServeHTTP(w, r)
	if w.Code != 400 || g.reads.Load() != 0 || g.base.calls.Load() != 0 {
		t.Fatal("duplicate guest credentials reached an owner")
	}
}

func TestGetHTTPAnonymousCustodyStaysUnprivilegedAndExpiresAfterHooks(t *testing.T) {
	for _, expired := range []bool{false, true} {
		g := newGuestReadFixture(t)
		now := g.base.config.Now()
		g.base.config.Now = func() time.Time { return now }
		hook := logoutMiddleware(identityhttp.MiddlewareBeforeHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			state, ok := identityhttp.PipelineValue[sessionhttp.GetState](r)
			principal, admitted := state.Principal()
			if !ok || admitted || principal != (sessionhttp.Principal{}) {
				t.Error("guest entered verified middleware admission")
			}
			if expired {
				now = now.Add(20 * time.Second)
			}
			next.ServeHTTP(w, r)
		})
		h, err := sessionhttp.NewGetHandlerWithMiddleware(g.base.config, []identityhttp.MiddlewareDescriptor{hook})
		if err != nil {
			t.Fatal(err)
		}
		// Constructor copies optional policy, not the caller-owned pointer.
		g.base.config.Anonymous.Sessions = nil
		g.base.config.Anonymous.Cookie = g.base.config.Cookie
		w := httptest.NewRecorder()
		h.ServeHTTP(w, g.request())
		want := 200
		if expired {
			want = 503
		}
		if w.Code != want || g.reads.Load() != 1 || (expired && strings.Contains(w.Body.String(), "guest-user")) || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("guest admission changed after construction or original custody was renewed")
		}
	}
}

func TestGetOriginalCustodyExpiresInsideResponseForwarding(t *testing.T) {
	for _, guest := range []bool{false, true} {
		for _, forwardedStatus := range []int{http.StatusOK, http.StatusCreated, http.StatusForbidden} {
			for _, boundary := range []string{"live", "at-expiry", "clock-panic"} {
				t.Run(fmt.Sprintf("guest=%t/status=%d/%s", guest, forwardedStatus, boundary), func(t *testing.T) {
					g := newGuestReadFixture(t)
					now := g.base.config.Now()
					// Both explicitly selected test services use 1ms uncertainty.
					until := g.observation.ValidUntil.Add(-time.Millisecond)
					commitAt := until.Add(-time.Nanosecond)
					if boundary == "at-expiry" {
						commitAt = until
					}
					panicClock := false
					g.base.config.Now = func() time.Time {
						if panicClock {
							panic("test clock unavailable")
						}
						return now
					}
					hook := logoutMiddleware(identityhttp.MiddlewareBeforeHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
						forward := httpsnoop.Wrap(w, httpsnoop.Hooks{WriteHeader: func(write httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
							return func(status int) {
								now = commitAt
								panicClock = boundary == "clock-panic"
								if status == http.StatusOK {
									status = forwardedStatus
								}
								write(status)
							}
						}})
						next.ServeHTTP(forward, r)
					})
					h, err := sessionhttp.NewGetHandlerWithMiddleware(g.base.config, []identityhttp.MiddlewareDescriptor{hook})
					if err != nil {
						t.Fatal(err)
					}
					r := g.request()
					if !guest {
						r = request(g.base, true)
					}
					w := httptest.NewRecorder()
					h.ServeHTTP(w, r)
					if boundary == "live" {
						if w.Code != forwardedStatus || !strings.Contains(w.Body.String(), "user") {
							t.Fatal("live original custody was rejected")
						}
						return
					}
					if w.Code != 503 || strings.Contains(w.Body.String(), "user") || strings.Contains(w.Body.String(), "recognized") || len(w.Result().Cookies()) != 0 {
						t.Fatal("expired original custody reached committed metadata", w.Code)
					}
				})
			}
		}
	}
}

func TestGetHTTPAnonymousActualResponseMatchesSelectedWire(t *testing.T) {
	g := newGuestReadFixture(t)
	logout := newLogout(t, session.CredentialCookie)
	logout.config.GetConfig = g.base.config
	feature, err := sessionhttp.NewFeature(logout.config)
	if err != nil {
		t.Fatal(err)
	}
	h, document, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, g.request())
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"anonymous"`) {
		t.Fatal("selected guest route did not recognize the actual owner")
	}
	parsed, err := openapi.ParseJSON(t.Context(), bytes.NewReader(document.JSON()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	node := parsed.Raw()
	for _, key := range []string{"paths", "/v1/session/get", "get", "responses", "200", "content", "application/json", "schema"} {
		var ok bool
		node, ok = node.Lookup(key)
		if !ok {
			t.Fatal("selected guest response schema missing")
		}
	}
	instance, err := parse.JSON(t.Context(), bytes.NewReader(w.Body.Bytes()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	report, err := validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
	if err != nil || !report.Valid() {
		t.Fatal("actual guest response disagrees with advertised wire")
	}
	// The document must not admit elevation by flipping the verified bit while
	// retaining a guest response; it is not a second permanent-session shape.
	bad := strings.Replace(w.Body.String(), `"authenticated":false`, `"authenticated":true`, 1)
	instance, err = parse.JSON(t.Context(), strings.NewReader(bad), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	report, err = validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{})
	if err != nil || report.Valid() {
		t.Fatal("guest wire allowed verified-user elevation")
	}
}
