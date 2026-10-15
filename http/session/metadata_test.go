package sessionhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authorization "github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-authorization/v3/acl"
	identityhttp "github.com/faustbrian/go-identity/http"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

func TestProtectedMetadataTransportResponsesMatchWire(t *testing.T) {
	for _, mode := range []session.CredentialKind{session.CredentialCookie, session.CredentialBearer} {
		for _, name := range []string{"https", "origin", "policy"} {
			t.Run(fmt.Sprint(mode, "/", name), func(t *testing.T) {
				f := newFixture(t, mode)
				effect := authorization.Allow
				if name == "policy" {
					effect = authorization.Deny
				}
				h, doc, err := sessionhttp.NewMetadataRouter(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, metadataSessionConfig(f, metadataPolicy(t, effect, "user-a", "tenant-a")), identityhttp.FeatureServices{}, nil)
				if err != nil {
					t.Fatal(err)
				}
				r := metadataSessionRequest(f, true)
				if name == "https" {
					r.TLS = nil
				}
				if name == "origin" {
					r.Header.Set("Origin", "https://other.example")
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				wantBody, wantMedia, wantReads := "{\"error\":\"denied\"}\n", "application/json", int32(1)
				if name == "https" {
					wantBody, wantReads = "{\"error\":\"https_required\"}\n", 0
				}
				if name == "origin" {
					wantBody, wantMedia, wantReads = "identity.http.origin_denied\n", "text/plain", 0
				}
				media, _, err := mime.ParseMediaType(w.Header().Get("Content-Type"))
				if err != nil || w.Code != 403 || w.Body.String() != wantBody || media != wantMedia || f.calls.Load() != wantReads || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Set-Cookie") != "" {
					t.Fatalf("incorrect denial status=%d media=%s reads=%d", w.Code, media, f.calls.Load())
				}
				parsed, err := openapi.ParseJSON(context.Background(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
				if err != nil {
					t.Fatal(err)
				}
				node := parsed.Raw()
				for _, key := range []string{"paths", "/openapi.json", "get", "responses", strconv.Itoa(w.Code), "content", media, "schema"} {
					var ok bool
					node, ok = node.Lookup(key)
					if !ok {
						t.Fatalf("missing actual response schema for %s media=%s", name, media)
					}
				}
				payload := w.Body.Bytes()
				if media == "text/plain" {
					payload, _ = json.Marshal(w.Body.String())
				}
				instance, err := parse.JSON(context.Background(), bytes.NewReader(payload), parse.DefaultLimits())
				if err != nil {
					t.Fatal(err)
				}
				report, err := validate.SchemaInstance(context.Background(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
				if err != nil || !report.Valid() {
					t.Fatalf("actual denial rejected by wire: %v %+v", err, report.Diagnostics())
				}
				bad := []byte(`{"error":"private_diagnostic"}`)
				if media == "text/plain" {
					bad = []byte(`"private_diagnostic"`)
				}
				instance, _ = parse.JSON(context.Background(), bytes.NewReader(bad), parse.DefaultLimits())
				report, err = validate.SchemaInstance(context.Background(), parsed, node, instance, validate.InstanceOptions{})
				if err != nil || report.Valid() {
					t.Fatal("wire admitted an arbitrary diagnostic")
				}
			})
		}
	}
}

func metadataPolicy(t *testing.T, effect authorization.Outcome, user, tenant string) *authorization.Engine {
	t.Helper()
	evaluator, err := acl.New([]acl.Entry{{ID: "metadata-admin", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)},
		Tenant: authorization.TenantID(tenant), Action: "metadata.read", ResourceType: "identity-metadata", ResourceID: "identity.openapi.document", Effect: effect}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := authorization.NewSnapshot(1, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "metadata", Revision: 1, Evaluator: evaluator})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := authorization.NewEngine(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func metadataSessionRequest(f *fixture, credential bool) *http.Request {
	r := request(f, credential)
	r.URL.Path, r.RequestURI = "/openapi.json", "/openapi.json"
	return r
}

func metadataSessionConfig(f *fixture, engine authorization.Authorizer) sessionhttp.MetadataConfig {
	return sessionhttp.MetadataConfig{Read: f.config, Authorization: engine, PolicyRevision: 1, Action: "metadata.read", ResourceType: "identity-metadata"}
}

func TestProtectedMetadataUsesRealSessionAndSeparateAdminPolicy(t *testing.T) {
	for _, mode := range []session.CredentialKind{session.CredentialCookie, session.CredentialBearer} {
		for _, effect := range []authorization.Outcome{authorization.Allow, authorization.Deny} {
			f := newFixture(t, mode)
			engine := metadataPolicy(t, effect, "user-a", "tenant-a")
			h, doc, err := sessionhttp.NewMetadataRouter(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, metadataSessionConfig(f, engine), identityhttp.FeatureServices{}, nil)
			if err != nil || f.calls.Load() != 0 {
				t.Fatal("metadata construction performed owner work", err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, metadataSessionRequest(f, false))
			if w.Code != 401 || bytes.Contains(w.Body.Bytes(), []byte("openapi")) || f.calls.Load() != 0 {
				t.Fatal("absent session disclosed metadata", w.Code)
			}
			challenge := "Bearer"
			if mode == session.CredentialCookie {
				challenge = "Session"
			}
			if w.Header().Get("WWW-Authenticate") != challenge {
				t.Fatal("challenge advertises another credential channel")
			}
			w = httptest.NewRecorder()
			h.ServeHTTP(w, metadataSessionRequest(f, true))
			want := 403
			if effect == authorization.Allow {
				want = 200
			}
			if w.Code != want || f.calls.Load() != 1 {
				t.Fatal("authentication replaced administrator authorization", w.Code)
			}
			if w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 {
				t.Fatal("metadata changed credential or cache policy")
			}
			if want == 200 && !bytes.Equal(w.Body.Bytes(), doc.JSON()) {
				t.Fatal("metadata served a different snapshot")
			}
			if want != 200 && bytes.Contains(w.Body.Bytes(), []byte("openapi")) {
				t.Fatal("denial disclosed document")
			}
			var wire struct {
				Paths map[string]map[string]struct {
					Security []map[string][]string `json:"security"`
				} `json:"paths"`
			}
			if json.Unmarshal(doc.JSON(), &wire) != nil || len(wire.Paths) != 1 || len(wire.Paths["/openapi.json"]["get"].Security) != 1 {
				t.Fatal("protected metadata advertised public or implicit routes")
			}
		}
	}
}

type metadataAuthorizer func(context.Context, authorization.Request) (authorization.Decision, error)

func TestProtectedMetadataRatesUnauthenticatedAttempts(t *testing.T) {
	f := newFixture(t, session.CredentialBearer)
	h, _, err := sessionhttp.NewMetadataRouter(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, metadataSessionConfig(f, metadataPolicy(t, authorization.Allow, "user-a", "tenant-a")), identityhttp.FeatureServices{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 101; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, metadataSessionRequest(f, false))
		want := 401
		if i == 100 {
			want = 429
		}
		if w.Code != want || f.calls.Load() != 0 {
			t.Fatalf("unauthenticated admission bypassed shared budget at%d status=%d", i, w.Code)
		}
	}
}

func (f metadataAuthorizer) Decide(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	return f(ctx, r)
}

func TestProtectedMetadataNeverExposesStaleOrWrongAuthority(t *testing.T) {
	for _, name := range []string{"wrong-user", "wrong-tenant", "inactive", "unknown-token", "owner-outage", "policy-outage", "policy-stale", "expired-policy-work", "expired-hook", "canceled-hook", "policy-panic"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, session.CredentialBearer)
			user, tenant := "user-a", "tenant-a"
			if name == "wrong-user" {
				user = "user-other"
			}
			if name == "wrong-tenant" {
				tenant = "tenant-other"
			}
			engine := metadataPolicy(t, authorization.Allow, user, tenant)
			c := metadataSessionConfig(f, engine)
			if name == "inactive" {
				f.observation.Active = false
			}
			if name == "owner-outage" {
				f.fail.Store(true)
			}
			if name == "policy-outage" {
				c.Authorization = metadataAuthorizer(func(context.Context, authorization.Request) (authorization.Decision, error) {
					return authorization.Decision{}, errors.New("private diagnostic")
				})
			}
			if name == "policy-stale" {
				c.PolicyRevision = 2
			}
			if name == "policy-panic" {
				c.Authorization = metadataAuthorizer(func(context.Context, authorization.Request) (authorization.Decision, error) {
					panic("private diagnostic")
				})
			}
			var advance atomic.Bool
			originalNow := f.config.Now
			c.Read.Now = func() time.Time {
				if advance.Load() {
					return originalNow().Add(20 * time.Second)
				}
				return originalNow()
			}
			if name == "expired-policy-work" {
				c.Authorization = metadataAuthorizer(func(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
					d, e := engine.Decide(ctx, r)
					advance.Store(true)
					return d, e
				})
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var hooks []identityhttp.MiddlewareDescriptor
			if name == "expired-hook" || name == "canceled-hook" {
				hooks = []identityhttp.MiddlewareDescriptor{logoutMiddleware(identityhttp.MiddlewareBeforeHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
					if name == "expired-hook" {
						advance.Store(true)
					} else {
						cancel()
					}
					next.ServeHTTP(w, r)
				})}
			}
			h, doc, err := sessionhttp.NewMetadataRouter(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, c, identityhttp.FeatureServices{}, hooks)
			if err != nil {
				t.Fatal(err)
			}
			r := metadataSessionRequest(f, true).WithContext(ctx)
			if name == "unknown-token" {
				token, _ := session.NewToken(32)
				wire, _ := token.Reveal()
				r.Header.Set("Authorization", "Bearer "+wire)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := 503
			if name == "wrong-user" || name == "wrong-tenant" {
				want = 403
			}
			if name == "inactive" || name == "unknown-token" {
				want = 401
			}
			if w.Code != want || bytes.Equal(w.Body.Bytes(), doc.JSON()) || strings.Contains(w.Body.String(), "private") || len(w.Result().Cookies()) != 0 {
				t.Fatal("unsafe authority result", w.Code)
			}
		})
	}
}

func TestProtectedMetadataRejectsMalformedRequestsBeforeOwner(t *testing.T) {
	for _, mode := range []session.CredentialKind{session.CredentialCookie, session.CredentialBearer} {
		f := newFixture(t, mode)
		h, _, err := sessionhttp.NewMetadataRouter(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, metadataSessionConfig(f, metadataPolicy(t, authorization.Allow, "user-a", "tenant-a")), identityhttp.FeatureServices{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name   string
			mutate func(*http.Request)
			want   int
		}{
			{"query", func(r *http.Request) { r.URL.RawQuery = "role=admin"; r.RequestURI += "?role=admin" }, 400},
			{"body", func(r *http.Request) { r.ContentLength = 1; r.Body = http.NoBody }, 400},
			{"retry", func(r *http.Request) { r.Header["idempotency-key"] = []string{"key"} }, 400},
			{"proxy-auth", func(r *http.Request) { r.Header.Set("Proxy-Authorization", "Bearer unused") }, 400},
			{"duplicate", func(r *http.Request) {
				if mode == session.CredentialCookie {
					r.Header.Add("Cookie", r.Header.Get("Cookie"))
				} else {
					r.Header.Add("Authorization", r.Header.Get("Authorization"))
				}
			}, 400},
			{"wrong-host", func(r *http.Request) { r.Host = "other.example" }, 421},
			{"http", func(r *http.Request) { r.TLS = nil }, 403},
			{"alias", func(r *http.Request) { r.URL.Path += "/"; r.RequestURI = r.URL.Path }, 404},
			{"head", func(r *http.Request) { r.Method = "HEAD" }, 405},
			{"options", func(r *http.Request) { r.Method = "OPTIONS" }, 405},
			{"oversize", func(r *http.Request) { r.Header.Set("X-Extra", strings.Repeat("a", 65537)) }, 400},
		} {
			t.Run(fmt.Sprint(mode, "/", tc.name), func(t *testing.T) {
				r := metadataSessionRequest(f, true)
				tc.mutate(r)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != tc.want || f.calls.Load() != 0 || len(w.Result().Cookies()) != 0 || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("malformed request reached owner", w.Code)
				}
				if r.Method == "HEAD" && w.Body.Len() != 0 {
					t.Fatal("HEAD denial has body")
				}
			})
		}
	}
}

func TestProtectedMetadataSharesRealSafeRateBudgets(t *testing.T) {
	for _, subjectBudget := range []bool{false, true} {
		f := newLogout(t, session.CredentialBearer)
		feature, err := sessionhttp.NewFeature(f.config)
		if err != nil {
			t.Fatal(err)
		}
		h, _, err := sessionhttp.NewMetadataRouter(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, metadataSessionConfig(f.fixture, metadataPolicy(t, authorization.Allow, "user-a", "tenant-a")), identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		limit := 100
		if subjectBudget {
			limit = 300
		}
		for i := 0; i <= limit; i++ {
			r := metadataSessionRequest(f.fixture, true)
			if subjectBudget {
				r.RemoteAddr = fmt.Sprintf("198.51.%d.%d:443", i/200, i%200+1)
			} else if i > 0 && i < limit {
				r = request(f.fixture, true)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := 200
			if i == limit {
				want = 429
			}
			if w.Code != want {
				t.Fatalf("shared quota mismatch at%d subject=%t status=%d", i, subjectBudget, w.Code)
			}
			if want == 429 && (w.Header().Get("Retry-After") == "" || strings.Contains(w.Body.String(), "openapi")) {
				t.Fatal("unsafe rate denial")
			}
		}
	}
}

func TestProtectedMetadataConstructionSnapshotAndHooks(t *testing.T) {
	f := newFixture(t, session.CredentialBearer)
	c := metadataSessionConfig(f, metadataPolicy(t, authorization.Allow, "user-a", "tenant-a"))
	for _, mutate := range []func(*sessionhttp.MetadataConfig){
		func(c *sessionhttp.MetadataConfig) { c.Authorization = nil },
		func(c *sessionhttp.MetadataConfig) { var engine *authorization.Engine; c.Authorization = engine },
		func(c *sessionhttp.MetadataConfig) { c.PolicyRevision = 0 },
		func(c *sessionhttp.MetadataConfig) { c.Action = "" },
		func(c *sessionhttp.MetadataConfig) {
			c.ResourceType = authorization.ResourceType(strings.Repeat("a", 129))
		},
		func(c *sessionhttp.MetadataConfig) { c.Read.Sessions = nil },
		func(c *sessionhttp.MetadataConfig) { c.Read.Rate = nil },
		func(c *sessionhttp.MetadataConfig) { c.Read.Now = nil },
	} {
		bad := c
		mutate(&bad)
		h, d, err := sessionhttp.NewMetadataRouter(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, bad, identityhttp.FeatureServices{}, nil)
		if err == nil || h != nil || len(d.JSON()) != 0 || f.calls.Load() != 0 {
			t.Fatal("invalid construction published endpoint")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if h, d, err := sessionhttp.NewMetadataRouter(ctx, identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, c, identityhttp.FeatureServices{}, nil); err == nil || h != nil || len(d.JSON()) != 0 {
		t.Fatal("canceled construction published endpoint")
	}
	var observed atomic.Int32
	hook := logoutMiddleware(identityhttp.MiddlewareAfterAuth, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		state, ok := identityhttp.PipelineValue[sessionhttp.GetState](r)
		principal, present := state.Principal()
		if !ok || !present || principal.UserID != "user-a" || principal.TenantID != "tenant-a" {
			t.Error("hook did not see real owner")
		}
		observed.Add(1)
		r.Host = "other.example"
		r.Header.Set("Authorization", "Bearer unused")
		w.Header().Set("Cache-Control", "public")
		w.Header().Set("Set-Cookie", "unused=value")
		next.ServeHTTP(w, r)
	})
	h, doc, err := sessionhttp.NewMetadataRouter(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, c, identityhttp.FeatureServices{}, []identityhttp.MiddlewareDescriptor{hook})
	if err != nil {
		t.Fatal(err)
	}
	want := doc.JSON()
	copyBytes := doc.JSON()
	copyBytes[0] = '!'
	ops := doc.Operations()
	ops[0].Wire.Definition[0] = '!'
	c.Read.Network.TenantHosts[0].TenantID = "other"
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			h.ServeHTTP(w, metadataSessionRequest(f, true))
			if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), want) || w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 {
				t.Error("snapshot or owner changed", w.Code)
			}
		}()
	}
	wg.Wait()
	if observed.Load() != 16 || f.calls.Load() != 16 {
		t.Fatal("hook duplicated authentication")
	}
}
