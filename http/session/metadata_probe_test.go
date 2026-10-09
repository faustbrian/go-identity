package sessionhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authorization "github.com/faustbrian/go-authorization"
	identityhttp "github.com/faustbrian/go-identity/http"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
)

func TestProtectedMetadataComposesPublicProbesAndSharedHooks(t *testing.T) {
	for _, mode := range []session.CredentialKind{session.CredentialCookie, session.CredentialBearer} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			f := newFixture(t, mode)
			var checks, publicHooks, adminHooks atomic.Int32
			var draining atomic.Bool
			probe, err := identityhttp.NewProbeFeature(identityhttp.ProbeConfig{
				State: func() identityhttp.ServerState {
					if draining.Load() {
						return identityhttp.ServerDraining
					}
					return identityhttp.ServerRunning
				}, Timeout: time.Second,
				Readiness: identityhttp.ReadinessProvider{Check: func(ctx context.Context) (identityhttp.ReadinessSnapshot, error) {
					checks.Add(1)
					return identityhttp.ReadinessSnapshot{Ready: true}, ctx.Err()
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			hook := logoutMiddleware(identityhttp.MiddlewareAfterAuth, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				state, authenticated := identityhttp.PipelineValue[sessionhttp.GetState](r)
				if r.URL.Path == "/openapi.json" {
					principal, present := state.Principal()
					if !authenticated || (present && (principal.UserID != "user-a" || principal.TenantID != "tenant-a")) {
						t.Error("metadata hook lost real session owner custody")
					}
					if present {
						adminHooks.Add(1)
					}
				} else {
					if authenticated {
						t.Error("public probe acquired a session principal")
					}
					for name := range r.Header {
						if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Cookie") || strings.EqualFold(name, "Proxy-Authorization") {
							t.Error("public hook received ambient credentials")
						}
					}
					publicHooks.Add(1)
					w.Header().Set("Set-Cookie", "unused=value")
					w.Header().Set("X-Probe-Override", "unused")
				}
				next.ServeHTTP(w, r)
			})
			services := identityhttp.FeatureServices{Features: []identityhttp.Feature{probe}}
			h, doc, err := sessionhttp.NewMetadataRouter(context.Background(), identityhttp.DocumentConfig{Title: "Selected", Version: "1"}, metadataSessionConfig(f, metadataPolicy(t, authorization.Allow, "user-a", "tenant-a")), services, []identityhttp.MiddlewareDescriptor{hook})
			if err != nil {
				t.Fatal("cannot compose protected metadata with public probe owners and shared middleware", err)
			}
			if checks.Load() != 0 || f.calls.Load() != 0 || publicHooks.Load() != 0 || adminHooks.Load() != 0 {
				t.Fatal("construction performed owner or hook work")
			}
			var wire struct {
				Paths map[string]map[string]struct {
					OperationID string                `json:"operationId"`
					Security    []map[string][]string `json:"security"`
				} `json:"paths"`
			}
			if json.Unmarshal(doc.JSON(), &wire) != nil || len(wire.Paths) != 3 || len(doc.Operations()) != 3 {
				t.Fatal("selected document contains missing or implicit operations")
			}
			for path, id := range map[string]string{"/healthz": "identity.health", "/readyz": "identity.readiness", "/openapi.json": "identity.openapi.document"} {
				op := wire.Paths[path]["get"]
				wantSecurity := 0
				if path == "/openapi.json" {
					wantSecurity = 1
				}
				if op.OperationID != id || len(op.Security) != wantSecurity {
					t.Fatal("document confuses public probes with protected metadata", path)
				}
			}
			services.Features[0] = identityhttp.Feature{}
			for _, path := range []string{"/healthz", "/readyz"} {
				r := request(f, true)
				r.URL.Path, r.RequestURI = path, path
				// The probe ignores even unrelated ambient credential channels.
				r.Header.Set("Proxy-Authorization", "Bearer unused")
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				want := "{\"status\":\"alive\"}\n"
				if path == "/readyz" {
					want = "{\"ready\":true}\n"
				}
				if w.Code != 200 || w.Body.String() != want || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-Probe-Override") != "" || f.calls.Load() != 0 {
					t.Fatal("public probe changed session authority or fixed output", path, w.Code)
				}
				if r.Header.Get("Proxy-Authorization") == "" {
					t.Fatal("probe mutated caller credentials")
				}
			}
			for _, credential := range []bool{false, true} {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, metadataSessionRequest(f, credential))
				want := 401
				if credential {
					want = 200
				}
				if w.Code != want || (credential && !bytes.Equal(w.Body.Bytes(), doc.JSON())) || (!credential && bytes.Contains(w.Body.Bytes(), []byte("openapi"))) {
					t.Fatal("public probe selection weakened protected metadata", w.Code)
				}
			}
			if checks.Load() != 1 || publicHooks.Load() != 2 || adminHooks.Load() != 1 || f.calls.Load() != 1 {
				t.Fatal("composition duplicated or confused owner phases")
			}
			draining.Store(true)
			r := request(f, false)
			r.URL.Path, r.RequestURI = "/readyz", "/readyz"
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 503 || w.Body.String() != "{\"ready\":false}\n" || checks.Load() != 1 || f.calls.Load() != 1 {
				t.Fatal("composed readiness lost lifecycle ownership")
			}
			for _, path := range []string{"/v1/session/get", "/v1/healthz", "/v1/readyz"} {
				r := request(f, true)
				r.URL.Path, r.RequestURI = path, path
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != 404 || f.calls.Load() != 1 {
					t.Fatal("composition implicitly selected a route", path)
				}
			}
			draining.Store(false)
			var wg sync.WaitGroup
			for range 16 {
				wg.Go(func() {
					for _, path := range []string{"/readyz", "/openapi.json"} {
						r := request(f, true)
						r.URL.Path, r.RequestURI = path, path
						w := httptest.NewRecorder()
						h.ServeHTTP(w, r)
						want := []byte("{\"ready\":true}\n")
						if path == "/openapi.json" {
							want = doc.JSON()
						}
						if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), want) || w.Header().Get("Set-Cookie") != "" {
							t.Error("mixed requests crossed owner or response custody", path, w.Code)
						}
					}
				})
			}
			wg.Wait()
			if f.calls.Load() != 17 || checks.Load() != 17 || adminHooks.Load() != 17 || publicHooks.Load() != 19 {
				t.Fatal("concurrent requests duplicated owner work")
			}
		})
	}
}

func TestProtectedMetadataProbeSelectionDoesNotGrantAdmin(t *testing.T) {
	f := newFixture(t, session.CredentialBearer)
	var checks atomic.Int32
	probe, err := identityhttp.NewProbeFeature(identityhttp.ProbeConfig{State: func() identityhttp.ServerState { return identityhttp.ServerRunning }, Timeout: time.Second, Readiness: identityhttp.ReadinessProvider{Check: func(ctx context.Context) (identityhttp.ReadinessSnapshot, error) {
		checks.Add(1)
		return identityhttp.ReadinessSnapshot{Ready: true}, ctx.Err()
	}}})
	if err != nil {
		t.Fatal(err)
	}
	c := metadataSessionConfig(f, metadataPolicy(t, authorization.Deny, "user-a", "tenant-a"))
	hook := logoutMiddleware(identityhttp.MiddlewareAfterAuth, func(w http.ResponseWriter, r *http.Request, next http.Handler) { next.ServeHTTP(w, r) })
	h, _, err := sessionhttp.NewMetadataRouter(context.Background(), identityhttp.DocumentConfig{Title: "Selected", Version: "1"}, c, identityhttp.FeatureServices{Features: []identityhttp.Feature{probe}}, []identityhttp.MiddlewareDescriptor{hook})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, metadataSessionRequest(f, true))
	if w.Code != 403 || bytes.Contains(w.Body.Bytes(), []byte("openapi")) || f.calls.Load() != 1 || checks.Load() != 0 {
		t.Fatal("probe selection bypassed real administrator policy")
	}
	for _, features := range [][]identityhttp.Feature{nil, {probe, probe}} {
		h, doc, err := sessionhttp.NewMetadataRouter(context.Background(), identityhttp.DocumentConfig{Title: "Selected", Version: "1"}, c, identityhttp.FeatureServices{Features: features}, []identityhttp.MiddlewareDescriptor{hook})
		if len(features) != 0 {
			if err == nil || h != nil || len(doc.JSON()) != 0 {
				t.Fatal("duplicate probes returned partial composition")
			}
			continue
		}
		if err != nil || len(doc.Operations()) != 1 {
			t.Fatal("metadata-only composition advertised unselected probes", err)
		}
		for _, path := range []string{"/healthz", "/readyz"} {
			r := request(f, true)
			r.URL.Path, r.RequestURI = path, path
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 404 || bytes.Contains(doc.JSON(), []byte(path)) || f.calls.Load() != 1 || checks.Load() != 0 {
				t.Fatal("disabled probe invoked owners or remained advertised")
			}
		}
	}
}
