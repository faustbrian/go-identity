package sessionhttp_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authorization "github.com/faustbrian/go-authorization/v3"
	identityhttp "github.com/faustbrian/go-identity/http"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
)

type getSession func(context.Context, session.GetRequest) (session.GetResult, error)

func (f getSession) Get(ctx context.Context, r session.GetRequest) (session.GetResult, error) {
	return f(ctx, r)
}

func originalGet(t *testing.T, f *fixture) session.GetResult {
	t.Helper()
	token, err := session.ParseToken(f.wire)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(f.config.Transport, token)
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.config.Sessions.Get(context.Background(), session.GetRequest{TenantID: "tenant-a", Credential: credential})
	if err != nil || !result.Authenticated {
		t.Fatal("primary session fixture did not authenticate", err)
	}
	f.calls.Store(0)
	return result
}

func TestGetReadOnlySelection(t *testing.T) {
	for _, mode := range []session.CredentialKind{session.CredentialCookie, session.CredentialBearer} {
		f := newFixture(t, mode)
		original := originalGet(t, f)
		calls := 0
		f.config.ReadOnly = getSession(func(ctx context.Context, r session.GetRequest) (session.GetResult, error) {
			calls++
			if _, bounded := ctx.Deadline(); !bounded || r.TenantID != "tenant-a" || r.Credential.Kind() != mode {
				t.Fatal("read-only selection lost bounded original transport/tenant custody")
			}
			return original, nil
		})
		w := serve(t, f, request(f, true))
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"authenticated":true`) || calls != 1 || f.calls.Load() != 0 {
			t.Fatalf("selected read not used: status=%d reads=%d primary=%d", w.Code, calls, f.calls.Load())
		}
		w = serve(t, f, request(f, false))
		if w.Code != 200 || strings.Contains(w.Body.String(), "user-a") || calls != 1 {
			t.Fatal("absent credential entered selected reader")
		}
	}
}

func TestGetReadOnlyDenialNeverFallsBack(t *testing.T) {
	for _, scenario := range []string{"inactive", "unavailable", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t, session.CredentialCookie)
			original := originalGet(t, f)
			f.config.ReadOnly = getSession(func(context.Context, session.GetRequest) (session.GetResult, error) {
				switch scenario {
				case "inactive":
					return session.GetResult{}, nil
				case "unavailable":
					return session.GetResult{}, errors.New("private cache diagnostic")
				default:
					return original, nil
				}
			})
			want := 503
			if scenario == "inactive" {
				want = 200
			}
			if scenario == "expired" {
				f.config.Now = func() time.Time { return original.ValidUntil() }
			}
			w := serve(t, f, request(f, true))
			if w.Code != want || strings.Contains(w.Body.String(), "user-a") || strings.Contains(w.Body.String(), "private") || f.calls.Load() != 0 {
				t.Fatalf("selected denial fell back or disclosed: status=%d primary=%d", w.Code, f.calls.Load())
			}
		})
	}
}

func TestReadOnlySelectionCannotReplaceProtectedPrimary(t *testing.T) {
	selected := 0
	deny := getSession(func(context.Context, session.GetRequest) (session.GetResult, error) {
		selected++
		return session.GetResult{}, errors.New("ordinary read only")
	})
	t.Run("metadata", func(t *testing.T) {
		f := newFixture(t, session.CredentialBearer)
		f.config.ReadOnly = deny
		h, _, err := sessionhttp.NewMetadataRouter(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, metadataSessionConfig(f, metadataPolicy(t, authorization.Allow, "user-a", "tenant-a")), identityhttp.FeatureServices{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, metadataSessionRequest(f, true))
		if w.Code != 200 || f.calls.Load() != 1 || selected != 0 {
			t.Fatal("protected metadata did not retain primary authority", w.Code)
		}
	})
	t.Run("signout", func(t *testing.T) {
		f := newLogout(t, session.CredentialCookie)
		f.config.ReadOnly = deny
		w := logoutServe(t, f, logoutRequest(f, true))
		if w.Code != 200 || f.executions != 1 || f.calls.Load() == 0 || selected != 0 {
			t.Fatal("signout did not retain primary authority", w.Code)
		}
	})
}

func TestReadOnlySelectionStillRequiresPrimary(t *testing.T) {
	f := newFixture(t, session.CredentialBearer)
	f.config.Sessions = nil
	f.config.ReadOnly = getSession(func(context.Context, session.GetRequest) (session.GetResult, error) {
		t.Fatal("construction invoked selected reader")
		return session.GetResult{}, nil
	})
	if _, err := sessionhttp.NewGetHandler(f.config); err == nil {
		t.Fatal("read-only selection replaced mandatory native primary")
	}
}
