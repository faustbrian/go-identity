package sessionhttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
)

func TestSessionFeatureComposesRealSelectedRoutes(t *testing.T) {
	for _, mode := range []session.CredentialKind{session.CredentialCookie, session.CredentialBearer} {
		f := newLogout(t, mode)
		feature, err := sessionhttp.NewFeature(f.config)
		if err != nil {
			t.Fatal(err)
		}
		selection := identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}}
		ops, err := identityhttp.NewOperationDescriptors(selection)
		if err != nil || len(ops) != 2 || ops[0].Record.OperationID != "identity.session.get" || ops[1].Record.OperationID != "identity.session.signout" {
			t.Fatal("wrong selected operation inventory")
		}
		wantCSRF := identityhttp.CSRFSessionState
		if mode == session.CredentialBearer {
			wantCSRF = identityhttp.CSRFNone
		}
		if ops[1].Record.CSRFOrigin.Mode != wantCSRF || ops[1].Record.CSRFOrigin.TokenMaximumAge != 0 {
			t.Fatal("feature falsely advertises cookie CSRF or token-age enforcement")
		}
		h, err := identityhttp.NewSelectedHandler(selection)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(f.fixture, true))
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"authenticated":true`) || len(w.Result().Cookies()) != 0 || !f.observation.Active {
			t.Fatal("composed GET not real read")
		}
		w = httptest.NewRecorder()
		h.ServeHTTP(w, logoutRequest(f, true))
		if w.Code != 200 || f.executions != 1 || f.observation.Active {
			t.Fatal("composed POST not real self signout")
		}
	}
}

func TestSessionFeatureDisabledAndProbeComposition(t *testing.T) {
	empty, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	f := newLogout(t, session.CredentialCookie)
	for _, r := range []*http.Request{request(f.fixture, true), logoutRequest(f, true)} {
		w := httptest.NewRecorder()
		empty.ServeHTTP(w, r)
		if w.Code != 404 || w.Header().Get("Location") != "" || f.calls.Load() != 0 {
			t.Fatal("disabled session exposed")
		}
	}
	selected, err := sessionhttp.NewFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := identityhttp.NewProbeFeature(identityhttp.ProbeConfig{State: func() identityhttp.ServerState { return identityhttp.ServerRunning }, Timeout: time.Second, Readiness: identityhttp.ReadinessProvider{Check: func(context.Context) (identityhttp.ReadinessSnapshot, error) {
		return identityhttp.ReadinessSnapshot{Ready: true}, nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	selection := identityhttp.FeatureServices{Features: []identityhttp.Feature{selected, probe}}
	h, err := identityhttp.NewSelectedHandler(selection)
	if err != nil {
		t.Fatal(err)
	}
	selection.Features[0] = identityhttp.Feature{}
	metadata := selected.Operations()
	metadata[0].Record.Owners[0] = "other"
	metadata[0].Route.Path = "/other"
	for _, path := range []string{"/healthz", "/readyz"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatal("probe lost to optional session composition")
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(f.fixture, true))
	if w.Code != 200 {
		t.Fatal("caller mutation changed frozen route selection")
	}
}

func TestSessionFeatureRejectsZeroOwnersWithoutIO(t *testing.T) {
	f := newLogout(t, session.CredentialCookie)
	for _, mutate := range []func(*sessionhttp.SignOutConfig){
		func(c *sessionhttp.SignOutConfig) { c.Sessions = &session.SessionService{} },
		func(c *sessionhttp.SignOutConfig) { c.Rate = &identityhttp.SafeRateLimiter{} },
		func(c *sessionhttp.SignOutConfig) { c.CookieSignOut = &session.CookieSignOutService{} },
	} {
		c := f.config
		mutate(&c)
		if feature, err := sessionhttp.NewFeature(c); err == nil || feature.ID() != "" || f.calls.Load() != 0 || f.executions != 0 {
			t.Fatal("zero owner admitted or factory performed IO")
		}
	}
	f = newLogout(t, session.CredentialBearer)
	f.config.BearerSignOut = &session.SignOutService{}
	if _, err := sessionhttp.NewFeature(f.config); err == nil || f.calls.Load() != 0 {
		t.Fatal("zero bearer owner admitted")
	}
}

func TestSessionFeatureConcurrentReadAndMetadataIsolation(t *testing.T) {
	f := newLogout(t, session.CredentialBearer)
	selected, err := sessionhttp.NewFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{selected}})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			metadata := selected.Operations()
			metadata[0].Record.Owners[0] = "other"
			metadata[0].Schemas[0].Name = "other"
			w := httptest.NewRecorder()
			h.ServeHTTP(w, request(f.fixture, true))
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"userID":"user-a"`) {
				t.Error("concurrent selection lost admitted identity")
			}
		})
	}
	wg.Wait()
	if selected.Operations()[0].Record.Owners[0] != "identity/session" || !f.observation.Active {
		t.Fatal("metadata alias changed owner/state")
	}
	f.fixture.config.Rate.Close()
	if f.fixture.config.Rate.Configured() {
		t.Fatal("closed rate owner remains configured")
	}
	f.config.GetConfig = f.fixture.config
	if _, err := sessionhttp.NewFeature(f.config); err == nil {
		t.Fatal("closed rate owner admitted")
	}
}

func TestConfiguredOwnersRejectNilWithoutIO(t *testing.T) {
	var sessions *session.SessionService
	var logout *session.SignOutService
	var cookie *session.CookieSignOutService
	var rate *identityhttp.SafeRateLimiter
	if sessions.Configured() || logout.Configured() || cookie.Configured() || rate.Configured() {
		t.Fatal("nil owner configured")
	}
}
