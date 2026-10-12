package reference

import (
	"context"
	identityhttp "github.com/faustbrian/go-identity/http"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMFATransportRequiresExplicitNativeSelection(t *testing.T) {
	if h, err := composeMFAHTTP(StoreConfiguration{}, nil, nil); err != nil || h != nil {
		t.Fatal("unselected HTTP acquired owners", err)
	}
	c := StoreConfiguration{HTTPMFA: &HTTPMFAConfiguration{TOTPVerify: true}}
	if h, err := composeMFAHTTP(c, nil, nil); err == nil || h != nil {
		t.Fatal("unconfigured MFA HTTP exposed completion")
	}
	if err := (&storeState{}).composeFeatureStores(c, ReferenceDependencies{}); err == nil {
		t.Fatal("selected MFA silently disappeared in recovery-only graph")
	}
}

func TestMFAEnrollmentHTTPRequiresSelectedNativeOwners(t *testing.T) {
	if h, err := composeMFAEnrollmentHTTP(StoreConfiguration{}, nil, nil, nil); err != nil || h != nil {
		t.Fatal("unselected enrollment acquired HTTP authority")
	}
	c := StoreConfiguration{HTTPMFAEnrollment: &HTTPMFAEnrollmentConfiguration{Confirmation: true}}
	if h, err := composeMFAEnrollmentHTTP(c, nil, nil, nil); err == nil || h != nil {
		t.Fatal("missing native owners exposed enrollment")
	}
	if err := (&storeState{}).composeFeatureStores(c, ReferenceDependencies{}); err == nil {
		t.Fatal("selected enrollment silently disappeared")
	}
}

func TestMFAEnrollmentClosedGraphPreservesOperationResponse(t *testing.T) {
	for _, operation := range []string{"identity.mfa.totp-uri", "identity.mfa.totp-verify"} {
		h := &mfaEnrollmentLifetimeHandler{state: &storeState{closed: true}, operation: operation, next: http.NotFoundHandler()}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "https://login.example/v1/mfa/totp-verify", nil))
		field := "disclosed"
		if operation == "identity.mfa.totp-verify" {
			field = "activated"
		}
		if w.Code != 503 || !strings.Contains(w.Body.String(), `"`+field+`":false`) || strings.Contains(w.Body.String(), `"enabled"`) {
			t.Fatal("graph shutdown changed operation wire contract")
		}
	}
}

func TestMFAEnrollmentHTTPPreservesHooksAndGraphLifetime(t *testing.T) {
	lifetime, cancel := context.WithCancel(t.Context())
	defer cancel()
	state := &storeState{lifetime: lifetime, features: &featureState{composed: true, ready: true, timeout: time.Second}}
	entered, finished := make(chan struct{}), make(chan struct{})
	var hook atomic.Bool
	inner, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[bool]{MaximumDuration: time.Second,
		Decode:       func(*http.Request) (bool, error) { return true, nil },
		Authenticate: func(_ *http.Request, b bool) (bool, error) { return b, nil },
		Admit:        func(*http.Request, bool) error { return nil },
		Handle:       func(_ http.ResponseWriter, r *http.Request, _ bool) { close(entered); <-r.Context().Done() },
		Reject:       func(http.ResponseWriter, *http.Request, error) { t.Error("unexpected pipeline denial") },
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := (&mfaEnrollmentLifetimeHandler{state: state, next: inner}).WithOperationMiddleware([]identityhttp.MiddlewareDescriptor{{Owner: "identity/reference", Middleware: identityhttp.Middleware{Name: "enrollment-hook", Phase: identityhttp.MiddlewareBeforeAuth, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hook.Store(true); next.ServeHTTP(w, r) })
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(finished)
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "https://login.example/v1/mfa/enable", nil))
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		cancel()
		<-finished
		t.Fatal("owned operation did not enter")
	}
	state.mu.Lock()
	active := state.active
	state.closed = true
	state.mu.Unlock()
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("graph cancellation did not terminate request")
	}
	state.mu.Lock()
	remaining := state.active
	state.mu.Unlock()
	if !hook.Load() || active != 1 || remaining != 0 {
		t.Fatal("pipeline hooks or graph drain ownership lost")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "https://login.example/v1/mfa/enable", nil))
	if w.Code != 503 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("closed graph retained enrollment authority")
	}
}
