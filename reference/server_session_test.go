package reference

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/session"
)

func TestSessionHTTPSelectionRequiresNativeCustody(t *testing.T) {
	if h, err := composeSessionHTTP(StoreConfiguration{}, nil, nil); err != nil || h != nil {
		t.Fatal("unselected HTTP acquired dependencies", err)
	}
	c := StoreConfiguration{HTTPSession: &HTTPSessionConfiguration{Transport: session.CredentialCookie}}
	if h, err := composeSessionHTTP(c, nil, nil); err == nil || h != nil {
		t.Fatal("selected HTTP accepted missing native authority")
	}
	if err := (&storeState{}).composeFeatureStores(c, ReferenceDependencies{}); err == nil {
		t.Fatal("selected session HTTP silently disappeared without a graph")
	}
}

func TestSessionHTTPLifetimeJoinsAndCancels(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := &storeState{lifetime: lifetime, features: &featureState{composed: true, ready: true, timeout: time.Second}}
	s := &Server{state: state}
	entered := make(chan struct{})
	finished := make(chan struct{})
	h := s.guardSessionLifetime(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	}))
	go func() {
		defer close(finished)
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "https://login.example/v1/session/get", nil))
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler did not enter graph")
	}
	state.mu.Lock()
	active := state.active
	state.closed = true
	state.mu.Unlock()
	if active != 1 {
		t.Fatal("HTTP work not owned by graph drain")
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("graph cancellation did not reach HTTP owner")
	}
	state.mu.Lock()
	active = state.active
	state.mu.Unlock()
	if active != 0 {
		t.Fatal("HTTP work did not release graph")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "https://login.example/v1/session/get", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatal("closed graph allowed retained HTTP handle")
	}
}
