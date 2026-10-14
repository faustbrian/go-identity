package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func csrfAdmissionFixture(t testing.TB, original session.Session) (session.Session, session.CSRFToken, session.CSRFKey) {
	t.Helper()
	base, err := original.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	key, err := session.NewCSRFKey(7, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	state, err := token.Digest(key, session.CSRFBinding{TenantID: base.TenantID, SessionID: base.SessionID, SessionVersion: base.Version})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSessionWithCSRF(base, state)
	if err != nil {
		t.Fatal(err)
	}
	return record, token, key
}

func TestCSRFAdmissionRejectsInvalidAndUnownedInputs(t *testing.T) {
	record, token, key := csrfAdmissionFixture(t, testSession(t))
	cfg := Config{Schema: "session_store", MaximumDuration: time.Second}
	var invalid identity.InvalidInputError
	for _, c := range []Config{{}, {Schema: "public", MaximumDuration: time.Second}, {Schema: "session_store", MaximumDuration: time.Minute + 1}} {
		if err := RequireCSRF(context.Background(), kernel.Work{}, c, record, token, key); !errors.As(err, &invalid) {
			t.Fatal("invalid configuration admitted", err)
		}
	}
	if err := RequireCSRF(nil, kernel.Work{}, cfg, record, token, key); !errors.As(err, &invalid) {
		t.Fatal("nil context admitted", err)
	}
	if err := RequireCSRF(context.Background(), kernel.Work{}, cfg, session.Session{}, token, key); !errors.As(err, &invalid) {
		t.Fatal("zero session admitted", err)
	}
	var denied identity.ForbiddenError
	for _, candidate := range []session.Session{testSession(t), withCSRFState(t, record, 9)} {
		if err := RequireCSRF(context.Background(), kernel.Work{}, cfg, candidate, token, key); !errors.As(err, &denied) {
			t.Fatal("absent/substituted state admitted", err)
		}
	}
	if err := RequireCSRF(context.Background(), kernel.Work{}, cfg, record, session.CSRFToken{}, key); !errors.As(err, &denied) {
		t.Fatal("zero token admitted", err)
	}
	if err := RequireCSRF(context.Background(), kernel.Work{}, cfg, record, token, session.CSRFKey{}); !errors.As(err, &denied) {
		t.Fatal("zero key admitted", err)
	}
	if err := RequireCSRF(context.Background(), kernel.Work{}, cfg, record, token, key); err == nil {
		t.Fatal("structural match became positive primary authority on zero Work")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	var ce identity.CancelledError
	if err := RequireCSRF(canceled, kernel.Work{}, cfg, record, token, key); !errors.As(err, &ce) {
		t.Fatal("cancellation classification lost", err)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	var de identity.DeadlineExceededError
	if err := RequireCSRF(expired, kernel.Work{}, cfg, record, token, key); !errors.As(err, &de) {
		t.Fatal("deadline classification lost", err)
	}
}
