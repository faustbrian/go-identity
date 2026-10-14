package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// The literal zero Work proves the native cursor type is accepted but cannot
// grant execution authority. Validation failures must occur before any SQL.
func TestSessionAdmissionInvalidInputsAndNativeCursor(t *testing.T) {
	expected := testSession(t)
	config := Config{Schema: "session_store", MaximumDuration: time.Second}
	var invalid identity.InvalidInputError
	for _, c := range []Config{{}, {Schema: "public", MaximumDuration: time.Second}, {Schema: "session_store", MaximumDuration: time.Minute + 1}} {
		if err := RequireSession(context.Background(), identitypostgres.Work{}, c, expected); !errors.As(err, &invalid) {
			t.Fatal("invalid config accepted", err)
		}
	}
	if err := RequireSession(context.Background(), identitypostgres.Work{}, config, session.Session{}); !errors.As(err, &invalid) {
		t.Fatal("zero session accepted", err)
	}
	if err := RequireSession(nil, identitypostgres.Work{}, config, expected); !errors.As(err, &invalid) {
		t.Fatal("nil context accepted", err)
	}
	if err := RequireSession(context.Background(), identitypostgres.Work{}, config, expected); err == nil {
		t.Fatal("zero Work accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	var ce identity.CancelledError
	if err := RequireSession(cancelled, identitypostgres.Work{}, config, expected); !errors.As(err, &ce) {
		t.Fatal("cancellation classification lost", err)
	}
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	var de identity.DeadlineExceededError
	if err := RequireSession(expired, identitypostgres.Work{}, config, expected); !errors.As(err, &de) {
		t.Fatal("deadline classification lost", err)
	}
}
