package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestNativeSessionServiceRejectsIncompleteComposition(t *testing.T) {
	service, err := NewSessionService(nil, SessionServiceConfig{})
	if service != nil || err == nil {
		t.Fatal("incomplete native authentication admitted")
	}
	var _ session.SessionReader = (*primarySessionReader)(nil)
}

type sessionReadClock func() time.Time

func (f sessionReadClock) Now() time.Time { return f() }

func TestNativeSessionReaderZeroAndRedaction(t *testing.T) {
	var reader *primarySessionReader
	if got, err := reader.ObserveSession(context.Background(), session.SessionLookup{}); !errors.Is(err, session.ErrInvalidInput) || got.Active {
		t.Fatal("zero native reader admitted")
	}
	if fmt.Sprintf("%#v", SessionServiceConfig{}) != "postgres.SessionServiceConfig(redacted)" {
		t.Fatal("config disclosure")
	}
	if _, err := json.Marshal(SessionServiceConfig{}); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("configuration encoding allowed")
	}
	for _, invalid := range []time.Time{{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if sessionReadTime(invalid) {
			t.Fatal("invalid authority clock")
		}
	}
	if !sessionReadTime(time.Now()) {
		t.Fatal("valid authority clock rejected")
	}
	for _, denied := range []error{identity.ErrUserAbsent, identity.ForbiddenError{}} {
		if !errors.Is(observationError(denied), session.ErrUnauthenticated) {
			t.Fatal("denial became infrastructure failure")
		}
	}
	unavailable := identity.UnavailableError{}
	if !errors.Is(observationError(unavailable), unavailable) {
		t.Fatal("infrastructure failure became absence")
	}
}
