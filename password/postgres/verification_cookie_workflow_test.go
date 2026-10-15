package passwordpostgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
)

func TestCookieVerificationWorkflowRejectsZeroOwnersAndCustody(t *testing.T) {
	key, err := session.NewCSRFKey(1, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, base := range []*ReauthenticationService{nil, {}} {
		if w, err := NewCookieVerificationWorkflow(base, []session.CSRFKey{key}); err == nil || w != nil {
			t.Fatal("invalid native owner selected")
		}
	}
	for _, w := range []*CookieVerificationWorkflow{nil, {}} {
		if got, err := w.Verify(context.Background(), password.CookieVerificationRequest{}); !errors.Is(err, password.ErrPasswordWork) || got != (password.VerificationResult{}) {
			t.Fatal("zero cookie owner issued authority")
		}
		if got, err := w.Recover(context.Background(), identity.RecoveryQuery{}, authorization.DecisionContext{}); !errors.Is(err, password.ErrPasswordWork) || got != (password.VerificationResult{}) {
			t.Fatal("zero cookie owner disclosed history")
		}
	}
}

func TestCookieVerificationFreezesKeysAndDeniesInvalidBeforeNative(t *testing.T) {
	base := &ReauthenticationService{pool: &database.Pool{}, repository: &Repository{}, sessions: &sessionpg.Repository{}}
	key, _ := session.NewCSRFKey(1, make([]byte, 32))
	for _, keys := range [][]session.CSRFKey{nil, {{}}, {key, key}, {key, key, key, key, key}} {
		if w, err := NewCookieVerificationWorkflow(base, keys); err == nil || w != nil {
			t.Fatal("invalid eligible keys admitted")
		}
	}
	keys := []session.CSRFKey{key}
	w, err := NewCookieVerificationWorkflow(base, keys)
	if err != nil {
		t.Fatal(err)
	}
	keys[0] = session.CSRFKey{}
	if w.keys()[0].Version() != 1 {
		t.Fatal("caller changed retained key policy")
	}
	w.native = func() *ReauthenticationService { t.Fatal("invalid input reached native"); return nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := w.Verify(ctx, password.CookieVerificationRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
	if _, err := w.Verify(nil, password.CookieVerificationRequest{}); !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("nil context admitted")
	}
	if _, err := w.Verify(context.Background(), password.CookieVerificationRequest{}); !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("zero synchronizer reached native")
	}
	if _, err := w.Recover(ctx, identity.RecoveryQuery{}, authorization.DecisionContext{}); !errors.Is(err, context.Canceled) {
		t.Fatal("recovery cancellation lost")
	}
	if _, err := w.Recover(context.Background(), identity.RecoveryQuery{}, authorization.DecisionContext{}); !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("invalid recovery reached native")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%q", "%s", "%x"} {
		if text := fmt.Sprintf(verb, w); strings.Contains(text, "native:") || strings.Contains(text, "keys:") {
			t.Fatal("runtime custody projected")
		}
	}
	if _, err := json.Marshal(w); !errors.Is(err, password.ErrSensitiveSerialization) {
		t.Fatal("runtime serialized")
	}
	if raw, err := w.MarshalText(); len(raw) != 0 || !errors.Is(err, password.ErrSensitiveSerialization) {
		t.Fatal("runtime text exported")
	}
}
