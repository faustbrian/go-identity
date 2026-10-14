package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// Native coverage plan: exact invocation and frozen intent; bounded stable
// selection across pages; complete source/current owner admission; no expired,
// revoked or stale promotion; original evidence survives payload pruning;
// over-limit, foreign Work and downstream failure roll back every session effect.
func TestPasswordChangeEffectRequiresOwnedWork(t *testing.T) {
	_, _, profile := identifierSessionFixture(t)
	config := Config{Schema: "session_store", MaximumDuration: time.Second}
	for _, c := range []Config{{}, {Schema: "identity", MaximumDuration: time.Second}, {Schema: "session_store", MaximumDuration: 2 * time.Minute}} {
		if effect, err := NewPasswordChangeEffect(c, profile); effect != nil || err == nil {
			t.Fatal("invalid native configuration accepted")
		}
	}
	if effect, err := NewPasswordChangeEffect(config, IdentifierAdmissionConfig{}); effect != nil || err == nil {
		t.Fatal("absent profile accepted")
	}
	profile.AuthenticationMethod = "oauth"
	if effect, err := NewPasswordChangeEffect(config, profile); effect != nil || err == nil {
		t.Fatal("non-password configuration accepted")
	}
	_, _, profile = identifierSessionFixture(t)
	effect, err := NewPasswordChangeEffect(config, profile)
	if err != nil {
		t.Fatal(err)
	}
	command, _, _ := passwordSessionCommandFixture(t, PasswordChangePreserveSessions, 1, true)
	for _, e := range []*PasswordChangeEffect{nil, {}, effect} {
		if _, err := e.Apply(context.Background(), kernel.Work{}, nil, command); err == nil {
			t.Fatal("foreign work accepted")
		}
		if _, err := e.Recover(context.Background(), kernel.RecoveryWork{}, nil); err == nil {
			t.Fatal("foreign recovery accepted")
		}
	}
	if _, err := effect.Apply(nil, kernel.Work{}, nil, command); err == nil {
		t.Fatal("nil context accepted")
	}
	if fmt.Sprintf("%#v", effect) != "postgres.PasswordChangeEffect(redacted)" {
		t.Fatal("configuration disclosed")
	}
	if _, err := json.Marshal(effect); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("implicit export accepted")
	}
	if _, err := effect.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("implicit text accepted")
	}
	if _, err := (PasswordChangeMigrationSource{}).Load(context.Background()); err == nil {
		t.Fatal("zero migration accepted")
	}
	if _, err := (PasswordChangeMigrationSource{Schema: "session_store", Version: 32}).Load(nil); err == nil {
		t.Fatal("nil migration context accepted")
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	var canceled identity.CancelledError
	if _, err := effect.Apply(ctx, kernel.Work{}, nil, command); !errors.As(err, &canceled) {
		t.Fatal("cancellation classification lost", err)
	}
	if _, err := (PasswordChangeMigrationSource{Schema: "session_store", Version: 32}).Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("migration cancellation lost", err)
	}
	for _, source := range []PasswordChangeMigrationSource{{Schema: "identity", Version: 32}, {Schema: "public", Version: 32}, {Schema: "session_store"}, {Schema: "session_store", Version: 1 << 63}} {
		if _, err := source.Load(context.Background()); err == nil {
			t.Fatal("invalid migration ownership admitted")
		}
	}
}
