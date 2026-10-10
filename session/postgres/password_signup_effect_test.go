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

func TestPasswordSignupEffectRequiresNativeWork(t *testing.T) {
	c := Config{Schema: "session_store", MaximumDuration: time.Second}
	p := IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	for _, bad := range []Config{{}, {Schema: "identity", MaximumDuration: time.Second}, {Schema: "session_store", MaximumDuration: 2 * time.Minute}} {
		if effect, err := NewPasswordSignupEffect(bad, p); effect != nil || err == nil {
			t.Fatal("invalid configuration admitted")
		}
	}
	if effect, err := NewPasswordSignupEffect(c, IdentifierAdmissionConfig{}); effect != nil || err == nil {
		t.Fatal("zero profile admitted")
	}
	effect, err := NewPasswordSignupEffect(c, p)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []*PasswordSignupEffect{nil, {}, effect} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			if _, err := candidate.Apply(ctx, kernel.Work{}, nil, identity.Command{}, kernel.RecipientRecord{}, session.PreAuthTransaction{}); err == nil {
				t.Fatal("unowned issuance admitted")
			}
			if _, err := candidate.Recover(ctx, kernel.RecoveryWork{}, nil); err == nil {
				t.Fatal("unowned recovery admitted")
			}
		}
	}
	if fmt.Sprintf("%#v", effect) != "postgres.PasswordSignupEffect(redacted)" {
		t.Fatal("configuration disclosed")
	}
	if _, err := json.Marshal(effect); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("configuration serialized")
	}
	if _, err := effect.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("configuration exported")
	}
	var repository *Repository
	if out, err := repository.ReadPasswordSignupIdentity(context.Background(), identity.CommandBinding{}); err == nil || out != (PasswordSignupIdentity{}) {
		t.Fatal("unowned history admitted")
	}
	if _, err := json.Marshal(PasswordSignupIdentity{}); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("history serialized")
	}
	if fmt.Sprintf("%#v", PasswordSignupIdentity{}) != "postgres.PasswordSignupIdentity(redacted)" {
		t.Fatal("history disclosed")
	}
}

func TestPasswordSignupMigrationRejectsInvalidAndCanceledInputs(t *testing.T) {
	for _, source := range []PasswordSignupMigrationSource{{}, {Schema: "identity", Version: 1}, {Schema: "session_store"}, {Schema: "session_store", Version: 1 << 63}} {
		if _, err := source.Load(context.Background()); err == nil {
			t.Fatal("invalid migration admitted")
		}
	}
	source := PasswordSignupMigrationSource{Schema: "session_store", Version: 36}
	if _, err := source.Load(nil); err == nil {
		t.Fatal("nil context admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	if history, err := source.Load(context.Background()); err != nil || len(history) != 1 {
		t.Fatal("valid migration denied", err)
	}
}
