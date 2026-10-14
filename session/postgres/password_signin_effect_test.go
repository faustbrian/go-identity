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

func TestPasswordSigninEffectRequiresNativeWork(t *testing.T) {
	c := Config{Schema: "session_store", MaximumDuration: time.Second}
	p := IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	for _, config := range []Config{{}, {Schema: "identity", MaximumDuration: time.Second}, {Schema: "session_store", MaximumDuration: 2 * time.Minute}} {
		if e, err := NewPasswordSigninEffect(config, p); e != nil || err == nil {
			t.Fatal("invalid configuration admitted")
		}
	}
	if e, err := NewPasswordSigninEffect(c, IdentifierAdmissionConfig{}); e != nil || err == nil {
		t.Fatal("zero profile admitted")
	}
	e, err := NewPasswordSigninEffect(c, p)
	if err != nil {
		t.Fatal(err)
	}
	for _, effect := range []*PasswordSigninEffect{nil, {}, e} {
		if err := effect.PrepareHashUpgrade(context.Background(), kernel.Work{}, nil, identity.Command{}, kernel.RecipientRecord{}); err == nil {
			t.Fatal("unowned predecessor reservation admitted")
		}
		if _, err := effect.ApplyHashUpgrade(context.Background(), kernel.Work{}, nil, identity.Command{}, session.PreAuthTransaction{}); err == nil {
			t.Fatal("unowned successor issuance admitted")
		}
		if _, err := effect.Apply(context.Background(), kernel.Work{}, nil, identity.Command{}, kernel.RecipientRecord{}, session.PreAuthTransaction{}); err == nil {
			t.Fatal("unowned issuance admitted")
		}
		if _, err := effect.Recover(context.Background(), kernel.RecoveryWork{}, nil); err == nil {
			t.Fatal("unowned recovery admitted")
		}
	}
	if fmt.Sprintf("%#v", e) != "postgres.PasswordSigninEffect(redacted)" {
		t.Fatal("configuration disclosed")
	}
	if _, err := json.Marshal(e); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("configuration serialized")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (PasswordSigninMigrationSource{Schema: "session_store", Version: 33}).Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("migration cancellation lost", err)
	}
}
