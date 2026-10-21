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

func TestAnonymousUpgradeEffectRejectsUnownedWork(t *testing.T) {
	config := Config{Schema: "session_store", MaximumDuration: time.Second}
	profile := IssueAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	for _, invalid := range []Config{{}, {Schema: "identity", MaximumDuration: time.Second}, {Schema: "session_store", MaximumDuration: 2 * time.Minute}} {
		if effect, err := NewAnonymousUpgradeEffect(invalid, profile); err == nil || effect != nil {
			t.Fatal("invalid upgrade configuration admitted")
		}
	}
	for _, invalid := range []IssueAdmissionConfig{{}, {GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "other", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}} {
		if effect, err := NewAnonymousUpgradeEffect(config, invalid); err == nil || effect != nil {
			t.Fatal("missing or unsupported target owner admitted")
		}
	}
	effect, err := NewAnonymousUpgradeEffect(config, profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []*AnonymousUpgradeEffect{nil, {}, effect} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			if _, err := candidate.Apply(ctx, kernel.Work{}, nil, identity.Command{}, session.Session{}, session.Session{}, time.Time{}); err == nil {
				t.Fatal("unowned upgrade persistence admitted")
			}
			if err := candidate.Check(ctx, kernel.Work{}, nil, identity.Command{}, session.Session{}, session.Session{}, time.Time{}); err == nil {
				t.Fatal("unowned upgrade final check admitted")
			}
			if _, err := candidate.Recover(ctx, kernel.RecoveryWork{}, nil, session.Session{}); err == nil {
				t.Fatal("unowned upgrade recovery admitted")
			}
		}
	}
	if fmt.Sprintf("%#v", effect) != "postgres.AnonymousUpgradeEffect(redacted)" {
		t.Fatal("upgrade effect disclosed configuration")
	}
	if _, err := json.Marshal(effect); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("upgrade effect serialized")
	}
	if _, err := effect.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("upgrade effect exported")
	}
}
