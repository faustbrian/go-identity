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

func TestAnonymousSigninEffectRejectsUnownedWork(t *testing.T) {
	config := Config{Schema: "session_store", MaximumDuration: time.Second}
	profile := AnonymousAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "guests", Audience: "service-a"}
	for _, invalid := range []Config{{}, {Schema: "identity", MaximumDuration: time.Second}, {Schema: "session_store", MaximumDuration: 2 * time.Minute}} {
		if effect, err := NewAnonymousSigninEffect(invalid, profile); err == nil || effect != nil {
			t.Fatal("invalid anonymous effect configuration admitted")
		}
	}
	if effect, err := NewAnonymousSigninEffect(config, AnonymousAdmissionConfig{}); err == nil || effect != nil {
		t.Fatal("missing anonymous authority owners admitted")
	}
	effect, err := NewAnonymousSigninEffect(config, profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []*AnonymousSigninEffect{nil, {}, effect} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			if _, err := candidate.Apply(ctx, kernel.Work{}, nil, identity.Command{}, kernel.AnonymousAuthorityRecord{}); err == nil {
				t.Fatal("unowned anonymous persistence admitted")
			}
			if err := candidate.Check(ctx, kernel.Work{}, nil, identity.Command{}, kernel.AnonymousAuthorityRecord{}); err == nil {
				t.Fatal("unowned anonymous final check admitted")
			}
			if _, err := candidate.Recover(ctx, kernel.RecoveryWork{}, nil); err == nil {
				t.Fatal("unowned anonymous recovery admitted")
			}
		}
	}
	if fmt.Sprintf("%#v", effect) != "postgres.AnonymousSigninEffect(redacted)" {
		t.Fatal("anonymous effect disclosed configuration")
	}
	if _, err := json.Marshal(effect); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("anonymous effect serialized")
	}
	if _, err := effect.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("anonymous effect exported")
	}
}
