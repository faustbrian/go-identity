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

func TestOTPSigninEffectRequiresTrustedConfigurationAndLiveWork(t *testing.T) {
	profile := OTPAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a"}
	config := Config{Schema: "session_store", MaximumDuration: time.Second}
	for _, c := range []Config{{}, {Schema: "identity", MaximumDuration: time.Second}, {Schema: "session_store", MaximumDuration: 2 * time.Minute}} {
		if effect, err := NewOTPSigninEffect(c, profile); effect != nil || err == nil {
			t.Fatal("invalid effect configuration admitted")
		}
	}
	if effect, err := NewOTPSigninEffect(config, OTPAdmissionConfig{}); effect != nil || err == nil {
		t.Fatal("zero owner profile admitted")
	}
	effect, err := NewOTPSigninEffect(config, profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, current := range []*OTPSigninEffect{nil, {}, effect} {
		if _, err := current.Apply(context.Background(), kernel.Work{}, nil, identity.Command{}, kernel.RecipientRecord{}); err == nil {
			t.Fatal("unowned work enabled session issuance")
		}
		if _, err := current.Recover(context.Background(), kernel.RecoveryWork{}, nil); err == nil {
			t.Fatal("unowned work enabled recovery")
		}
	}
	if _, err := effect.Apply(nil, kernel.Work{}, nil, identity.Command{}, kernel.RecipientRecord{}); err == nil {
		t.Fatal("nil context admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := effect.Apply(ctx, kernel.Work{}, nil, identity.Command{}, kernel.RecipientRecord{}); err == nil {
		t.Fatal("cancelled unowned work admitted")
	}
	_, err = (OTPIssueMigrationSource{Schema: "session_store", Version: 29}).Load(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("migration cancellation lost", err)
	}
}

func TestOTPSigninEffectNoImplicitDisclosure(t *testing.T) {
	effect, err := NewOTPSigninEffect(Config{Schema: "session_store", MaximumDuration: time.Second}, OTPAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a"})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%#v", effect) != "postgres.OTPSigninEffect(redacted)" {
		t.Fatal("implicit formatting exposes deployment configuration")
	}
	if _, err := json.Marshal(effect); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("implicit JSON export admitted")
	}
	if _, err := effect.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("implicit text export admitted")
	}
}
