package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestMagicLinkSigninEffectRequiresNativeConsumption(t *testing.T) {
	c := Config{Schema: "session_store", MaximumDuration: time.Second}
	p := MagicLinkAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a"}
	for _, invalid := range []Config{{}, {Schema: "identity", MaximumDuration: time.Second}, {Schema: "session_store", MaximumDuration: 2 * time.Minute}} {
		if e, err := NewMagicLinkSigninEffect(invalid, p); e != nil || err == nil {
			t.Fatal("invalid configuration admitted")
		}
	}
	if e, err := NewMagicLinkSigninEffect(c, MagicLinkAdmissionConfig{}); e != nil || err == nil {
		t.Fatal("unconfigured authority admitted")
	}
	e, err := NewMagicLinkSigninEffect(c, p)
	if err != nil {
		t.Fatal(err)
	}
	for _, effect := range []*MagicLinkSigninEffect{nil, {}, e} {
		if _, err := effect.Apply(context.Background(), kernel.Work{}, nil, identity.Command{}, kernel.RecipientRecord{}, session.PreAuthTransaction{}); err == nil {
			t.Fatal("metadata-only issuance admitted")
		}
		if _, err := effect.Recover(context.Background(), kernel.RecoveryWork{}, nil); err == nil {
			t.Fatal("unowned recovery admitted")
		}
	}
	if fmt.Sprintf("%#v", e) != "postgres.MagicLinkSigninEffect(redacted)" {
		t.Fatal("configuration disclosed")
	}
	if _, err := json.Marshal(e); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("configuration serialized")
	}
	if _, err := e.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("configuration exported")
	}
}

func TestMagicLinkSigninMigrationRejectsInvalidOwnership(t *testing.T) {
	var invalid identity.InvalidInputError
	for _, source := range []MagicLinkSigninMigrationSource{{}, {Schema: "identity", Version: 40}, {Schema: "session_store"}, {Schema: "session_store", Version: migrations.Version(math.MaxInt64) + 1}} {
		if _, err := source.Load(context.Background()); !errors.As(err, &invalid) {
			t.Fatal("invalid migration admitted", err)
		}
	}
	source := MagicLinkSigninMigrationSource{Schema: "session_store", Version: 40}
	if _, err := source.Load(nil); !errors.As(err, &invalid) {
		t.Fatal("nil migration context admitted", err)
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if _, err := source.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("migration cancellation lost", err)
	}
}
