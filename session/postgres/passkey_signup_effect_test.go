package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

type passkeySignupDeniedAuthority struct{}

func (*passkeySignupDeniedAuthority) RequirePasskeySignupSession(context.Context, kernel.Work, kernel.PasskeyRegistrationContributor, identity.Command, string, session.Session) error {
	return identity.ForbiddenError{}
}

func TestPasskeySignupEffectRequiresOriginalWorkAndOwners(t *testing.T) {
	_, _, profile := passkeySessionFixture(t)
	cfg := Config{Schema: "session_store", MaximumDuration: time.Second}
	if _, err := NewPasskeySignupEffect(cfg, profile, nil); err == nil {
		t.Fatal("missing signup authority admitted")
	}
	var typedNil *passkeySignupDeniedAuthority
	if _, err := NewPasskeySignupEffect(cfg, profile, typedNil); err == nil {
		t.Fatal("typed nil signup authority admitted")
	}
	effect, err := NewPasskeySignupEffect(cfg, profile, &passkeySignupDeniedAuthority{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []*PasskeySignupEffect{nil, {}, effect} {
		if _, err := e.Apply(t.Context(), kernel.Work{}, nil, identity.Command{}); err == nil {
			t.Fatal("unowned signup session write admitted")
		}
		if err := e.Check(t.Context(), kernel.Work{}, nil, identity.Command{}); err == nil {
			t.Fatal("unowned signup check admitted")
		}
		if _, err := e.Recover(t.Context(), kernel.RecoveryWork{}, nil); err == nil {
			t.Fatal("unowned signup recovery admitted")
		}
		if _, err := json.Marshal(e); e != nil && err == nil {
			t.Fatal("signup configuration serialized")
		}
		if !strings.Contains(fmt.Sprintf("%#v", e), "redacted") {
			t.Fatal("signup configuration leaked")
		}
	}
	for _, value := range []any{PasskeySignupIdentity{}, effect} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("signup historical identity/configuration serialized")
		}
		if !strings.Contains(fmt.Sprintf("%#v", value), "redacted") {
			t.Fatal("signup historical identity/configuration formatting leaked")
		}
	}
	if ids, err := (&Repository{}).ReadPasskeySignupIdentity(t.Context(), identity.CommandBinding{}); err == nil || ids != (PasskeySignupIdentity{}) {
		t.Fatal("unowned historical signup read admitted")
	}
}
