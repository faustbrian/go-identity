package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestRetainedPasswordSigninIdentityRejectsUnownedReads(t *testing.T) {
	for _, r := range []*Repository{nil, {}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			if got, err := r.ReadPasswordSigninIdentity(ctx, identity.CommandBinding{}); err == nil || got != (PasswordSigninIdentity{}) {
				t.Fatal("unowned retained password identity admitted")
			}
		}
	}
}

func TestRetainedPasswordSigninIdentityNoImplicitDisclosure(t *testing.T) {
	got := PasswordSigninIdentity{UserID: "private-user", SessionID: "private-session", FamilyID: "private-family"}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if fmt.Sprintf(verb, got) != "postgres.PasswordSigninIdentity(redacted)" {
			t.Fatal("retained password identity exposed in diagnostics")
		}
	}
	if _, err := json.Marshal(got); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("retained password identity admitted implicit JSON")
	}
	if _, err := got.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("retained password identity admitted implicit text")
	}
}
