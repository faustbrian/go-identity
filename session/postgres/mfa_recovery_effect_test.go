package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestMFARecoverySessionEffectRequiresExactNativeOwnership(t *testing.T) {
	_, _, profile := identifierSessionFixture(t)
	if e, err := NewMFARecoverySessionEffect(Config{}, profile); err == nil || e != nil {
		t.Fatal("unconfigured session disposition admitted")
	}
	e, err := NewMFARecoverySessionEffect(Config{Schema: "session_store", MaximumDuration: time.Second}, profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []context.Context{nil, t.Context()} {
		if err := e.Apply(ctx, kernel.Work{}, nil, identity.Command{}); err == nil {
			t.Fatal("unowned Work revoked subject sessions")
		}
	}
}
