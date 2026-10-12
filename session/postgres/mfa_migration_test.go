package postgres

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestMFAMigrationRejectsInvalidOwnerAndPreservesCancellation(t *testing.T) {
	var invalid identity.InvalidInputError
	for _, source := range []MFAMigrationSource{{}, {Schema: "public", Version: 17}, {Schema: "identity", Version: 17}, {Schema: "session_store"}, {Schema: "session_store", Version: 1 << 63}} {
		if _, err := source.Load(context.Background()); !errors.As(err, &invalid) {
			t.Fatal("invalid migration owner accepted", err)
		}
	}
	source := MFAMigrationSource{Schema: "session_store", Version: 17}
	if _, err := source.Load(nil); !errors.As(err, &invalid) {
		t.Fatal("nil migration context accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("migration lost cancellation", err)
	}
}

func TestMFASigninMigrationRejectsInvalidOwner(t *testing.T) {
	if _, err := (MFASigninMigrationSource{}).Load(context.Background()); err == nil {
		t.Fatal("zero issuance migration accepted")
	}
	if _, err := (MFASigninMigrationSource{Schema: "session_store", Version: 18}).Load(nil); err == nil {
		t.Fatal("nil issuance migration context accepted")
	}
}
