package postgres

import (
	"context"
	"errors"
	"math"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestSendMigrationRejectsUnsafeInput(t *testing.T) {
	for _, source := range []SendFamilyMigrationSource{
		{}, {Schema: "public", Version: 103}, {Schema: "otp_store;drop", Version: 103},
		{Schema: "otp_store", Version: 0}, {Schema: "otp_store", Version: migrations.Version(math.MaxInt64) + 1},
	} {
		ms, err := source.Load(context.Background())
		var invalid identity.InvalidInputError
		if !errors.As(err, &invalid) || len(ms) != 0 {
			t.Fatal("unsafe installation accepted", err)
		}
	}
	source := SendFamilyMigrationSource{Schema: "otp_store", Version: 103}
	if _, err := source.Load(nil); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ms, err := source.Load(ctx); !errors.Is(err, context.Canceled) || len(ms) != 0 {
		t.Fatal("cancelled install accepted", err)
	}
}
