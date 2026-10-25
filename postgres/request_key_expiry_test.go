package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestRequestKeyExpiryPreservesOriginalExclusivePrecision(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, offset := range []time.Duration{0, 1, 999, 1000, 1001, 999999, 1000000} {
		original := base.Add(offset)
		got, err := requestKeyExpiryDeadline(original)
		if err != nil || got.Before(original) || got.Sub(original) >= time.Microsecond || !postgresExactTime(got) {
			t.Fatal("conversion permits early expiry or expands beyond precision", offset, err)
		}
	}
	for _, invalid := range []time.Time{{}, time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)} {
		if got, err := requestKeyExpiryDeadline(invalid); err == nil || !got.IsZero() {
			t.Fatal("invalid or overflowing expiry admitted")
		}
	}
}

func TestRequestKeyExpiryDecoderRedactsFailureAndHonorsCancellation(t *testing.T) {
	for _, panicInstead := range []bool{false, true} {
		owner := &requestPreparationParticipant{expiry: func(context.Context, RequestKeyPreparationBinding, []byte) (identity.CommandBinding, time.Time, error) {
			if panicInstead {
				panic("private expiry diagnostic")
			}
			return identity.CommandBinding{CommandID: "private"}, time.Now(), errors.New("private expiry diagnostic")
		}}
		if b, at, err := restoreRequestKeyExpiry(context.Background(), owner, RequestKeyPreparationBinding{}, nil); err == nil || b != (identity.CommandBinding{}) || !at.IsZero() || err.Error() == "private expiry diagnostic" {
			t.Fatal("failed original decoder leaked correlation or diagnostics")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	owner := &requestPreparationParticipant{expiry: func(context.Context, RequestKeyPreparationBinding, []byte) (identity.CommandBinding, time.Time, error) {
		t.Fatal("cancelled expiry reached native decoder")
		return identity.CommandBinding{}, time.Time{}, nil
	}}
	if b, at, err := restoreRequestKeyExpiry(ctx, owner, RequestKeyPreparationBinding{}, nil); !errors.Is(err, context.Canceled) || b != (identity.CommandBinding{}) || !at.IsZero() {
		t.Fatal("cancelled expiry lost classification or returned custody", err)
	}
}

func TestRequestKeyExpiryMigrationRetainsPopulatedHistory(t *testing.T) {
	base := RequestKeyPreparationMigrationSource{Base: RequestKeyMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}
	before, err := base.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	source := RequestKeyExpiryMigrationSource{Base: base, Version: 12}
	after, err := source.Load(t.Context())
	if err != nil || len(after) != len(before)+1 || after[len(before)].DownSQL() != "" {
		t.Fatal("invalid forward expiry history", err)
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatal("installed migration was rewritten")
		}
	}
	for _, invalid := range []RequestKeyExpiryMigrationSource{{}, {Base: base, Version: 11}, {Base: MigrationSource{}, Version: 12}} {
		if history, err := invalid.Load(t.Context()); err == nil || history != nil {
			t.Fatal("missing/non-successor expiry history accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if history, err := source.Load(ctx); !errors.Is(err, context.Canceled) || history != nil {
		t.Fatal("cancelled migration returned history", err)
	}
}
