package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestMigrationHistory(t *testing.T) {
	s := MigrationSource{Schema: "otp_store", Version: 100}
	h, err := s.Load(context.Background())
	if err != nil || len(h) != 1 || h[0].Version() != 100 || h[0].DownSQL() != "" || h[0].TransactionMode() != migrations.TransactionModeDefault {
		t.Fatal("missing forward atomic OTP history", err)
	}
	original := h[0]
	h[0] = migrations.Migration{}
	h, err = s.Load(context.Background())
	if err != nil || h[0] != original {
		t.Fatal("caller changed retained history", err)
	}
	for _, schema := range []string{"", "public", "identity", "information_schema", "pg_otp", "1otp", "OTP", "otp\";DROP SCHEMA identity", strings.Repeat("a", 64)} {
		if h, err := (MigrationSource{Schema: schema, Version: 100}).Load(context.Background()); h != nil || err == nil {
			t.Fatal("unsafe namespace admitted")
		}
	}
	for _, version := range []migrations.Version{0, ^migrations.Version(0)} {
		if h, err := (MigrationSource{Schema: "otp_store", Version: version}).Load(context.Background()); h != nil || err == nil {
			t.Fatal("unsafe allocation admitted")
		}
	}
	if h, err := s.Load(nil); h != nil || err == nil {
		t.Fatal("nil context admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if h, err := s.Load(ctx); h != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
	for _, schema := range []string{"a", "otp_2", strings.Repeat("a", 63)} {
		if _, err := (MigrationSource{Schema: schema, Version: 9223372036854775807}).Load(context.Background()); err != nil {
			t.Fatal("bounded namespace rejected", err)
		}
	}
}
