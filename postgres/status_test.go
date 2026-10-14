package postgres

import (
	"context"
	"errors"
	"math"
	"strconv"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestStatusRejectsInvalidRuntime(t *testing.T) {
	var repository *Repository
	if got, err := repository.GetStatus(context.Background(), identity.UserStatusQuery{}); err == nil || got != (identity.UserStatusRecord{}) {
		t.Fatal("invalid status repository supplied authority")
	}
	var owner *StatusUnitOfWork
	if got, err := owner.Execute(context.Background(), identity.Command{}); err == nil || got.Validate() == nil {
		t.Fatal("invalid status owner executed")
	}
	if _, err := NewStatusUnitOfWork(nil, nil, StatusUnitOfWorkConfig{}); err == nil {
		t.Fatal("invalid composition accepted")
	}
}

func TestStatusDecodeKeepsIndependentFullWidthAuthority(t *testing.T) {
	q := identity.UserStatusQuery{TenantID: "tenant", UserID: "user"}
	for _, epoch := range []uint64{1, 1<<53 + 1, 1 << 63, math.MaxUint64} {
		value := strconv.FormatUint(epoch, 10)
		got, err := decodeStatus(q, "tenant", "user", "banned", "7", value)
		if err != nil || got.AuthorityVersion != epoch || got.User.Version != 7 || got.User.Status.AllowsAuthentication() {
			t.Fatal("authority dimension changed", err)
		}
	}
	for _, args := range [][5]string{{"foreign", "user", "active", "7", "1"}, {"tenant", "other", "active", "7", "1"}, {"tenant", "user", "unknown", "7", "1"}, {"tenant", "user", "active", "0", "1"}, {"tenant", "user", "active", "7", "0"}, {"tenant", "user", "active", "7", "01"}, {"tenant", "user", "active", "7", "1.5"}, {"tenant", "user", "active", "7", "18446744073709551616"}} {
		if got, err := decodeStatus(q, args[0], args[1], args[2], args[3], args[4]); err == nil || got != (identity.UserStatusRecord{}) {
			t.Fatal("corrupt/mismatched authority admitted")
		}
	}
}

func TestStatusMigrationIsExplicitForwardComposition(t *testing.T) {
	base, err := (MigrationSource{}).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []migrations.Version{0, 1, 9} {
		if _, err := (StatusMigrationSource{Base: MigrationSource{}, Version: version}).Load(context.Background()); err == nil {
			t.Fatal("colliding migration allocation admitted")
		}
	}
	source := StatusMigrationSource{Base: MigrationSource{}, Version: 12}
	got, err := source.Load(context.Background())
	if err != nil || len(got) != len(base)+1 {
		t.Fatal("forward status history absent", err)
	}
	for i := range base {
		if got[i].Checksum() != base[i].Checksum() {
			t.Fatal("installed history changed")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled migration ignored")
	}
}
