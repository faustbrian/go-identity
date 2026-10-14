package postgres

import (
	"context"
	"fmt"
	"math"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestPrivateLockoutCustodyIsRedacted(t *testing.T) {
	p, err := newLockoutProfile([32]byte{91})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%+v", p) != "otp.postgres.LockoutProfile(redacted)" {
		t.Fatal("lockout key formatting exposed custody")
	}
	locked := lockedLockouts{tenant: "tenant", rows: []lockoutRow{{identity: lockoutIdentity{kind: "subject", digest: [32]byte{3}}, version: 1}}}
	if fmt.Sprintf("%+v", locked) != "otp.postgres.LockedLockouts(redacted)" {
		t.Fatal("lockout state formatting exposed correlation")
	}
}

func TestLockoutMigrationConfiguration(t *testing.T) {
	for _, s := range []LockoutMigrationSource{{}, {Schema: "public", Version: 1}, {Schema: "otp_store", Version: 0}, {Schema: "otp_store", Version: migrations.Version(math.MaxInt64) + 1}} {
		if _, err := s.Load(context.Background()); err == nil {
			t.Fatal("invalid extension allocation accepted")
		}
	}
	s := LockoutMigrationSource{Schema: "otp_store", Version: 101}
	if _, err := s.Load(nil); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Load(ctx); err != context.Canceled {
		t.Fatal("cancellation lost")
	}
	if _, err := newLockoutProfile([32]byte{}); err != ErrInvalidConfiguration {
		t.Fatal("zero key accepted")
	}
}
