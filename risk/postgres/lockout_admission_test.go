package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

func TestLockoutConfigurationRequiresNativeCounters(t *testing.T) {
	_, key := evaluatedIssue(t, risk.PhoneResetInitiation)
	_, err := NewRepository(Config{Schema: "risk_store", PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{key}, EnvelopeKeys: map[string][]byte{"wrapping_v1": wrappingKey(1)}, CurrentEnvelopeKey: "wrapping_v1", EnforceLockouts: true})
	if !errors.Is(err, risk.ErrInvalidPolicy) {
		t.Fatal("lockout authority without native counter roots", err)
	}
}

func TestLockoutExclusiveExpiryAndForwardHistory(t *testing.T) {
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	l := nativeLockout{startedAt: now, expiresAt: now.Add(time.Hour)}
	for _, tc := range []struct {
		at   time.Time
		deny bool
	}{{now.Add(-time.Microsecond), true}, {now, true}, {l.expiresAt.Add(-time.Microsecond), true}, {l.expiresAt, false}, {l.expiresAt.Add(time.Microsecond), false}} {
		if l.denies(tc.at) != tc.deny {
			t.Fatal("exclusive original interval changed")
		}
	}
	base := CounterMigrationSource{Base: ReservationMigrationSource{Base: IssuanceIDMigrationSource{Base: MigrationSource{Schema: "risk_store", Version: 20}, Version: 21}, Version: 22}, Version: 23}
	original, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s := LockoutMigrationSource{Base: base, Version: 24}
	history, err := s.Load(context.Background())
	if err != nil || len(history) != len(original)+1 {
		t.Fatal(err)
	}
	for i := range original {
		if original[i].UpSQL() != history[i].UpSQL() || original[i].Checksum() != history[i].Checksum() {
			t.Fatal("prior migration rewritten")
		}
	}
	history[0] = history[len(history)-1]
	again, err := s.Load(context.Background())
	if err != nil || again[0].Checksum() != original[0].Checksum() {
		t.Fatal("history aliased", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = s.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled migration", err)
	}
	s.Version = 23
	if _, err = s.Load(context.Background()); err == nil {
		t.Fatal("non-forward allocation")
	}
}

func TestLockoutEndPreservesOriginalIntervalAndDeniesFutureEnd(t *testing.T) {
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	end := now.Add(time.Minute)
	l := nativeLockout{startedAt: now, expiresAt: now.Add(time.Hour), endedAt: &end}
	for _, tc := range []struct {
		at   time.Time
		deny bool
	}{{now.Add(-time.Microsecond), true}, {now, true}, {end.Add(-time.Microsecond), true}, {end, false}, {end.Add(time.Microsecond), false}} {
		if l.denies(tc.at) != tc.deny {
			t.Fatal("explicit original end boundary not enforced", tc.at)
		}
	}
	if l.expiresAt != now.Add(time.Hour) {
		t.Fatal("ending rewrote original interval")
	}
}
