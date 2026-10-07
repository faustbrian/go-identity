package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/otp"
)

func sendPolicy(t *testing.T, cap uint32) otp.CodeProfile {
	t.Helper()
	p, err := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposeEmailVerification, Alphabet: "0123456789", Length: 6, TTL: time.Minute, ResendInterval: time.Minute, MaximumSends: cap, Attempts: 3, Replacement: otp.RetainPrevious})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSendWindowExactBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 7, 1, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		sent   []time.Time
		at     time.Time
		denied bool
		count  int
	}{
		{"first", nil, now, false, 1},
		{"before-resend", []time.Time{now.Add(-time.Minute)}, now.Add(-time.Microsecond), true, 0},
		{"exact-resend", []time.Time{now.Add(-time.Minute)}, now, false, 2},
		{"after-resend", []time.Time{now.Add(-time.Minute)}, now.Add(time.Microsecond), false, 2},
		{"hour-before", []time.Time{now.Add(-time.Hour), now.Add(-2 * time.Minute)}, now.Add(-time.Microsecond), true, 0},
		{"hour-exact", []time.Time{now.Add(-time.Hour), now.Add(-2 * time.Minute)}, now, false, 2},
		{"hour-after", []time.Time{now.Add(-time.Hour), now.Add(-2 * time.Minute)}, now.Add(time.Microsecond), false, 2},
		{"cap", []time.Time{now.Add(-2 * time.Minute), now.Add(-time.Minute)}, now, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]time.Time(nil), tc.sent...)
			next, err := nextSendWindow(sendPolicy(t, 2), tc.sent, tc.at)
			if tc.denied {
				if !errors.Is(err, ErrInvalidCommand) || next != nil {
					t.Fatal("send allowance exceeded", err)
				}
			} else if err != nil || len(next) != tc.count || !next[len(next)-1].Equal(tc.at) {
				t.Fatal("boundary result", len(next), err)
			}
			for i := range before {
				if !tc.sent[i].Equal(before[i]) {
					t.Fatal("borrowed history mutated")
				}
			}
			if len(next) > 0 {
				next[0] = time.Time{}
				for i := range before {
					if !tc.sent[i].Equal(before[i]) {
						t.Fatal("result aliases history")
					}
				}
			}
		})
	}
}

func TestSendFamilyStableScope(t *testing.T) {
	p, _ := newLockoutProfile([32]byte{91})
	a, _ := mappedAttempt(t, otp.PurposeEmailVerification, false)
	b, _ := a.Bindings()
	c, _ := b.Continuation.Bindings()
	original := c.Scope
	first, err := p.sendIdentity(original)
	if err != nil || first == ([32]byte{}) {
		t.Fatal(err)
	}
	changed := original
	changed.ChallengeID, changed.TargetID = "successor", "other-target"
	changed.Generation++
	changed.PolicyVersion++
	changed.AuthorizationBinding = [32]byte{9}
	if next, err := p.sendIdentity(changed); err != nil || next != first {
		t.Fatal("reissue reset family allowance", err)
	}
	for _, mutate := range []func(*otp.DigestScopeSpec){
		func(s *otp.DigestScopeSpec) { s.TenantID = "other" },
		func(s *otp.DigestScopeSpec) { s.Purpose = otp.PurposePasswordReset },
		func(s *otp.DigestScopeSpec) { s.SubjectID = "other" },
		func(s *otp.DigestScopeSpec) { s.Channel = otp.ChannelSMS },
		func(s *otp.DigestScopeSpec) { s.Destination, _ = otp.NewDestinationInput("other@example.test") },
	} {
		s := original
		mutate(&s)
		if next, err := p.sendIdentity(s); err != nil || next == first {
			t.Fatal("distinct family shares allowance", err)
		}
	}
}

func TestSendWindowRejectsCorruptHistory(t *testing.T) {
	now := time.Date(2026, 10, 7, 1, 0, 0, 0, time.UTC)
	for _, history := range [][]time.Time{
		{time.Time{}}, {now.Add(time.Microsecond)}, {now.Add(-time.Minute).Add(time.Nanosecond)},
		{now.Add(-time.Minute), now.Add(-time.Minute)},
		{now.Add(-time.Minute), now.Add(-2 * time.Minute)},
		{now.Add(-2 * time.Minute), now.Add(-2*time.Minute + 29*time.Second)},
		make([]time.Time, 11),
	} {
		if next, err := nextSendWindow(sendPolicy(t, 2), history, now); !errors.Is(err, ErrInvalidCommand) || next != nil {
			t.Fatal("corrupt history granted allowance", err)
		}
	}
	if _, err := nextSendWindow(otp.CodeProfile{}, nil, now); err == nil {
		t.Fatal("zero policy accepted")
	}
	if _, err := nextSendWindow(sendPolicy(t, 2), nil, time.Time{}); err == nil {
		t.Fatal("zero time accepted")
	}
	p, _ := sendPolicy(t, 2).Bindings()
	p.ResendInterval += time.Nanosecond
	fractional, _ := otp.NewCodeProfile(p)
	if _, err := nextSendWindow(fractional, nil, now); err == nil {
		t.Fatal("SQL precision silently truncated")
	}
	if _, err := (lockoutProfile{}).sendIdentity(otp.DigestScopeSpec{}); err == nil {
		t.Fatal("unbound family accepted")
	}
}
