package mfapostgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/mfa"
)

func TestRecoveryAndTOTPDenialsShareOriginalBudget(t *testing.T) {
	c := continuationFixture(t)
	s, _ := c.Bindings()
	now := s.IssuedAt.Add(time.Second)
	var writtenState int16
	var writtenRemaining int32
	var writtenVersion string
	calls := 0
	sql := totpAttemptSQL{exec: func(_ context.Context, _ string, args ...any) (int64, error) {
		calls++
		writtenState, writtenVersion, writtenRemaining = args[3].(int16), args[4].(string), args[5].(int32)
		return 1, nil
	}}
	if err := spendMFAAttempt(t.Context(), sql, c, now, "recovery-code"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || writtenState != int16(mfa.Challenged) || writtenVersion != "2" || writtenRemaining != 2 {
		t.Fatal("recovery denial did not use original continuation budget")
	}
	c, _ = c.RecordAttempt("recovery-code", now, s.Version)
	s, _ = c.Bindings()
	if err := spendMFAAttempt(t.Context(), sql, c, now, "totp"); err != nil || writtenVersion != "3" || writtenRemaining != 1 {
		t.Fatal("TOTP fallback reset recovery budget", err)
	}
	c, _ = c.RecordAttempt("totp", now, s.Version)
	if err := spendMFAAttempt(t.Context(), sql, c, now, "recovery-code"); err != nil || writtenState != int16(mfa.Revoked) || writtenVersion != "4" || writtenRemaining != 0 {
		t.Fatal("mixed-method exhaustion did not revoke", err)
	}
	before := calls
	if err := spendMFAAttempt(t.Context(), sql, c, now, "unknown"); err == nil || calls != before {
		t.Fatal("unsupported method mutated continuation")
	}
	s, _ = continuationFixture(t).Bindings()
	s.AllowedMethods = []string{"totp"}
	onlyTOTP, err := mfa.NewPartialAuthContinuation(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := spendMFAAttempt(t.Context(), sql, onlyTOTP, now, "recovery-code"); err == nil || calls != before {
		t.Fatal("disallowed recovery method charged or downgraded")
	}
}
