package mfa_test

import (
	"testing"
	"time"

	"github.com/faustbrian/go-identity/mfa"
)

func FuzzContinuationBoundsAndClosedLifecycle(f *testing.F) {
	f.Add("AAAAAAAAAAAAAAAAAAAAAQ", "https://app.test", "totp", uint8(mfa.Pending), uint32(3), uint64(1))
	f.Add("", "https://app.test?", "password", uint8(0), uint32(0), uint64(0))
	f.Add("AAAAAAAAAAAAAAAAAAAAAQ", "https://app.test", "recovery-code", uint8(mfa.Revoked), uint32(0), uint64(100))
	f.Fuzz(func(t *testing.T, id, origin, method string, state uint8, remaining uint32, version uint64) {
		spec := continuationFixture(t)
		spec.ID, spec.Origin, spec.AllowedMethods = mfa.ContinuationID(id), origin, []string{method}
		spec.State, spec.AttemptsRemaining, spec.Version = mfa.ContinuationState(state), remaining, version
		c, err := mfa.NewPartialAuthContinuation(spec)
		if err != nil {
			return
		}
		got, err := c.Bindings()
		if err != nil || got.ID != spec.ID || got.Origin != origin || got.ExpiresAt != spec.ExpiresAt || got.RememberPolicy != spec.RememberPolicy {
			t.Fatal("accepted state changed immutable input")
		}
		if _, err := c.CapabilityPayload("https://issuer.test"); err != nil {
			t.Fatal("accepted state cannot bind scope", err)
		}
		if c.RequirePending(spec.ExpiresAt) == nil {
			t.Fatal("absolute expiry bypassed")
		}
		next, err := c.RecordAttempt(method, spec.IssuedAt.Add(time.Second), version)
		if err == nil {
			result, _ := next.Bindings()
			if remaining == 0 || result.AttemptsRemaining != remaining-1 || result.Version != version+1 || result.ExpiresAt != got.ExpiresAt {
				t.Fatal("attempt budget/version/lifetime diverged")
			}
		}
	})
}
