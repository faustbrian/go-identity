package risk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func lockoutPolicyForTest(t *testing.T) LockoutPolicy {
	t.Helper()
	key, _ := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	counters, err := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: testPolicy(t), Keys: []CounterDigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewLockoutPolicy(LockoutPolicyConfig{Counters: counters, MaximumDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func lockoutRequestForTest() LockoutRequest {
	return LockoutRequest{Scope: Context{Tenant: "tenant", Operation: "identity.password.change", Attempt: "attempt"}, Subject: Subject{User: "user", Session: "session", Network: "2001:db8::1"}, Actor: "risk-administrator", Mode: StartLockout, Duration: time.Minute}
}

// QA: narrow override, no unauthenticated account-lockout DoS, rotation scope.
func TestLockoutPreparationOwnsOriginalBoundedIntent(t *testing.T) {
	p := lockoutPolicyForTest(t)
	now := testContext().Now.UTC().Truncate(time.Microsecond)
	r := lockoutRequestForTest()
	c, err := p.Prepare(r, now)
	if err != nil {
		t.Fatal(err)
	}
	b := c.Bindings()
	if b.Mode != StartLockout || b.ExpectedVersion != 0 || b.Duration != time.Minute || b.Actor != r.Actor || b.Counter.Operation != r.Scope.Operation || b.Target.Dimension != SubjectDimension || len(b.Target.Keys) != 1 {
		t.Fatal("lost original restriction intent")
	}
	b.Target.Keys[0].Encoded = "changed"
	b.Counter.Targets[0].Keys[0].Encoded = "changed"
	if c.Bindings().Target.Keys[0].Encoded == "changed" || p.Validate(c, r, now) != nil {
		t.Fatal("projection changed immutable intent")
	}
	other := lockoutPolicyForTest(t)
	if other.Validate(c, r, now) == nil {
		t.Fatal("foreign policy accepted command")
	}
	for _, at := range []time.Time{now.Add(-time.Microsecond), now.Add(15 * time.Minute), now.Add(time.Nanosecond)} {
		if p.Validate(c, r, at) == nil {
			t.Fatal("invalid or renewed preparation accepted")
		}
	}
	if p.Validate(c, r, now.Add(15*time.Minute-time.Microsecond)) != nil {
		t.Fatal("exclusive boundary shortened")
	}
	r.Mode, r.ExpectedVersion, r.Duration = EndLockout, 9, 0
	end, err := p.Prepare(r, now)
	if err != nil || end.Bindings().Mode != EndLockout || end.Bindings().ExpectedVersion != 9 || end.Bindings().Duration != 0 {
		t.Fatal("CAS end unavailable", err)
	}
}

func TestLockoutPreparationRejectsBroadOrChangedAuthority(t *testing.T) {
	p := lockoutPolicyForTest(t)
	now := testContext().Now.UTC().Truncate(time.Microsecond)
	r := lockoutRequestForTest()
	c, _ := p.Prepare(r, now)
	for _, change := range []func(*LockoutRequest){
		func(r *LockoutRequest) { r.Scope.Tenant = "other" },
		func(r *LockoutRequest) { r.Scope.Attempt = "other" },
		func(r *LockoutRequest) { r.Subject.User = "other" },
		func(r *LockoutRequest) { r.Subject.Network = "192.0.2.1" },
		func(r *LockoutRequest) { r.Subject.Session = "other" },
		func(r *LockoutRequest) { r.Actor = "other" },
		func(r *LockoutRequest) { r.ExpectedVersion = 1 },
		func(r *LockoutRequest) { r.Duration = 2 * time.Minute },
	} {
		changed := r
		change(&changed)
		if p.Validate(c, changed, now) == nil {
			t.Fatal("changed original intent admitted")
		}
	}
	for _, change := range []func(*LockoutRequest){
		func(r *LockoutRequest) { r.Actor = "" },
		func(r *LockoutRequest) { r.Actor = strings.Repeat("a", 129) },
		func(r *LockoutRequest) { r.Scope.Now = now },
		func(r *LockoutRequest) { r.Scope.IndependentFactor = true },
		func(r *LockoutRequest) { r.Mode = "override" },
		func(r *LockoutRequest) { r.ExpectedVersion = ^uint64(0) },
		func(r *LockoutRequest) { r.Duration = 0 },
		func(r *LockoutRequest) { r.Duration = time.Hour + time.Microsecond },
		func(r *LockoutRequest) { r.Duration = time.Nanosecond },
		func(r *LockoutRequest) { r.Mode = EndLockout; r.Duration = 0 },
		func(r *LockoutRequest) { r.Mode = EndLockout; r.ExpectedVersion = 1 },
		func(r *LockoutRequest) { r.Subject.User = "" },
		func(r *LockoutRequest) { r.Subject.IdentifierDigest = "hint" },
		func(r *LockoutRequest) { r.Scope.Operation = "identity.password.signin" },
		func(r *LockoutRequest) { r.Scope.Operation = "identity.password.reset-complete" },
		func(r *LockoutRequest) { r.Scope.Operation = "identity.profile.get" },
		func(r *LockoutRequest) { r.Scope.Operation = "identity.admin.user-ban" },
		func(r *LockoutRequest) { r.Scope.Operation = "unknown" },
	} {
		changed := r
		change(&changed)
		if got, err := p.Prepare(changed, now); err == nil || got.Bindings().Target.Dimension != "" {
			t.Fatal("unsafe preparation accepted")
		}
	}
}

func TestLockoutExclusiveTimeBoundsAndScopedRoots(t *testing.T) {
	p := lockoutPolicyForTest(t)
	now := testContext().Now.UTC().Truncate(time.Microsecond)
	r := lockoutRequestForTest()
	r.Duration = time.Hour
	first, err := p.Prepare(r, now)
	if err != nil {
		t.Fatal("configured exact maximum rejected", err)
	}
	other := r
	other.Scope.Tenant = "other"
	second, err := p.Prepare(other, now)
	if err != nil || first.Bindings().Target.Keys[0].Encoded == second.Bindings().Target.Keys[0].Encoded {
		t.Fatal("tenant restriction roots collided", err)
	}
	for _, at := range []time.Time{{}, now.Add(time.Nanosecond), now.In(time.FixedZone("offset", 3600)), time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC)} {
		if _, err := p.Prepare(r, at); err == nil {
			t.Fatal("invalid or overflowing primary interval admitted")
		}
	}
	end := r
	end.Mode, end.ExpectedVersion, end.Duration = EndLockout, 1, 0
	c, err := p.Prepare(end, now)
	if err != nil || p.Validate(c, end, now) != nil {
		t.Fatal("end intent rejected", err)
	}
}

// QA: safe recovery is not synonymous with the Authentication risk class.
// Several factor-proof and administrative recovery operations use the same
// CredentialMutation counter profile as ordinary credential changes.
func TestLockoutPreservesFactorAndAdministrativeRecoveryRoutes(t *testing.T) {
	p := lockoutPolicyForTest(t)
	now := testContext().Now.UTC().Truncate(time.Microsecond)
	for _, action := range []Action{
		"identity.mfa.recovery-use", "identity.mfa.recovery-regenerate",
		"identity.mfa.totp-verify", "identity.mfa.security-key-assert-verify",
		"identity.mfa.otp-send", "identity.mfa.otp-verify",
		"identity.admin.mfa-recovery-issue", "identity.admin.mfa-reset",
	} {
		t.Run(string(action), func(t *testing.T) {
			r := lockoutRequestForTest()
			r.Scope.Operation = action
			if c, err := p.Prepare(r, now); err == nil || c.Bindings().Target.Dimension != "" {
				t.Fatal("safe recovery operation became a lockout target")
			}
		})
	}
}

func TestLockoutConfigurationAndRedaction(t *testing.T) {
	p := lockoutPolicyForTest(t)
	r := lockoutRequestForTest()
	c, _ := p.Prepare(r, testContext().Now.UTC().Truncate(time.Microsecond))
	for _, v := range []any{p, c, r, c.Bindings(), LockoutPolicyConfig{Counters: p.state.counters, MaximumDuration: time.Hour}} {
		if out := fmt.Sprintf("%+v %#v", v, v); strings.Contains(out, "risk-administrator") || strings.Contains(out, "2001:db8") || strings.Contains(out, c.Bindings().Target.Keys[0].Encoded) {
			t.Fatal("restriction custody exposed")
		}
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("sensitive restriction serialized")
		}
		if _, err := v.(interface{ MarshalText() ([]byte, error) }).MarshalText(); err == nil {
			t.Fatal("sensitive restriction serialized as text")
		}
	}
	for _, cfg := range []LockoutPolicyConfig{{}, {Counters: p.state.counters}, {Counters: p.state.counters, MaximumDuration: -time.Microsecond}, {Counters: p.state.counters, MaximumDuration: time.Nanosecond}} {
		if _, err := NewLockoutPolicy(cfg); err == nil {
			t.Fatal("invalid duration policy accepted")
		}
	}
	if _, err := (LockoutPolicy{}).Prepare(r, testContext().Now); err == nil {
		t.Fatal("zero policy accepted")
	}
	if p.Validate(LockoutCommand{}, r, testContext().Now) == nil {
		t.Fatal("zero command accepted")
	}
}
