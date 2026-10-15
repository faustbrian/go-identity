package risk

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

type verificationCounterPolicy interface {
	PrepareVerification(Context, Subject, string, time.Time) (CounterCommand, error)
	ValidateVerification(CounterCommand, Context, Subject, string, time.Time) error
}

func TestEmailChangeCountersKeepDistinctProofBoundAction(t *testing.T) {
	key, _ := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	policy, _ := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: testPolicy(t), Keys: []CounterDigestKey{key}})
	owner, ok := any(policy).(interface {
		PrepareEmailChange(Context, Subject, string, time.Time) (CounterCommand, error)
		ValidateEmailChange(CounterCommand, Context, Subject, string, time.Time) error
	})
	if !ok {
		t.Fatal("new-address confirmation cannot charge genuine proof-bound counters")
	}
	now := testContext().Now.UTC().Truncate(time.Microsecond)
	scope := Context{Tenant: "tenant", Operation: "identity.email.change-confirm", Attempt: "attempt"}
	subject := Subject{User: "user", Network: "127.0.0.1"}
	command, err := owner.PrepareEmailChange(scope, subject, "change-grant", now)
	if err != nil || owner.ValidateEmailChange(command, scope, subject, "change-grant", now) != nil {
		t.Fatal("genuine change counters failed", err)
	}
	if policy.ValidateVerification(command, scope, subject, "change-grant", now) == nil {
		t.Fatal("change aliased verification-only")
	}
	if owner.ValidateEmailChange(command, scope, subject, "other-grant", now) == nil || owner.ValidateEmailChange(command, scope, subject, "change-grant", now.Add(15*time.Minute)) == nil {
		t.Fatal("changed proof or expired evidence admitted")
	}
	scope.Operation = "identity.email.verification-confirm"
	if _, err := owner.PrepareEmailChange(scope, subject, "change-grant", now); err == nil {
		t.Fatal("change widened verification API")
	}
}

// Signup confirmation has no authenticated session. Its real signed grant ID
// must select a distinct counter dimension, not masquerade as a session. These
// pure projections grant neither proof authentication nor allowance/consumption.
func TestVerificationCountersBindProofWithoutInventingSession(t *testing.T) {
	key, _ := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	policy, _ := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: testPolicy(t), Keys: []CounterDigestKey{key}})
	owner, ok := any(policy).(verificationCounterPolicy)
	if !ok {
		t.Fatal("sessionless verification counter preparation is missing")
	}
	now := testContext().Now.UTC().Truncate(time.Microsecond)
	scope := Context{Tenant: "tenant", Operation: "identity.email.verification-confirm", Attempt: "attempt"}
	subject := Subject{User: "user", Network: "2001:db8::1"}
	command, err := owner.PrepareVerification(scope, subject, "original-grant", now)
	if err != nil {
		t.Fatal("original signup proof counter preparation denied", err)
	}
	b := command.Bindings()
	want := []Dimension{TenantDimension, SubjectDimension, "capability", NetworkDimension}
	if b.Phase != ReserveWithCommand || b.Window != 15*time.Minute || b.Limit != 5 || b.PreparedAt != now || len(b.Targets) != len(want) {
		t.Fatal("verification changed protected profile bounds")
	}
	for n, target := range b.Targets {
		if target.Dimension != want[n] || len(target.Keys) != 1 || !strings.HasPrefix(target.Keys[0].Encoded, "rc1:7:") || strings.Contains(target.Keys[0].Encoded, "original-grant") {
			t.Fatal("proof counter has wrong or raw dimension")
		}
	}
	if err := owner.ValidateVerification(command, scope, subject, "original-grant", now); err != nil {
		t.Fatal("original verification counter denied", err)
	}
	if policy.Validate(command, scope, subject, now) == nil {
		t.Fatal("session-based validator accepted sessionless proof lane")
	}
	canonical := subject
	canonical.Network = "2001:0db8:0:0:0:0:0:1"
	if owner.ValidateVerification(command, scope, canonical, "original-grant", now) != nil {
		t.Fatal("canonical network equivalence lost")
	}
	for _, change := range []func(*Context, *Subject, *string){
		func(c *Context, s *Subject, p *string) { c.Tenant = "foreign" },
		func(c *Context, s *Subject, p *string) { c.Attempt = "foreign" },
		func(c *Context, s *Subject, p *string) { s.User = "foreign" },
		func(c *Context, s *Subject, p *string) { s.Network = "192.0.2.1" },
		func(c *Context, s *Subject, p *string) { *p = "foreign-grant" },
	} {
		c, s, proof := scope, subject, "original-grant"
		change(&c, &s, &proof)
		if owner.ValidateVerification(command, c, s, proof, now) == nil {
			t.Fatal("foreign scope or proof validated")
		}
	}
	for _, at := range []time.Time{now.Add(-time.Microsecond), now.Add(time.Nanosecond), now.Add(15 * time.Minute)} {
		if owner.ValidateVerification(command, scope, subject, "original-grant", at) == nil {
			t.Fatal("invalid or expired observation validated")
		}
	}
	for _, action := range []Action{"identity.email.verification-send", "identity.email.change-confirm", "identity.password.change", "verification-confirm"} {
		wrong := scope
		wrong.Operation = action
		if got, err := owner.PrepareVerification(wrong, subject, "original-grant", now); err == nil || got.Bindings().Fingerprint != "" {
			t.Fatal("proof lane widened another protected operation")
		}
	}
	for _, proof := range []string{"", strings.Repeat("x", 257), "raw\nproof"} {
		if got, err := owner.PrepareVerification(scope, subject, proof, now); err == nil || got.Bindings().Fingerprint != "" {
			t.Fatal("unbounded or invalid proof ID admitted")
		}
	}
	for _, mutate := range []func(*Subject){
		func(s *Subject) { s.Session = "claimed-session" },
		func(s *Subject) { s.Actor = "claimed-actor" },
		func(s *Subject) { s.Device = "extra" },
		func(s *Subject) { s.User = "" },
		func(s *Subject) { s.Network = "::" },
	} {
		wrong := subject
		mutate(&wrong)
		if got, err := owner.PrepareVerification(scope, wrong, "original-grant", now); err == nil || got.Bindings().Fingerprint != "" {
			t.Fatal("missing or foreign dimension admitted")
		}
	}
	if _, err := owner.PrepareVerification(scope, subject, strings.Repeat("x", 256), now); err != nil {
		t.Fatal("issuer-supported grant ID boundary narrowed", err)
	}
	other, _ := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: testPolicy(t), Keys: []CounterDigestKey{key}})
	if other.ValidateVerification(command, scope, subject, "original-grant", now) == nil || (CommandCounterPolicy{}).ValidateVerification(command, scope, subject, "original-grant", now) == nil || owner.ValidateVerification(CounterCommand{}, scope, subject, "original-grant", now) == nil {
		t.Fatal("foreign or zero ownership admitted")
	}
	sessionSubject := subject
	sessionSubject.Session = "real-session"
	sessionCommand, err := policy.Prepare(scope, sessionSubject, now)
	if err != nil || policy.Validate(sessionCommand, scope, sessionSubject, now) != nil || owner.ValidateVerification(sessionCommand, scope, subject, "original-grant", now) == nil {
		t.Fatal("existing session lane changed or admitted as proof lane", err)
	}
	config := testPolicyConfig()
	config.Profiles[1].Window, config.Profiles[1].EvidenceTTL, config.Profiles[1].Limit = time.Minute, time.Second, 2
	lower, _ := NewPolicy(config)
	lowerCounters, _ := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: lower, Keys: []CounterDigestKey{key}})
	limited, err := lowerCounters.PrepareVerification(scope, subject, "original-grant", now)
	if err != nil || limited.Bindings().Window != time.Minute || limited.Bindings().Limit != 2 || lowerCounters.ValidateVerification(limited, scope, subject, "original-grant", now.Add(time.Second)) == nil {
		t.Fatal("explicit lower bounds or expiry widened", err)
	}
}
