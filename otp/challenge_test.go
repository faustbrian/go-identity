package otp_test

import (
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-identity/otp"
)

func challengeFixture(t *testing.T) (otp.ChallengeSpec, otp.Verifier, otp.AttemptCommand) {
	t.Helper()
	p, e := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposeSignin, Alphabet: "0123456789", Length: 6, TTL: time.Minute, ResendInterval: time.Minute, MaximumSends: 2, Attempts: 2, Replacement: otp.ReplacePrevious})
	if e != nil {
		t.Fatal(e)
	}
	policy, e := otp.NewAttemptPolicy(p, otp.CheckPolicySpec{Enabled: true, MaximumChecks: 2, LockoutAfter: time.Minute})
	if e != nil {
		t.Fatal(e)
	}
	c := attemptContinuation(t)
	scope, _ := c.DigestScope()
	v, _ := otp.NewVerifier(1, map[uint32][32]byte{1: {1}})
	code, _ := auth.NewOneTimeCode("123456")
	digest, _ := v.Digest(scope, code)
	i, _ := otp.NewAttemptIssuer(1, [32]byte{2})
	cmd, e := i.Prepare(context.Background(), c, otp.AttemptModeConsume, 1, code)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	return otp.ChallengeSpec{Continuation: c, Policy: policy, Digest: digest.Storage(), IssuedAt: now, ExpiresAt: now.Add(time.Minute), State: otp.ChallengeIssued, Version: 1}, v, cmd
}

func TestAttemptPolicyBoundsAndExactProjection(t *testing.T) {
	s, _, _ := challengeFixture(t)
	profile, checks, e := s.Policy.Bindings()
	if e != nil || profile.Attempts != 2 || !checks.Enabled || checks.MaximumChecks != 2 || checks.LockoutAfter != time.Minute {
		t.Fatal("policy projection changed")
	}
	p, _ := otp.NewCodeProfile(profile)
	for _, invalid := range []otp.CheckPolicySpec{
		{}, {LockoutAfter: -1}, {LockoutAfter: 25 * time.Hour}, {LockoutAfter: time.Nanosecond},
		{Enabled: true, LockoutAfter: time.Minute}, {Enabled: true, MaximumChecks: 11, LockoutAfter: time.Minute},
		{MaximumChecks: 1, LockoutAfter: time.Minute},
	} {
		if _, e := otp.NewAttemptPolicy(p, invalid); !errors.Is(e, otp.ErrInvalidProfile) {
			t.Fatal("invalid check policy accepted")
		}
	}
	if _, e := otp.NewAttemptPolicy(otp.CodeProfile{}, checks); !errors.Is(e, otp.ErrInvalidProfile) {
		t.Fatal("zero profile accepted")
	}
	if _, _, e := (otp.AttemptPolicy{}).Bindings(); !errors.Is(e, otp.ErrInvalidProfile) {
		t.Fatal("zero policy projection")
	}
	disabled, e := otp.NewAttemptPolicy(p, otp.CheckPolicySpec{LockoutAfter: time.Microsecond})
	if e != nil {
		t.Fatal(e)
	}
	_, got, _ := disabled.Bindings()
	if got.Enabled || got.MaximumChecks != 0 || got.LockoutAfter != time.Microsecond {
		t.Fatal("disabled checks inferred differently")
	}
	// Returned policy structs are independent, not permission to mutate live policy.
	profile.Attempts = 9
	checks.MaximumChecks = 10
	again, againChecks, _ := s.Policy.Bindings()
	if again.Attempts != 2 || againChecks.MaximumChecks != 2 {
		t.Fatal("projection changed issued policy")
	}
}

func TestChallengeGuardsNeverChargeForeignOrTerminalState(t *testing.T) {
	s, v, cmd := challengeFixture(t)
	original := s
	for _, state := range []otp.ChallengeState{otp.ChallengeReserved, otp.ChallengeFinalized, otp.ChallengeReleased, otp.ChallengeExpired, otp.ChallengeRevoked, otp.ChallengeExhausted} {
		s := original
		s.State = state
		if state == otp.ChallengeReserved || state == otp.ChallengeFinalized || state == otp.ChallengeReleased {
			s.UsedAttempts = 1
		}
		if state == otp.ChallengeExhausted {
			s.UsedAttempts = 2
			s.FailedAttempts = 2
		}
		c, e := otp.NewChallenge(s)
		if e != nil {
			t.Fatal(e)
		}
		for _, now := range []time.Time{s.IssuedAt, s.ExpiresAt, s.ExpiresAt.Add(time.Hour)} {
			d, e := v.EvaluateAttempt(c, cmd, now)
			if e != nil || d.Outcome != otp.AttemptDenied || d.State != state || d.Version != 1 || d.FailedAttempts != s.FailedAttempts || d.Checks != 0 || d.LockoutAfter != 0 {
				t.Fatal("terminal or reserved state changed")
			}
		}
	}
	// Exact challenge version is mandatory, and wraparound cannot mint ownership.
	for _, version := range []uint64{2, ^uint64(0)} {
		s := original
		s.Version = version
		c, _ := otp.NewChallenge(s)
		d, e := v.EvaluateAttempt(c, cmd, s.IssuedAt)
		if e != nil || d.Outcome != otp.AttemptConflict || d.Version != version || d.FailedAttempts != 0 || d.Checks != 0 {
			t.Fatal("version bypass")
		}
	}
	// Matching the maximum version must also deny; stale-version rejection
	// alone would not detect a wrapping successor.
	max := original
	max.Version = ^uint64(0)
	maxChallenge, _ := otp.NewChallenge(max)
	issuer, _ := otp.NewAttemptIssuer(1, [32]byte{2})
	code, _ := auth.NewOneTimeCode("123456")
	maxCommand, _ := issuer.Prepare(context.Background(), max.Continuation, otp.AttemptModeConsume, max.Version, code)
	maxDecision, maxErr := v.EvaluateAttempt(maxChallenge, maxCommand, max.IssuedAt)
	if maxErr != nil || maxDecision.Outcome != otp.AttemptConflict || maxDecision.Version != max.Version {
		t.Fatal("matching maximum version wrapped")
	}
	c, _ := otp.NewChallenge(original)
	d, e := v.EvaluateAttempt(c, cmd, s.IssuedAt.Add(-time.Microsecond))
	if e != nil || d.Outcome != otp.AttemptDenied || d.Version != 1 {
		t.Fatal("future challenge admitted")
	}
	// Foreign scope fields cannot charge another challenge, even with correct code.
	for _, change := range []func(*otp.DigestScopeSpec){
		func(s *otp.DigestScopeSpec) { s.Purpose = otp.PurposeMFA },
		func(s *otp.DigestScopeSpec) { s.TenantID = "other" }, func(s *otp.DigestScopeSpec) { s.SubjectID = "other" },
		func(s *otp.DigestScopeSpec) { s.ChallengeID = "other" }, func(s *otp.DigestScopeSpec) { s.TargetID = "other" },
		func(s *otp.DigestScopeSpec) { s.Channel = otp.ChannelSMS }, func(s *otp.DigestScopeSpec) { s.PolicyVersion++ },
		func(s *otp.DigestScopeSpec) { s.Generation++ }, func(s *otp.DigestScopeSpec) { s.Destination, _ = otp.NewDestinationInput("other@example.test") },
	} {
		binding, _ := s.Continuation.Bindings()
		scope := binding.Scope
		scope.AuthorizationBinding = [32]byte{}
		change(&scope)
		foreign, e := otp.NewContinuation(scope, binding.Authorization, binding.RememberPolicy)
		if e != nil {
			t.Fatal(e)
		}
		issuer, _ := otp.NewAttemptIssuer(1, [32]byte{2})
		code, _ := auth.NewOneTimeCode("123456")
		foreignCommand, _ := issuer.Prepare(context.Background(), foreign, otp.AttemptModeConsume, 1, code)
		d, e := v.EvaluateAttempt(c, foreignCommand, s.IssuedAt)
		if e != nil || d.Outcome != otp.AttemptDenied || d.State != otp.ChallengeIssued || d.Version != 1 || d.FailedAttempts != 0 || d.Checks != 0 {
			t.Fatal("foreign scope charged")
		}
	}
}

func TestChallengeChecksAreBoundedWithoutBlockingConsume(t *testing.T) {
	s, v, _ := challengeFixture(t)
	profile, _, _ := s.Policy.Bindings()
	p, _ := otp.NewCodeProfile(profile)
	issuer, _ := otp.NewAttemptIssuer(1, [32]byte{2})
	code, _ := auth.NewOneTimeCode("123456")
	for _, disabled := range []bool{false, true} {
		s := s
		if disabled {
			s.Policy, _ = otp.NewAttemptPolicy(p, otp.CheckPolicySpec{LockoutAfter: time.Minute})
		} else {
			s.Policy, _ = otp.NewAttemptPolicy(p, otp.CheckPolicySpec{Enabled: true, MaximumChecks: 1, LockoutAfter: time.Minute})
			s.Checks, s.UsedAttempts = 1, 1
		}
		c, e := otp.NewChallenge(s)
		if e != nil {
			t.Fatal(e)
		}
		check, _ := issuer.Prepare(context.Background(), s.Continuation, otp.AttemptModeCheck, 1, code)
		d, e := v.EvaluateAttempt(c, check, s.IssuedAt)
		if e != nil || d.Outcome != otp.AttemptDenied || d.Version != 1 || d.Checks != s.Checks || d.FailedAttempts != 0 {
			t.Fatal("check limit bypass")
		}
		consume, _ := issuer.Prepare(context.Background(), s.Continuation, otp.AttemptModeConsume, 1, code)
		d, e = v.EvaluateAttempt(c, consume, s.IssuedAt)
		if e != nil || d.Outcome != otp.AttemptReserved || d.Checks != s.Checks || d.Version != 2 {
			t.Fatal("check cap disabled legitimate consume")
		}
	}
}

func TestChallengeKeyFailureCannotChargeOrReserve(t *testing.T) {
	s, _, cmd := challengeFixture(t)
	c, _ := otp.NewChallenge(s)
	retired, _ := otp.NewVerifier(2, map[uint32][32]byte{2: {2}})
	for _, v := range []otp.Verifier{retired, {}} {
		d, e := v.EvaluateAttempt(c, cmd, s.IssuedAt)
		if e == nil || d != (otp.AttemptDecision{}) {
			t.Fatal("key failure produced proposal")
		}
	}
	again, _ := c.Bindings()
	if again.Version != 1 || again.FailedAttempts != 0 || again.State != otp.ChallengeIssued {
		t.Fatal("key failure changed challenge")
	}
}

func TestChallengeNormalizationCustodyAndConcurrentEvaluation(t *testing.T) {
	s, v, cmd := challengeFixture(t)
	// No rounding; offset representations preserve the exact original instant.
	s.IssuedAt = s.IssuedAt.In(time.FixedZone("offset", 3600))
	s.ExpiresAt = s.ExpiresAt.In(time.FixedZone("offset", 3600))
	c, e := otp.NewChallenge(s)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := c.Bindings()
	if b.IssuedAt.Location() != time.UTC || b.ExpiresAt.Location() != time.UTC || !b.IssuedAt.Equal(s.IssuedAt) {
		t.Fatal("timestamp changed")
	}
	b.Version = 999
	again, _ := c.Bindings()
	if again.Version != 1 {
		t.Fatal("projection mutation retained")
	}
	if _, e := (otp.Challenge{}).Bindings(); !errors.Is(e, otp.ErrInvalidChallenge) {
		t.Fatal("zero projection")
	}
	d, _ := v.EvaluateAttempt(c, cmd, s.IssuedAt)
	for _, value := range []any{s, c, d} {
		for _, format := range []string{"%v", "%+v", "%#v", "%q", "%x"} {
			if !strings.Contains(fmt.Sprintf(format, value), "redacted") {
				t.Fatal("challenge metadata disclosed")
			}
		}
		if _, e := json.Marshal(value); e == nil {
			t.Fatal("challenge JSON allowed")
		}
		if _, e := value.(encoding.TextMarshaler).MarshalText(); !errors.Is(e, otp.ErrSensitiveSerialization) {
			t.Fatal("challenge text allowed")
		}
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			got, e := v.EvaluateAttempt(c, cmd, s.IssuedAt)
			if e != nil || got != d {
				t.Error("parallel evaluation changed")
			}
		})
	}
	wg.Wait()
}

func FuzzChallengeSnapshotBounds(f *testing.F) {
	f.Add(uint8(1), uint32(0), uint32(0), uint32(0), uint64(1))
	f.Add(uint8(7), uint32(2), uint32(2), uint32(1), uint64(2))
	f.Add(uint8(2), uint32(2), uint32(2), uint32(0), uint64(1))
	f.Add(uint8(0), uint32(0), uint32(0), uint32(0), uint64(0))
	f.Fuzz(func(t *testing.T, state uint8, used, failures, checks uint32, version uint64) {
		s, _, _ := challengeFixture(t)
		s.State, s.UsedAttempts, s.FailedAttempts, s.Checks, s.Version = otp.ChallengeState(state), used, failures, checks, version
		// Independent literal classification of the fixed two-attempt/two-check
		// fixture, not a production validator or returned policy bound.
		want := state >= 1 && state <= 7 && used <= 2 && failures <= used && checks <= used && checks <= 2 && version > 0 &&
			(state != 1 || used < 2) && (!(state == 2 || state == 3 || state == 4) || used > failures && used > checks) && (state != 7 || used == 2)
		c, e := otp.NewChallenge(s)
		if (e == nil) != want {
			t.Fatal("snapshot validity differs")
		}
		if want {
			got, e := c.Bindings()
			if e != nil || got.State != s.State || got.Version != version || got.UsedAttempts != used || got.FailedAttempts != failures || got.Checks != checks {
				t.Fatal("snapshot counters changed")
			}
		}
	})
}

func TestChallengeEvaluationProposesOnlyTheBoundedTransition(t *testing.T) {
	s, v, cmd := challengeFixture(t)
	c, e := otp.NewChallenge(s)
	if e != nil {
		t.Fatal(e)
	}
	d, e := v.EvaluateAttempt(c, cmd, s.IssuedAt)
	if e != nil || d.Outcome != otp.AttemptReserved || d.State != otp.ChallengeReserved || d.Version != 2 || d.UsedAttempts != 1 || d.FailedAttempts != 0 || d.Checks != 0 {
		t.Fatal("correct consuming proposal differs")
	}
	unchanged, _ := c.Bindings()
	if unchanged.State != otp.ChallengeIssued || unchanged.Version != 1 {
		t.Fatal("evaluation mutated primary declaration")
	}
	// Correct precheck uses a separate bounded budget, without reservation.
	code, _ := auth.NewOneTimeCode("123456")
	i, _ := otp.NewAttemptIssuer(1, [32]byte{2})
	check, _ := i.Prepare(context.Background(), s.Continuation, otp.AttemptModeCheck, 1, code)
	d, e = v.EvaluateAttempt(c, check, s.IssuedAt)
	if e != nil || d.Outcome != otp.AttemptChecked || d.State != otp.ChallengeIssued || d.Checks != 1 || d.UsedAttempts != 1 || d.FailedAttempts != 0 || d.Version != 2 {
		t.Fatal("check reserved or escaped separate budget")
	}
	// Expiry is exclusive; equality cannot reserve a code.
	d, e = v.EvaluateAttempt(c, cmd, s.ExpiresAt)
	if e != nil || d.Outcome != otp.AttemptExpired || d.State != otp.ChallengeExpired || d.Version != 2 {
		t.Fatal("expiry equality accepted")
	}
}

func TestChallengeWrongCodeCannotEscapeAcrossVerificationModes(t *testing.T) {
	s, v, _ := challengeFixture(t)
	wrong, _ := auth.NewOneTimeCode("654321")
	i, _ := otp.NewAttemptIssuer(1, [32]byte{2})
	for index, mode := range []otp.AttemptMode{otp.AttemptModeCheck, otp.AttemptModeConsume} {
		c, e := otp.NewChallenge(s)
		if e != nil {
			t.Fatal(e)
		}
		cmd, _ := i.Prepare(context.Background(), s.Continuation, mode, s.Version, wrong)
		d, e := v.EvaluateAttempt(c, cmd, s.IssuedAt)
		if e != nil || d.UsedAttempts != uint32(index+1) || d.FailedAttempts != uint32(index+1) || d.Checks != 1 || d.Version != s.Version+1 {
			t.Fatal("wrong code budget changed incorrectly")
		}
		if index == 0 && (d.Outcome != otp.AttemptDenied || d.State != otp.ChallengeIssued || d.LockoutAfter != 0) {
			t.Fatal("early exhaustion")
		}
		if index == 1 && (d.Outcome != otp.AttemptExhausted || d.State != otp.ChallengeExhausted || d.LockoutAfter != time.Minute) {
			t.Fatal("shared budget did not exhaust")
		}
		s.UsedAttempts, s.FailedAttempts, s.Checks, s.Version, s.State = d.UsedAttempts, d.FailedAttempts, d.Checks, d.Version, d.State
	}
	c, _ := otp.NewChallenge(s)
	good, _ := auth.NewOneTimeCode("123456")
	cmd, _ := i.Prepare(context.Background(), s.Continuation, otp.AttemptModeConsume, s.Version, good)
	d, e := v.EvaluateAttempt(c, cmd, s.IssuedAt)
	if e != nil || d.Outcome != otp.AttemptDenied || d.Version != s.Version {
		t.Fatal("exhausted challenge resurrected")
	}
}

func TestSuccessfulChecksAlsoConsumeTheProfileTotalAttemptBudget(t *testing.T) {
	s, v, _ := challengeFixture(t)
	issuer, _ := otp.NewAttemptIssuer(1, [32]byte{2})
	code, _ := auth.NewOneTimeCode("123456")
	for index := uint32(1); index <= 2; index++ {
		c, e := otp.NewChallenge(s)
		if e != nil {
			t.Fatal(e)
		}
		cmd, _ := issuer.Prepare(context.Background(), s.Continuation, otp.AttemptModeCheck, s.Version, code)
		d, e := v.EvaluateAttempt(c, cmd, s.IssuedAt)
		if e != nil || d.Outcome != otp.AttemptChecked || d.Checks != index || d.UsedAttempts != index || d.FailedAttempts != 0 || d.LockoutAfter != 0 || d.Version != s.Version+1 {
			t.Fatal("successful check did not account for attempt")
		}
		if index == 2 && d.State != otp.ChallengeExhausted {
			t.Fatal("successful checks bypassed total attempt budget")
		}
		s.UsedAttempts, s.Checks, s.Version, s.State = d.UsedAttempts, d.Checks, d.Version, d.State
	}
	c, _ := otp.NewChallenge(s)
	cmd, _ := issuer.Prepare(context.Background(), s.Continuation, otp.AttemptModeConsume, s.Version, code)
	d, e := v.EvaluateAttempt(c, cmd, s.IssuedAt)
	if e != nil || d.Outcome != otp.AttemptDenied || d.UsedAttempts != 2 || d.Version != s.Version {
		t.Fatal("check exhaustion admitted later consume")
	}
}

func TestChallengeInvalidInputFailsClosed(t *testing.T) {
	s, v, cmd := challengeFixture(t)
	for _, change := range []func(*otp.ChallengeSpec){
		func(s *otp.ChallengeSpec) { s.Continuation = otp.Continuation{} },
		func(s *otp.ChallengeSpec) { s.Policy = otp.AttemptPolicy{} },
		func(s *otp.ChallengeSpec) { s.Digest.KeyVersion = 0 },
		func(s *otp.ChallengeSpec) { s.Digest.Value = [32]byte{} },
		func(s *otp.ChallengeSpec) { s.IssuedAt = time.Time{} },
		func(s *otp.ChallengeSpec) { s.ExpiresAt = s.IssuedAt },
		func(s *otp.ChallengeSpec) { s.ExpiresAt = s.ExpiresAt.Add(time.Microsecond) },
		func(s *otp.ChallengeSpec) { s.IssuedAt = s.IssuedAt.Add(time.Nanosecond) },
		func(s *otp.ChallengeSpec) { s.State = 0 },
		func(s *otp.ChallengeSpec) { s.State = 99 },
		func(s *otp.ChallengeSpec) { s.Version = 0 },
		func(s *otp.ChallengeSpec) { s.UsedAttempts = 3 },
		func(s *otp.ChallengeSpec) { s.UsedAttempts = 2 },
		func(s *otp.ChallengeSpec) { s.State = otp.ChallengeReserved; s.UsedAttempts = 1; s.Checks = 1 },
		func(s *otp.ChallengeSpec) { s.FailedAttempts = 3 },
		func(s *otp.ChallengeSpec) { s.FailedAttempts = 2 },
		func(s *otp.ChallengeSpec) { s.Checks = 3 },
		func(s *otp.ChallengeSpec) { s.State = otp.ChallengeExhausted },
	} {
		copy := s
		change(&copy)
		if _, e := otp.NewChallenge(copy); !errors.Is(e, otp.ErrInvalidChallenge) {
			t.Fatal("malformed challenge accepted")
		}
	}
	c, _ := otp.NewChallenge(s)
	if _, e := v.EvaluateAttempt(otp.Challenge{}, cmd, s.IssuedAt); !errors.Is(e, otp.ErrInvalidChallenge) {
		t.Fatal("zero snapshot accepted")
	}
	if _, e := v.EvaluateAttempt(c, otp.AttemptCommand{}, s.IssuedAt); !errors.Is(e, otp.ErrInvalidAttempt) {
		t.Fatal("zero command accepted")
	}
	if _, e := v.EvaluateAttempt(c, cmd, time.Time{}); !errors.Is(e, otp.ErrInvalidChallenge) {
		t.Fatal("zero primary time accepted")
	}
}
