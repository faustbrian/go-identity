package otp_test

import (
	"context"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

func phoneRecoveryChallenge(t *testing.T) (otp.ChallengeSpec, otp.Verifier, otp.AttemptIssuer, auth.OneTimeCode) {
	t.Helper()
	s, verifier, _ := challengeFixture(t)
	base := boundPreAuthSpec(t)
	base.Binding.Intent.Purpose = session.PreAuthPhonePasswordRecovery
	base.Binding.Intent.Action = "identity.phone.password-reset-request"
	base.Binding.Intent.IdentifierBinding = [32]byte{1}
	base.Binding.Intent.Remember = session.RememberPolicy{}
	record, err := session.NewPreAuthTransaction(base)
	if err != nil {
		t.Fatal(err)
	}
	flow, _ := otp.NewBoundPreAuthAuthorization(record)
	scope, _ := s.Continuation.Bindings()
	scope.Scope.AuthorizationBinding = [32]byte{}
	scope.Scope.Purpose, scope.Scope.Channel, scope.Scope.SubjectID = otp.PurposePasswordReset, otp.ChannelSMS, "user"
	scope.Scope.Destination, _ = otp.NewDestinationInput("+358401234567")
	s.Continuation, err = otp.NewContinuation(scope.Scope, flow, session.RememberPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	p, checks, _ := s.Policy.Bindings()
	p.Purpose = otp.PurposePasswordReset
	profile, _ := otp.NewCodeProfile(p)
	s.Policy, _ = otp.NewAttemptPolicy(profile, checks)
	code, _ := auth.NewOneTimeCode("123456")
	digestScope, _ := s.Continuation.DigestScope()
	digest, err := verifier.Digest(digestScope, code)
	if err != nil {
		t.Fatal(err)
	}
	s.Digest = digest.Storage()
	issuer, _ := otp.NewAttemptIssuer(1, [32]byte{2})
	return s, verifier, issuer, code
}

func TestPhoneRecoveryIndependentFactorDenialDebitsOneSharedBudget(t *testing.T) {
	s, verifier, issuer, correct := phoneRecoveryChallenge(t)
	challenge, err := otp.NewChallenge(s)
	if err != nil {
		t.Fatal(err)
	}
	attempt, _ := issuer.Prepare(context.Background(), s.Continuation, otp.AttemptModeConsume, s.Version, correct)
	ordinary, err := verifier.EvaluateAttempt(challenge, attempt, s.IssuedAt)
	if err != nil || ordinary.Outcome != otp.AttemptReserved {
		t.Fatal("success control cannot reserve", err)
	}
	denied, err := verifier.EvaluatePhoneRecoveryDenial(challenge, attempt, s.IssuedAt)
	if err != nil || denied.Outcome != otp.AttemptDenied || denied.State != otp.ChallengeIssued || denied.Version != 2 || denied.UsedAttempts != 1 || denied.FailedAttempts != 1 || denied.Checks != 0 || denied.LockoutAfter != 0 {
		t.Fatal("correct SMS plus denied independent factor did not charge exactly one non-consuming denial", err)
	}
	wrong, _ := auth.NewOneTimeCode("234567")
	wrongAttempt, _ := issuer.Prepare(context.Background(), s.Continuation, otp.AttemptModeConsume, s.Version, wrong)
	wrongDecision, err := verifier.EvaluatePhoneRecoveryDenial(challenge, wrongAttempt, s.IssuedAt)
	if err != nil || wrongDecision != denied {
		t.Fatal("either failed factor must yield the same one-charge proposal", err)
	}
	s.Version, s.UsedAttempts, s.FailedAttempts = denied.Version, denied.UsedAttempts, denied.FailedAttempts
	updated, err := otp.NewChallenge(s)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := verifier.EvaluatePhoneRecoveryDenial(updated, attempt, s.IssuedAt)
	if err != nil || stale.Outcome != otp.AttemptConflict || stale.Version != 2 || stale.UsedAttempts != 1 {
		t.Fatal("stale original submission charged twice", err)
	}
	second, _ := issuer.Prepare(context.Background(), s.Continuation, otp.AttemptModeConsume, s.Version, correct)
	exhausted, err := verifier.EvaluatePhoneRecoveryDenial(updated, second, s.IssuedAt)
	if err != nil || exhausted.Outcome != otp.AttemptExhausted || exhausted.State != otp.ChallengeExhausted || exhausted.UsedAttempts != 2 || exhausted.FailedAttempts != 2 || exhausted.Version != 3 || exhausted.LockoutAfter != time.Minute {
		t.Fatal("compound denial did not exhaust the existing challenge budget", err)
	}
}

func TestPhoneRecoveryDenialCannotWidenIntoCheckOrForeignAuthority(t *testing.T) {
	s, verifier, issuer, code := phoneRecoveryChallenge(t)
	challenge, _ := otp.NewChallenge(s)
	attempt, _ := issuer.Prepare(context.Background(), s.Continuation, otp.AttemptModeConsume, s.Version, code)
	expired, err := verifier.EvaluatePhoneRecoveryDenial(challenge, attempt, s.ExpiresAt)
	if err != nil || expired.Outcome != otp.AttemptExpired || expired.UsedAttempts != 0 || expired.FailedAttempts != 0 {
		t.Fatal("exclusive expiry charged a comparison", err)
	}
	check, _ := issuer.Prepare(context.Background(), s.Continuation, otp.AttemptModeCheck, s.Version, code)
	if _, err := verifier.EvaluatePhoneRecoveryDenial(challenge, check, s.IssuedAt); err == nil {
		t.Fatal("compound denial became a metered precheck")
	}
	legacy, _, foreign := challengeFixture(t)
	foreignChallenge, _ := otp.NewChallenge(legacy)
	if _, err := verifier.EvaluatePhoneRecoveryDenial(foreignChallenge, foreign, s.IssuedAt); err == nil {
		t.Fatal("ordinary login challenge acquired compound recovery semantics")
	}
	decision, err := verifier.EvaluatePhoneRecoveryDenial(challenge, foreign, s.IssuedAt)
	if err != nil || decision.Version != s.Version || decision.UsedAttempts != 0 {
		t.Fatal("foreign submission charged recovery", err)
	}
	retired, _ := otp.NewVerifier(2, map[uint32][32]byte{2: {2}})
	if out, err := retired.EvaluatePhoneRecoveryDenial(challenge, attempt, s.IssuedAt); err == nil || out != (otp.AttemptDecision{}) {
		t.Fatal("missing digest key charged recovery")
	}
}
