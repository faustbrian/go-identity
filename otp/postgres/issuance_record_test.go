package postgres

import (
	"bytes"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

func issuanceRecordSeed(t testing.TB) otp.Challenge {
	t.Helper()
	remember, err := session.NewRememberPolicy(session.RememberPolicySpec{Choice: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	original, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: session.PreAuthBinding{ID: identity.PreAuthTransactionID("AgICAgICAgICAgICAgICAg"), Intent: session.PreAuthIntent{TenantID: "tenant", Action: "identity.otp.signin", Origin: "https://identity.test", Nonce: [32]byte{1}, Remember: remember, PolicyID: "login", PolicyVersion: 11}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}, Cookie: session.TokenDigest{KeyVersion: 3, Sum: [32]byte{1}}, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	flow, err := otp.NewBoundPreAuthAuthorization(original)
	if err != nil {
		t.Fatal(err)
	}
	destination, _ := otp.NewDestinationInput("private-person@example.test")
	continuation, err := otp.NewContinuation(otp.DigestScopeSpec{TenantID: "tenant", Purpose: otp.PurposeSignin, Channel: otp.ChannelEmail, Destination: destination, ChallengeID: "challenge", TargetID: "target", PolicyVersion: 11, Generation: 1}, flow, remember)
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposeSignin, Alphabet: "0123456789", Length: 6, TTL: 5 * time.Minute, ResendInterval: time.Minute, MaximumSends: 5, Attempts: 5, Replacement: otp.RetainPrevious})
	policy, _ := otp.NewAttemptPolicy(profile, otp.CheckPolicySpec{LockoutAfter: time.Minute})
	challenge, err := otp.NewChallenge(otp.ChallengeSpec{Continuation: continuation, Policy: policy, Digest: otp.StoredCodeDigest{KeyVersion: 4, Value: [32]byte{1}}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), State: otp.ChallengeIssued, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	return challenge
}

func TestIssuanceRecordClosedCanonicalFrame(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		_, challenge, _, _, _ := issuanceCustodyFixture(t, authenticated)
		data := encodeIssuanceRecord(challenge)
		decoded, err := decodeIssuanceRecord(data)
		if err != nil || !bytes.Equal(data, encodeIssuanceRecord(decoded)) {
			t.Fatal("valid frame changed")
		}
		for n := range len(data) {
			if _, err := decodeIssuanceRecord(data[:n]); err == nil {
				t.Fatal("truncated custody accepted")
			}
		}
		if _, err := decodeIssuanceRecord(append(bytes.Clone(data), 0)); err == nil {
			t.Fatal("trailing custody accepted")
		}
		if _, err := decodeIssuanceRecord(bytes.Repeat([]byte{0}, 8193)); err == nil {
			t.Fatal("oversized custody accepted")
		}
	}
}

func TestIssuanceRecordPreservesPurposeAndPolicy(t *testing.T) {
	seed, _ := issuanceRecordSeed(t).Bindings()
	base, _ := seed.Continuation.Bindings()
	for _, purpose := range []otp.Purpose{otp.PurposeSignin, otp.PurposeEmailVerification, otp.PurposePasswordReset, otp.PurposeEmailChange, otp.PurposeMFA, otp.PurposeStepUp} {
		scope := base.Scope
		scope.Purpose, scope.AuthorizationBinding = purpose, [32]byte{}
		remember := session.RememberPolicy{}
		if purpose == otp.PurposeSignin || purpose == otp.PurposeMFA {
			remember = base.RememberPolicy
		}
		continuation, err := otp.NewContinuation(scope, base.Authorization, remember)
		if err != nil {
			t.Fatal(err)
		}
		p, checks, _ := seed.Policy.Bindings()
		p.Purpose = purpose
		profile, _ := otp.NewCodeProfile(p)
		policy, _ := otp.NewAttemptPolicy(profile, checks)
		s := seed
		s.Continuation, s.Policy = continuation, policy
		challenge, err := otp.NewChallenge(s)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeIssuanceRecord(encodeIssuanceRecord(challenge))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := decoded.Bindings()
		gc, _ := got.Continuation.Bindings()
		if gc.Scope.Purpose != purpose || got.Policy != policy || gc.RememberPolicy != remember {
			t.Fatal("purpose/policy coerced")
		}
	}
}

func FuzzIssuanceRecord(f *testing.F) {
	f.Add(encodeIssuanceRecord(issuanceRecordSeed(f)))
	f.Add([]byte(issuanceRecordPrefix))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8193 {
			return
		}
		challenge, err := decodeIssuanceRecord(data)
		if err != nil {
			return
		}
		if !bytes.Equal(data, encodeIssuanceRecord(challenge)) {
			t.Fatal("noncanonical issuance frame accepted")
		}
	})
}
