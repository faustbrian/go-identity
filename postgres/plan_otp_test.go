package postgres

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func otpPlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	_, command, p := featurePlanFixture(t)
	s, _ := command.Feature()
	p.SubjectType = "user"
	p.Audits[0].RetentionClass = "protected"
	p.Contributors = append(p.Contributors, ContributorDescriptor{Owner: "identity/otp/postgres", ContractID: "identity.otp.store", Version: 1})
	p.OTP = &OTPAttemptPlan{AttemptID: "AQAAAAAAAAAAAAAAAAAAAA", AttemptFingerprint: [32]byte{1}, FingerprintKeyVersion: 1, ChallengeID: "challenge-a", ScopeDigest: [32]byte{2}, DigestKeyVersion: 1, ExpectedVersion: 1, Mode: OTPConsume}
	return s.Binding, p
}

func TestOTPPlanBindsEveryFieldAndConservesHistory(t *testing.T) {
	b, p := otpPlanFixture(t)
	fingerprint := [32]byte{3}
	wire, err := encodeFeaturePlan(b, fingerprint, p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeFeaturePlan(b, fingerprint, wire)
	if err != nil || decoded.OTP == nil || *decoded.OTP != *p.OTP {
		t.Fatal("OTP custody not frozen in historical plan", err)
	}
	for _, change := range []func(*OTPAttemptPlan){
		func(s *OTPAttemptPlan) { s.AttemptID = "AgAAAAAAAAAAAAAAAAAAAA" },
		func(s *OTPAttemptPlan) { s.AttemptFingerprint[0]++ },
		func(s *OTPAttemptPlan) { s.FingerprintKeyVersion++ },
		func(s *OTPAttemptPlan) { s.ChallengeID = "challenge-b" },
		func(s *OTPAttemptPlan) { s.ScopeDigest[0]++ },
		func(s *OTPAttemptPlan) { s.DigestKeyVersion++ },
		func(s *OTPAttemptPlan) { s.ExpectedVersion++ },
		func(s *OTPAttemptPlan) { s.Mode = OTPCheck },
	} {
		changed := p
		copy := *p.OTP
		changed.OTP = &copy
		change(changed.OTP)
		other, err := encodeFeaturePlan(b, fingerprint, changed)
		if err != nil || bytes.Equal(wire, other) {
			t.Fatal("OTP intent field omitted", err)
		}
	}
	// Nil custody must retain the complete historical encoder's existing bytes.
	plain := p
	plain.OTP = nil
	plain.Contributors = plain.Contributors[:4]
	old, err := encodeFeaturePlan(b, fingerprint, plain)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := decodeFeaturePlan(b, fingerprint, old)
	if err != nil || recovered.OTP != nil {
		t.Fatal("legacy history acquired OTP custody", err)
	}
	again, err := encodeFeaturePlan(b, fingerprint, recovered)
	if err != nil || !bytes.Equal(old, again) {
		t.Fatal("ordinary history changed")
	}
}

func TestOTPPlanRejectsInvalidAndUnsupportedAdmission(t *testing.T) {
	for _, change := range []func(*OTPAttemptPlan){
		func(s *OTPAttemptPlan) { s.AttemptID = "" },
		func(s *OTPAttemptPlan) { s.AttemptID = strings.Repeat("a", 23) },
		func(s *OTPAttemptPlan) { s.AttemptID = "AAAAAAAAAAAAAAAAAAAAAA" },
		func(s *OTPAttemptPlan) { s.AttemptFingerprint = [32]byte{} },
		func(s *OTPAttemptPlan) { s.FingerprintKeyVersion = 0 },
		func(s *OTPAttemptPlan) { s.ChallengeID = "" },
		func(s *OTPAttemptPlan) { s.ChallengeID = strings.Repeat("x", 257) },
		func(s *OTPAttemptPlan) { s.ChallengeID = "wrong\nchallenge" },
		func(s *OTPAttemptPlan) { s.ScopeDigest = [32]byte{} },
		func(s *OTPAttemptPlan) { s.DigestKeyVersion = 0 },
		func(s *OTPAttemptPlan) { s.ExpectedVersion = 0 },
		func(s *OTPAttemptPlan) { s.Mode = 0 },
		func(s *OTPAttemptPlan) { s.Mode = 3 },
	} {
		b, p := otpPlanFixture(t)
		change(p.OTP)
		if _, err := FeaturePlanDigest(b, [32]byte{1}, p); err == nil {
			t.Fatal("invalid OTP plan accepted")
		}
	}
	c, command, p := featurePlanFixture(t)
	b, declared := otpPlanFixture(t)
	p.OTP = declared.OTP
	if _, err := c.PrepareCommandPlan(b, command, p); err == nil {
		t.Fatal("declaration enabled incomplete OTP phases")
	}
	if _, err := KernelPlanDigest(b, [32]byte{1}, declared); err == nil {
		t.Fatal("OTP declaration entered kernel plan")
	}
	if _, err := json.Marshal(declared.OTP); err == nil || !strings.Contains(fmt.Sprintf("%#v", declared.OTP), "redacted") {
		t.Fatal("OTP custody diagnostics exposed")
	}
}

func TestOTPPlanCombinedEvidencePreservesCanonicalHistory(t *testing.T) {
	for _, counters := range []bool{false, true} {
		b, p := captchaUsePlanFixture(t)
		_, otp := otpPlanFixture(t)
		p.OTP = cloneOTPPlan(otp.OTP)
		p.Contributors = append(p.Contributors, otpDescriptor())
		if counters {
			p.CommandCounters = &CommandCounterPlan{PolicyVersion: p.CaptchaEvidence.PolicyVersion, Fingerprint: [32]byte{1}}
		}
		wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeFeaturePlan(b, [32]byte{1}, wire)
		if err != nil || decoded.OTP == nil || *decoded.OTP != *p.OTP || decoded.CaptchaEvidence == nil || *decoded.CaptchaEvidence != *p.CaptchaEvidence || (decoded.CommandCounters != nil) != counters {
			t.Fatal("combined evidence omitted from history", err)
		}
		for i := range wire {
			if _, err := decodeFeaturePlan(b, [32]byte{1}, wire[:i]); err == nil {
				t.Fatal("truncated plan admitted", i)
			}
		}
		if _, err := decodeFeaturePlan(b, [32]byte{1}, append(wire, 0)); err == nil {
			t.Fatal("trailing data admitted")
		}
	}
}

func FuzzOTPPlanCanonicalDecode(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xa9})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 65537 {
			return
		}
		b, p := otpPlanFixture(t)
		fp := [32]byte{1}
		// The empty seed exercises the known-valid canonical profile; hostile
		// inputs are decoded verbatim, without normalizing their representation.
		if len(input) == 0 {
			var err error
			input, err = encodeFeaturePlan(b, fp, p)
			if err != nil {
				t.Fatal(err)
			}
		}
		decoded, err := decodeFeaturePlan(b, fp, input)
		if err != nil {
			return
		}
		canonical, err := encodeFeaturePlan(b, fp, decoded)
		if err != nil || !bytes.Equal(input, canonical) {
			t.Fatal("noncanonical history accepted")
		}
	})
}
