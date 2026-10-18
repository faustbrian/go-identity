package otp

import (
	"errors"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
)

func TestPhoneVerificationPurposeCannotSubstituteEmailOrSignin(t *testing.T) {
	// A phone workflow needs its own retained purpose; neither the existing
	// email verification profile nor a signin challenge proves enrollment.
	const phoneVerification Purpose = "phone-verification"
	spec := profileSpec()
	spec.Purpose = phoneVerification
	profile, err := NewCodeProfile(spec)
	if err != nil {
		t.Fatal("phone verification has no distinct code profile", err)
	}
	if got, err := profile.Bindings(); err != nil || got.Purpose != phoneVerification {
		t.Fatal("phone purpose changed after construction", err)
	}
	destination, err := NewDestinationInput("+358401234567")
	if err != nil {
		t.Fatal(err)
	}
	input := DigestScopeSpec{TenantID: "tenant", SubjectID: "user", Purpose: phoneVerification, Channel: ChannelSMS, Destination: destination, ChallengeID: "challenge", TargetID: "phone", PolicyVersion: 1, Generation: 1, AuthorizationBinding: [32]byte{1}}
	scope, err := NewDigestScope(input)
	if err != nil {
		t.Fatal("phone SMS scope denied", err)
	}
	verifier, err := NewVerifier(1, map[uint32][32]byte{1: {7}})
	if err != nil {
		t.Fatal(err)
	}
	code, err := auth.NewOneTimeCode("123456")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := verifier.Digest(scope, code)
	if err != nil {
		t.Fatal(err)
	}
	for _, purpose := range []Purpose{PurposeEmailVerification, PurposeSignin, PurposePasswordReset, PurposeMFA} {
		foreign := input
		foreign.Purpose = purpose
		other, err := NewDigestScope(foreign)
		if err != nil {
			t.Fatal(err)
		}
		if match, err := verifier.Compare(other, digest.Storage(), code); err != nil || match {
			t.Fatal("phone verification digest crossed workflow purpose", err)
		}
	}
	input.Channel = ChannelEmail
	if _, err := NewDigestScope(input); !errors.Is(err, ErrInvalidDigest) {
		t.Fatal("phone ownership proof accepted a non-SMS scope")
	}
}
