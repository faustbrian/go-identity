package postgres

import (
	"bytes"
	"testing"

	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

func phoneRecoveryPreAuthSeed(t testing.TB) session.PreAuthTransaction {
	t.Helper()
	seed, err := issuanceRecordSeed(t).Bindings()
	if err != nil {
		t.Fatal(err)
	}
	base, _ := seed.Continuation.Bindings()
	old, _ := base.Authorization.PreAuthTransaction()
	spec, _ := old.Bindings()
	spec.Binding.Intent.Purpose = session.PreAuthPhonePasswordRecovery
	spec.Binding.Intent.Action = "identity.phone.password-reset-request"
	spec.Binding.Intent.Remember = session.RememberPolicy{}
	spec.Binding.Intent.IdentifierBinding = [32]byte{17}
	original, err := session.NewPreAuthTransaction(spec)
	if err != nil {
		t.Fatal(err)
	}
	return original
}

func TestPhoneRecoveryPreAuthCustodyPreservesPurposeWithoutRemember(t *testing.T) {
	seed, err := issuanceRecordSeed(t).Bindings()
	if err != nil {
		t.Fatal(err)
	}
	base, _ := seed.Continuation.Bindings()
	original := phoneRecoveryPreAuthSeed(t)
	spec, _ := original.Bindings()
	wire := appendPreAuthRecord(nil, original)
	reader := recordReader{data: wire, ok: true}
	got, err := readPreAuthRecord(&reader)
	if err != nil {
		t.Fatal("OTP custody cannot restore original no-session recovery", err)
	}
	projection, err := got.Bindings()
	if err != nil || projection != spec || len(reader.data) != 0 || !bytes.Equal(wire, appendPreAuthRecord(nil, got)) {
		t.Fatal("sessionless original scope changed", err)
	}
	flow, _ := otp.NewBoundPreAuthAuthorization(original)
	scope := base.Scope
	scope.AuthorizationBinding = [32]byte{}
	scope.Purpose, scope.Channel, scope.SubjectID = otp.PurposePasswordReset, otp.ChannelSMS, "user"
	scope.Destination, _ = otp.NewDestinationInput("+358401234567")
	continuation, err := otp.NewContinuation(scope, flow, session.RememberPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	profile, checks, _ := seed.Policy.Bindings()
	profile.Purpose = otp.PurposePasswordReset
	codeProfile, err := otp.NewCodeProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := otp.NewAttemptPolicy(codeProfile, checks)
	if err != nil {
		t.Fatal(err)
	}
	seed.Continuation, seed.Policy = continuation, policy
	challenge, err := otp.NewChallenge(seed)
	if err != nil {
		t.Fatal(err)
	}
	encoded := encodeIssuanceRecord(challenge)
	decoded, err := decodeIssuanceRecord(encoded)
	if err != nil {
		t.Fatal("recovery challenge lost original custody", err)
	}
	decodedSpec, _ := decoded.Bindings()
	decodedFlow, _ := decodedSpec.Continuation.Bindings()
	retained, present := decodedFlow.Authorization.PreAuthTransaction()
	retainedSpec, _ := retained.Bindings()
	if !present || retainedSpec != spec || decodedFlow.RememberPolicy != (session.RememberPolicy{}) || !bytes.Equal(encoded, encodeIssuanceRecord(decoded)) {
		t.Fatal("challenge recovery invented or discarded sessionless intent")
	}
}

func TestPhoneRecoveryPreAuthCustodyRejectsTruncationAndPurposeDowngrade(t *testing.T) {
	wire := appendPreAuthRecord(nil, phoneRecoveryPreAuthSeed(t))
	for n := range len(wire) {
		reader := recordReader{data: wire[:n], ok: true}
		if _, err := readPreAuthRecord(&reader); err == nil {
			t.Fatalf("truncated recovery custody admitted at %d", n)
		}
	}
	for _, purpose := range []byte{byte(session.PreAuthSessionIssuance), 2, 255} {
		changed := bytes.Clone(wire)
		changed[len(phoneRecoveryPreAuthRecordPrefix)] = purpose
		reader := recordReader{data: changed, ok: true}
		if _, err := readPreAuthRecord(&reader); err == nil {
			t.Fatal("recovery marker allowed a different purpose")
		}
	}
	zeroTarget := bytes.Clone(wire)
	clear(zeroTarget[len(phoneRecoveryPreAuthRecordPrefix)+1 : len(phoneRecoveryPreAuthRecordPrefix)+33])
	downgraded := append([]byte(identifierBoundPreAuthRecordPrefix), wire[len(phoneRecoveryPreAuthRecordPrefix)+1:]...)
	unknown := bytes.Clone(wire)
	unknown[4] = '4'
	for _, changed := range [][]byte{zeroTarget, downgraded, unknown, wire[len(phoneRecoveryPreAuthRecordPrefix)+33:]} {
		reader := recordReader{data: changed, ok: true}
		if _, err := readPreAuthRecord(&reader); err == nil {
			t.Fatal("recovery custody lost its explicit sessionless target profile")
		}
	}
}
