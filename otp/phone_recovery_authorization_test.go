package otp_test

import (
	"testing"

	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

func TestPhoneRecoveryContinuationConservesExplicitSessionlessScope(t *testing.T) {
	base := boundPreAuthSpec(t)
	base.Binding.Intent.Purpose = session.PreAuthPhonePasswordRecovery
	base.Binding.Intent.Action = "identity.phone.password-reset-request"
	base.Binding.Intent.IdentifierBinding = [32]byte{1}
	base.Binding.Intent.Remember = session.RememberPolicy{}
	scope := digestScopeSpec(t)
	scope.AuthorizationBinding = [32]byte{}
	scope.Purpose, scope.Channel, scope.SubjectID = otp.PurposePasswordReset, otp.ChannelSMS, "user"
	destination, err := otp.NewDestinationInput("+358401234567")
	if err != nil {
		t.Fatal(err)
	}
	scope.Destination = destination
	bind := func(s session.PreAuthTransactionSpec) (otp.FlowAuthorization, otp.ContinuationBindings) {
		t.Helper()
		record, err := session.NewPreAuthTransaction(s)
		if err != nil {
			t.Fatal(err)
		}
		flow, err := otp.NewBoundPreAuthAuthorization(record)
		if err != nil {
			t.Fatal(err)
		}
		continuation, err := otp.NewContinuation(scope, flow, session.RememberPolicy{})
		if err != nil {
			t.Fatal("explicit phone recovery denied", err)
		}
		bound, err := continuation.Bindings()
		if err != nil || bound.RememberPolicy != (session.RememberPolicy{}) {
			t.Fatal("phone recovery invented session policy", err)
		}
		return flow, bound
	}
	flow, original := bind(base)
	changed := base
	changed.Binding.Intent.IdentifierBinding[0]++
	_, other := bind(changed)
	if original.Scope.AuthorizationBinding == other.Scope.AuthorizationBinding {
		t.Fatal("phone recovery target commitment was omitted from OTP authorization")
	}
	for _, change := range []func(*otp.DigestScopeSpec){
		func(s *otp.DigestScopeSpec) { s.Purpose = otp.PurposeEmailVerification },
		func(s *otp.DigestScopeSpec) { s.Purpose = otp.PurposeStepUp },
		func(s *otp.DigestScopeSpec) { s.Channel = otp.ChannelEmail },
		func(s *otp.DigestScopeSpec) { s.SubjectID = "" },
	} {
		foreign := scope
		change(&foreign)
		if _, err := otp.NewContinuation(foreign, flow, session.RememberPolicy{}); err == nil {
			t.Fatal("sessionless recovery was relabelled as another operation/channel")
		}
	}
	if _, err := otp.NewContinuation(scope, flow, rememberPolicy(t)); err == nil {
		t.Fatal("phone recovery accepted a remember choice")
	}
}
