package postgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/phone"
)

func TestPhoneSigninInitiationRequiresOriginalTargetBeforeDiscovery(t *testing.T) {
	policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	number, err := policy.Canonicalize(context.Background(), "+12025550123")
	if err != nil {
		t.Fatal(err)
	}
	_, challenge, _, _, _ := issuanceCustodyFixture(t, false)
	issued, _ := challenge.Bindings()
	continuation, _ := issued.Continuation.Bindings()
	original, _ := continuation.Authorization.PreAuthTransaction()
	flow, _ := original.Bindings()
	key := [32]byte{42}
	flow.Binding.Intent.Action = "identity.phone.signin"
	flow.Binding.Intent.IdentifierBinding, err = phone.OTPSigninIdentifierBinding(number, flow.Binding.Intent.TenantID, key[:])
	if err != nil {
		t.Fatal(err)
	}
	destination, _ := otp.NewDestinationInput("+12025550123")
	request := sendInitiatingRequest{flowKind: otp.FlowAuthorizationPreAuthTransaction, purpose: otp.PurposeSignin, channel: otp.ChannelSMS, destination: destination, target: "identity.phone.signin"}
	profile := &phoneSigninProfile{policy: policy, identifierKey: key}
	if err := profile.requireOriginalTarget(context.Background(), identity.TenantID(flow.Binding.Intent.TenantID), request, flow.Binding); err != nil {
		t.Fatal("original canonical phone OTP target rejected", err)
	}
	for _, change := range []string{"number", "tenant", "purpose", "channel", "target", "user", "action", "binding", "session"} {
		t.Run(change, func(t *testing.T) {
			r, f, tenant := request, flow.Binding, identity.TenantID(flow.Binding.Intent.TenantID)
			switch change {
			case "number":
				r.destination, _ = otp.NewDestinationInput("+12025550124")
			case "tenant":
				tenant = "foreign"
			case "purpose":
				r.purpose = otp.PurposePhoneVerification
			case "channel":
				r.channel = otp.ChannelEmail
			case "target":
				r.target = "identity.phone.password-signin"
			case "user":
				r.userID = "substituted"
			case "action":
				f.Intent.Action = "identity.otp.signin"
			case "binding":
				f.Intent.IdentifierBinding = [32]byte{}
			case "session":
				r.flowKind = otp.FlowAuthorizationAuthenticatedSession
			}
			if err := profile.requireOriginalTarget(context.Background(), tenant, r, f); err == nil {
				t.Fatal("substituted original phone target admitted")
			}
		})
	}
}
