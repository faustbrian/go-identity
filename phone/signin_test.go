package phone_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/phone"
)

func TestPhoneSigninSendOwnsCanonicalNumberAndOriginalPublicFlow(t *testing.T) {
	enrollment := enrollmentRequest(t)
	flow, err := otp.NewPreAuthSendFlow("AAAAAAAAAAAAAAAAAAAAAQ", enrollment.Session)
	if err != nil {
		t.Fatal(err)
	}
	caller := enrollment.Caller.Clone()
	caller.Request.Action = "identity.phone.signin"
	caller.Request.Subject.Kind, caller.Request.Subject.ID = authorization.SubjectServiceAccount, "phone-login"
	input := phone.SigninSendRequestSpec{TenantID: enrollment.TenantID, Number: enrollment.Number, Caller: caller, Flow: flow, Network: enrollment.Network, Device: enrollment.Device, IdempotencyKey: enrollment.IdempotencyKey}
	request, err := phone.NewSigninSendRequest(input)
	if err != nil {
		t.Fatal("canonical public phone initiation rejected", err)
	}
	input.Caller.Request.Action = "identity.phone.password-signin"
	retained, err := request.Bindings()
	retainedNumber, numberErr := retained.Number.Record()
	originalNumber, _ := enrollment.Number.Record()
	if err != nil || numberErr != nil || retained.Caller.Request.Action != "identity.phone.signin" || retainedNumber != originalNumber || retained.Flow != flow {
		t.Fatal("phone request did not freeze the original canonical flow")
	}
	retained.Caller.Request.Action = "identity.otp.signin"
	if got, err := request.Bindings(); err != nil || got.Caller.Request.Action != "identity.phone.signin" {
		t.Fatal("projection mutated original phone action")
	}
	if _, err := phone.NewSigninSendRequest(input); err == nil {
		t.Fatal("password action entered phone OTP initiation")
	}
	input.Caller.Request.Action = "identity.phone.signin"
	input.Number = phone.Number{}
	if _, err := phone.NewSigninSendRequest(input); err == nil {
		t.Fatal("noncanonical/missing phone entered initiation")
	}
	input.Number = enrollment.Number
	input.Flow, err = otp.NewSessionSendFlow("original-session", enrollment.Session)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := phone.NewSigninSendRequest(input); err == nil {
		t.Fatal("authenticated-session flow entered public phone signin")
	}
	if _, err := (phone.SigninSendRequest{}).Bindings(); err == nil {
		t.Fatal("zero phone request projected usable custody")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%q", "%x"} {
		wire := fmt.Sprintf(verb, struct{ private any }{request})
		if strings.Contains(wire, "+12025550123") || strings.Contains(wire, enrollment.Session.Token()) {
			t.Fatal("phone OTP request disclosed nested custody")
		}
	}
	if _, err := json.Marshal(request); err == nil {
		t.Fatal("phone OTP request implicitly serialized")
	}
}
