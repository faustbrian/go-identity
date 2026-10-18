package passwordpostgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/phone"
)

func TestPhoneVerificationRequiresActualNativeOwners(t *testing.T) {
	policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	if service, err := NewPhoneVerificationService(nil, policy, PhoneVerificationConfig{}, nil); service != nil || err == nil {
		t.Fatal("missing native owners exposed phone verification")
	}
	for _, service := range []*PhoneVerificationService{nil, {}} {
		if result, err := service.SendVerification(context.Background(), phone.EnrollmentRequest{}); err == nil {
			t.Fatal("zero service supplied enrollment")
		} else if _, e := result.Bindings(); e == nil {
			t.Fatal("zero service supplied enrollment result custody")
		}
		if result, err := service.Verify(context.Background(), phone.VerificationRequest{}); err == nil {
			t.Fatal("zero service supplied verification")
		} else if _, e := result.Bindings(); e == nil {
			t.Fatal("zero service supplied verification result custody")
		}
		if result, err := service.RecoverVerification(context.Background(), phone.VerificationRecoveryRequest{}); err == nil {
			t.Fatal("zero service supplied history")
		} else if _, e := result.Bindings(); e == nil {
			t.Fatal("zero service supplied recovery result custody")
		}
	}
}

func TestPhoneEnrollmentIdentifierRetainsOriginalServerCommand(t *testing.T) {
	first, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	a, err := phoneEnrollmentIdentifier(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := phoneEnrollmentIdentifier(first)
	if err != nil || b != a {
		t.Fatal("retry replaced original candidate")
	}
	c, err := phoneEnrollmentIdentifier(second)
	if err != nil || c == a {
		t.Fatal("different sends aliased phone candidate")
	}
	if _, err := identity.ParseIdentifierID(string(a)); err != nil {
		t.Fatal("candidate is not a kernel identifier")
	}
	if _, err := phoneEnrollmentIdentifier(""); err == nil {
		t.Fatal("caller-selected missing command supplied candidate")
	}
}
