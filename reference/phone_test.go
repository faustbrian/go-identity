package reference_test

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/reference"
)

func TestPhoneHandleRequiresSelectedLiveGraph(t *testing.T) {
	var features reference.FeatureSet
	if owner, err := features.Phone(); owner != nil || err == nil {
		t.Fatal("zero graph exposed phone authority")
	}
	for _, owner := range []*reference.PhoneService{nil, {}} {
		if result, err := owner.SendVerification(context.Background(), phone.EnrollmentRequest{}); err == nil {
			t.Fatal("zero graph executed phone enrollment")
		} else if _, e := result.Bindings(); e == nil {
			t.Fatal("denied graph retained enrollment result")
		}
		if result, err := owner.Verify(context.Background(), phone.VerificationRequest{}); err == nil {
			t.Fatal("zero graph executed phone verification")
		} else if _, e := result.Bindings(); e == nil {
			t.Fatal("denied graph retained verification result")
		}
		if result, err := owner.RecoverVerification(context.Background(), phone.VerificationRecoveryRequest{}); err == nil {
			t.Fatal("zero graph disclosed phone history")
		} else if _, e := result.Bindings(); e == nil {
			t.Fatal("denied graph retained phone history")
		}
	}
}
