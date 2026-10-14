package mfapostgres

import (
	"context"
	"reflect"
	"testing"

	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

func TestOTPEnrollmentSendRejectsUnownedNativeWorkflow(t *testing.T) {
	if service, err := NewOTPEnrollmentSendService(nil, OTPEnrollmentSendConfig{}); err == nil || service != nil {
		t.Fatal("missing enrollment, primary and issuance owners manufactured a sender")
	}
	for _, service := range []*OTPEnrollmentSendService{nil, {}} {
		out, err := service.OtpSend(context.Background(), mfa.OtpSendRequest{})
		if err == nil || out.CommandID != "" || out.ChallengeID != "" || out.DeliveryState != 0 || out.Outcome != 0 {
			t.Fatal("unowned sender returned issuance or delivery")
		}
	}
}

func TestOTPSendIntentDoesNotConsumeBorrowedSynchronizer(t *testing.T) {
	csrf, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	state := &otpEnrollmentSendState{common: &totpURIState{enrollment: &totpEnrollmentState{config: TOTPEnrollmentConfig{intentKey: func() [32]byte { return [32]byte{9} }}}}}
	r := mfa.OtpSendRequest{Enrollment: &mfa.OTPEnrollmentContext{CSRFToken: csrf}}
	a, err := state.intent(r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := state.intent(r)
	if err != nil {
		t.Fatal("intent consumed borrowed synchronizer before retry", err)
	}
	aFields, _ := a.Fields()
	bFields, _ := b.Fields()
	if !reflect.DeepEqual(aFields, bFields) {
		t.Fatal("same original intent changed")
	}
	if _, err := csrf.Reveal(); err != nil {
		t.Fatal("fingerprinting consumed issuer-owned reveal", err)
	}
}
