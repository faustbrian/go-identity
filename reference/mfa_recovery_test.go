package reference

import (
	"context"
	"reflect"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestNativeRecoveryInputRejectsMissingOwners(t *testing.T) {
	var s *magicLinkTOTPService
	if input, err := s.readRecoveryInput(context.Background(), nativeRecoveryRequest(t), false); err == nil || input != nil {
		t.Fatal("missing recovery owner admitted input")
	}
	if result, err := s.RecoveryUse(t.Context(), nativeRecoveryRequest(t)); err == nil || result.Session.Token != (session.Token{}) {
		t.Fatal("missing recovery owner issued session")
	}
	if user, child, lifetime, err := s.RecoveryVerificationRateSource(t.Context(), nativeRecoveryRequest(t)); err == nil || user != "" || child != "" || lifetime != 0 {
		t.Fatal("missing recovery owner exposed rate source")
	}
}

func TestNativeRecoveryTransactionRejectsZeroCustody(t *testing.T) {
	p := &magicTOTPPhase{}
	if _, err := p.RecordMFARecoveryAttemptDenial(t.Context(), kernel.MFARecoveryAttemptWork{}); err == nil {
		t.Fatal("zero recovery custody admitted attempt")
	}
}

func TestPasswordRecoverySelectionRequiresExplicitOwnedGraph(t *testing.T) {
	var empty FeatureSet
	if owner, err := empty.PasswordRecovery(); err == nil || owner != nil {
		t.Fatal("empty graph exposed recovery")
	}
	_, _, graph := serverFixture(t)
	if owner, err := graph.PasswordRecovery(); err == nil || owner != nil {
		t.Fatal("unselected graph exposed recovery")
	}
}

func nativeRecoveryRequest(t *testing.T) mfa.RecoveryUseRequest {
	t.Helper()
	r := nativeTOTPRequest(t)
	code, err := auth.NewRecoveryCode("synthetic-recovery-code")
	if err != nil {
		t.Fatal(err)
	}
	r.Caller.Request.Action = "identity.mfa.recovery-use"
	return mfa.RecoveryUseRequest{TenantID: r.TenantID, CommandID: r.CommandID, ContinuationID: mfa.ContinuationID(r.ChallengeID), RecoveryCode: code, Proof: r.Proof, PreAuthID: r.PreAuthID, Cookie: r.Cookie, Caller: r.Caller, Origin: r.Origin, Callback: r.Callback, Network: r.Network, Device: r.Device}
}

func TestNativeRecoveryOriginalIntentIsStableAndDistinct(t *testing.T) {
	r := nativeRecoveryRequest(t)
	state := &magicLinkTOTPState{config: MagicLinkTOTPCompletionConfig{ConfigurationID: "native-recovery-v1", PolicyID: "recovery-login", Coordinator: kernel.CoordinatorConfig{AdmissionPolicy: &kernel.CommandQueryPolicy{PolicyVersion: 9}}}}
	original, err := state.originalRecoveryCommand(r, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := original.Feature()
	again, err := state.originalRecoveryCommand(r, [32]byte{1})
	got, _ := again.Feature()
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("same recovery input changed intent", err)
	}
	if _, ok := original.OneTimeCode(); ok {
		t.Fatal("recovery relabeled OTP")
	}
	if _, ok := original.RecoveryCode(); !ok {
		t.Fatal("original recovery code lost")
	}
	for _, change := range []func(*mfa.RecoveryUseRequest){func(r *mfa.RecoveryUseRequest) { r.Network = "127.0.0.2" }, func(r *mfa.RecoveryUseRequest) { r.Device = "other-device" }, func(r *mfa.RecoveryUseRequest) { r.Callback = "https://app.test/other" }, func(r *mfa.RecoveryUseRequest) {
		r.ContinuationID = "AgICAgICAgICAgICAgICAg"
		r.Caller.Request.Resource.ID = "AgICAgICAgICAgICAgICAg"
	}} {
		changed := r
		change(&changed)
		command, err := state.originalRecoveryCommand(changed, [32]byte{1})
		projection, _ := command.Feature()
		if err != nil || reflect.DeepEqual(projection.Fields, want.Fields) {
			t.Fatal("changed recovery intent shared fields", err)
		}
	}
	if _, err := state.originalRecoveryCommand(r, [32]byte{}); err == nil {
		t.Fatal("unverified envelope identity accepted")
	}
}
