package mfapostgres

import (
	"testing"

	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestOTPActiveSendEnvelopeBindsOriginalCoordinatorProvenance(t *testing.T) {
	p := &otpActivePhase{state: &otpActiveState{shared: &totpEnrollmentState{config: TOTPEnrollmentConfig{RequestKeys: kernel.RequestKeyConfig{Namespace: "active-test", Policy: kernel.CommandQueryPolicy{PolicyVersion: 9}}}}, identity: [32]byte{1}}}
	k := kernel.RequestKeyPreparationBinding{Namespace: "active-test", Scope: kernel.RequestKeyScope{Method: "POST", RouteID: otpActiveOperation(false).OperationID}, Admission: kernel.RequestKeyAdmission{FingerprintKeyVersion: 1}, Feature: kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: otpActiveOperation(false)}, PolicyVersion: 9, IntentDigest: [32]byte{2}}
	a, err := p.sendInputAAD(k)
	if err != nil {
		t.Fatal("actual original provenance cannot bind native encrypted preparation", err)
	}
	k.IntentDigest[0]++
	b, err := p.sendInputAAD(k)
	if err != nil || string(a.AdditionalData()) == string(b.AdditionalData()) {
		t.Fatal("changed original intent retained the same envelope binding", err)
	}
}
