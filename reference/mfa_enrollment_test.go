package reference

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/risk"
)

func TestMFAEnrollmentSelectionDeniesAbsentNativeAuthority(t *testing.T) {
	if owner, err := composeMFAEnrollment(StoreConfiguration{}, ReferenceDependencies{}, nil, risk.Evaluator{}); err != nil || owner != nil {
		t.Fatal("unselected enrollment acquired authority")
	}
	c := StoreConfiguration{MFAEnrollment: &MFAEnrollmentConfiguration{}}
	if owner, err := composeMFAEnrollment(c, ReferenceDependencies{}, nil, risk.Evaluator{}); err == nil || owner != nil {
		t.Fatal("selected enrollment accepted absent primary/storage authority")
	}
	if err := (&storeState{}).composeFeatureStores(c, ReferenceDependencies{}); err == nil {
		t.Fatal("enrollment selection vanished without its required graph")
	}
}

func TestMFAEnrollmentMigrationsPreservePreviouslySelectedHistories(t *testing.T) {
	c := featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "session_store", signinSchema: "session_store", global: "deployment"}
	s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: c}}}
	before, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	s.state.features.mfaEnrollment = &mfaEnrollmentState{}
	s.state.features.migrations.mfaEnrollment = true
	after, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range before[0].history {
		if m != after[0].history[i] {
			t.Fatal("enrollment rewrote already-selected shared history")
		}
	}
	want := map[string]bool{"identity_mfa": false, "identity_risk_lockouts": false, "identity_password_change_kernel": false}
	for _, h := range after {
		if _, ok := want[h.namespace]; ok {
			want[h.namespace] = true
		}
		if h.namespace == "identity_mfa" && len(h.history) != 6 {
			t.Fatal("incomplete enrollment migrations")
		}
	}
	for _, present := range want {
		if !present {
			t.Fatal("native enrollment prerequisite absent")
		}
	}
}

func TestMFAEnrollmentHandlesRetainGraphLifetimeAndTenantAdmission(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &storeState{lifetime: lifetime, cancel: cancel, features: &featureState{composed: true, timeout: time.Second}}
	f := FeatureSet{state: s}
	if owner, err := f.MFAEnrollment(); err == nil || owner != nil {
		t.Fatal("unselected graph exposed enrollment")
	}
	if owner, err := f.MFAProvisioningURI(); err == nil || owner != nil {
		t.Fatal("unselected graph exposed provisioning")
	}
	if owner, err := f.MFAEnrollmentConfirmation(); err == nil || owner != nil {
		t.Fatal("unselected graph exposed confirmation")
	}
	s.features.mfaEnrollment = &mfaEnrollmentState{enable: &mfapg.TOTPEnrollmentService{}, uri: &mfapg.TOTPURIService{}, confirm: &mfapg.TOTPConfirmationService{}}
	enable, err := f.MFAEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	uri, err := f.MFAProvisioningURI()
	if err != nil {
		t.Fatal(err)
	}
	confirm, err := f.MFAEnrollmentConfirmation()
	if err != nil {
		t.Fatal(err)
	}
	deny := func() {
		t.Helper()
		if _, err := enable.Enable(t.Context(), mfa.EnableRequest{TenantID: "foreign"}); err == nil {
			t.Fatal("inactive/foreign graph admitted enrollment")
		}
		if _, err := uri.TotpUri(t.Context(), mfa.TotpUriRequest{TenantID: "foreign"}); err == nil {
			t.Fatal("inactive/foreign graph admitted disclosure")
		}
		if _, err := confirm.TotpVerify(t.Context(), mfa.TotpVerifyRequest{TenantID: "foreign"}); err == nil {
			t.Fatal("inactive/foreign graph admitted activation")
		}
		q := identity.RecoveryQuery{TenantID: "foreign"}
		if _, err := enable.RecoverEnable(t.Context(), q, authorization.DecisionContext{}); err == nil {
			t.Fatal("inactive/foreign graph admitted enrollment recovery")
		}
		if _, err := uri.RecoverTotpUri(t.Context(), q, authorization.DecisionContext{}); err == nil {
			t.Fatal("inactive/foreign graph admitted URI recovery")
		}
		if _, err := confirm.RecoverTotpVerify(t.Context(), q, authorization.DecisionContext{}); err == nil {
			t.Fatal("inactive/foreign graph admitted activation recovery")
		}
		if s.active != 0 {
			t.Fatal("enrollment operation leaked graph admission")
		}
	}
	deny()
	s.features.ready = true
	deny()
	s.closed = true
	cancel()
	deny()
	if owner, err := f.MFAEnrollment(); err == nil || owner != nil {
		t.Fatal("closed graph exposed enrollment")
	}
}
