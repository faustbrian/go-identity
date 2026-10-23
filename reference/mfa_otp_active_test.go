package reference

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestMFAOTPManagementAppendsMissingSharedDisposition(t *testing.T) {
	c := featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "session_store", signinSchema: "session_store", passwordSigninSchema: "session_store", global: "deployment"}
	s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: c, mfaOTPEnrollment: &mfaOTPEnrollmentState{active: &mfapg.OTPActiveStepUpService{}, manage: &mfapg.FactorUpdateService{}}}}}
	base, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for i, h := range base {
		if h.namespace == "identity_mfa_recovery_dispositions" {
			if len(h.history) != 2 {
				t.Fatal("OTP-only composition omitted session effect extension")
			}
			// A prior regeneration-only deployment has the exact v1 history but
			// has not selected the v2 update disposition. Preserve that prefix.
			base[i].history = base[i].history[:1]
			base[i].owners = map[migrations.Version]ModuleID{1: "identity/session/postgres"}
		}
	}
	// otpActiveMigrationCatalog expects the original OTP prefix before v17.
	for i, h := range base {
		if h.namespace == "identity_mfa_otp" {
			base[i].history = h.history[:len(h.history)-2]
		}
	}
	result, err := s.otpActiveMigrationCatalog(t.Context(), base)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range result {
		if h.namespace == "identity_mfa_recovery_dispositions" {
			found = true
			if len(h.history) != 2 || h.owners[2] != "identity/session/postgres" {
				t.Fatal("existing v1 disposition prevented required OTP rename extension")
			}
		}
	}
	if !found {
		t.Fatal("missing session disposition history")
	}
}

func TestMFAOTPActiveSelectionAndRetainedLifetime(t *testing.T) {
	var absent FeatureSet
	if owner, err := absent.MFAOTPActiveStepUp(); err == nil || owner != nil {
		t.Fatal("absent graph exposed OTP action proof")
	}
	if owner, err := absent.MFAOTPFactorManagement(); err == nil || owner != nil {
		t.Fatal("absent graph exposed OTP management")
	}
	_, _, graph := serverFixture(t)
	graph.state.features.mfaOTPEnrollment = &mfaOTPEnrollmentState{}
	if owner, err := graph.MFAOTPActiveStepUp(); err == nil || owner != nil {
		t.Fatal("unselected graph exposed OTP action proof")
	}
	if owner, err := graph.MFAOTPFactorManagement(); err == nil || owner != nil {
		t.Fatal("unselected graph exposed OTP management")
	}
	graph.state.features.mfaOTPEnrollment.active = &mfapg.OTPActiveStepUpService{}
	graph.state.features.mfaOTPEnrollment.manage = &mfapg.FactorUpdateService{}
	active, err := graph.MFAOTPActiveStepUp()
	if err != nil {
		t.Fatal(err)
	}
	management, err := graph.MFAOTPFactorManagement()
	if err != nil {
		t.Fatal(err)
	}
	deny := func(ctx context.Context, tenant identity.TenantID) {
		t.Helper()
		if out, err := active.OtpSend(ctx, mfa.OtpSendRequest{TenantID: tenant}); err == nil || out.CommandID != "" || out.ChallengeID != "" {
			t.Fatal("unadmitted OTP send returned custody")
		}
		if out, err := active.OtpVerify(ctx, mfa.OtpVerifyRequest{TenantID: tenant}); err == nil || out.StepUpProof.Bindings().Proof.ID != "" {
			t.Fatal("unadmitted OTP verify returned proof")
		}
		caller := nativeTOTPRequest(t).Caller
		q := identity.RecoveryQuery{TenantID: tenant}
		if _, err := active.RecoverOtpSend(ctx, q, caller); err == nil {
			t.Fatal("unadmitted OTP send recovery")
		}
		if _, err := active.RecoverOtpVerify(ctx, q, caller); err == nil {
			t.Fatal("unadmitted OTP proof recovery")
		}
		if out, err := management.FactorUpdate(ctx, mfa.FactorUpdateRequest{TenantID: tenant}); err == nil || out.Factor.ID != "" {
			t.Fatal("unadmitted OTP rename returned metadata")
		}
		if _, err := management.RecoverFactorUpdate(ctx, q, caller); err == nil {
			t.Fatal("unadmitted OTP rename recovery")
		}
		if graph.state.active != 0 {
			t.Fatal("denied OTP request leaked graph admission")
		}
	}
	deny(t.Context(), "tenant")
	graph.state.features.ready = true
	deny(t.Context(), "foreign")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	deny(ctx, "tenant")
	graph.state.closed = true
	deny(t.Context(), "tenant")
	if owner, err := graph.MFAOTPActiveStepUp(); err == nil || owner != nil {
		t.Fatal("closed graph exposed OTP proof owner")
	}
	if owner, err := graph.MFAOTPFactorManagement(); err == nil || owner != nil {
		t.Fatal("closed graph exposed OTP mutation owner")
	}
}
