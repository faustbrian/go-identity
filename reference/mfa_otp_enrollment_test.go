package reference

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/risk"
)

func TestMFAOTPEnrollmentRequiresSelectedGraph(t *testing.T) {
	var absent FeatureSet
	if owner, err := absent.MFAOTPEnrollment(); err == nil || owner != nil {
		t.Fatal("absent graph exposed OTP enrollment")
	}
	if owner, err := absent.MFAOTPEnrollmentConfirmation(); err == nil || owner != nil {
		t.Fatal("absent graph exposed OTP enrollment sending/confirmation")
	}
	selected := FeatureSet{state: &storeState{features: &featureState{composed: true}}}
	if owner, err := selected.MFAOTPEnrollment(); err == nil || owner != nil {
		t.Fatal("unselected graph exposed OTP enrollment")
	}
	if owner, err := selected.MFAOTPEnrollmentConfirmation(); err == nil || owner != nil {
		t.Fatal("unselected graph exposed OTP enrollment sending/confirmation")
	}
}

func TestMFAOTPEnrollmentRetainsGraphLifetimeAndTenant(t *testing.T) {
	_, _, graph := serverFixture(t)
	graph.state.features.mfaOTPEnrollment = &mfaOTPEnrollmentState{}
	enable, err := graph.MFAOTPEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	confirmation, err := graph.MFAOTPEnrollmentConfirmation()
	if err != nil {
		t.Fatal(err)
	}
	deny := func(tenant identity.TenantID) {
		t.Helper()
		if _, err := enable.Enable(t.Context(), mfa.EnableRequest{TenantID: tenant}); err == nil {
			t.Fatal("unadmitted enrollment")
		}
		query := identity.RecoveryQuery{TenantID: tenant}
		caller := nativeTOTPRequest(t).Caller
		if _, err := enable.RecoverEnable(t.Context(), query, caller); err == nil {
			t.Fatal("unadmitted enrollment recovery")
		}
		if _, err := confirmation.OtpSend(t.Context(), mfa.OtpSendRequest{TenantID: tenant}); err == nil {
			t.Fatal("unadmitted enrollment send")
		}
		if _, err := confirmation.OtpVerify(t.Context(), mfa.OtpVerifyRequest{TenantID: tenant}); err == nil {
			t.Fatal("unadmitted confirmation")
		}
		if _, err := confirmation.RecoverOtpSend(t.Context(), query, caller); err == nil {
			t.Fatal("unadmitted send recovery")
		}
		if _, err := confirmation.RecoverOtpVerify(t.Context(), query, caller); err == nil {
			t.Fatal("unadmitted confirmation recovery")
		}
		if graph.state.active != 0 {
			t.Fatal("denied enrollment leaked graph admission")
		}
	}
	deny("tenant")
	graph.state.features.ready = true
	deny("foreign")
	graph.state.closed = true
	deny("tenant")
	if owner, err := graph.MFAOTPEnrollment(); err == nil || owner != nil {
		t.Fatal("closed graph exported enrollment")
	}
	if owner, err := graph.MFAOTPEnrollmentConfirmation(); err == nil || owner != nil {
		t.Fatal("closed graph exported confirmation")
	}
}

func TestMFAOTPEnrollmentDoesNotInventMissingOwnersOrExposeKeys(t *testing.T) {
	if owner, err := composeMFAOTPEnrollment(StoreConfiguration{}, ReferenceDependencies{}, nil, risk.Evaluator{}, nil); err != nil || owner != nil {
		t.Fatal("unselected graph invented OTP enrollment")
	}
	c := StoreConfiguration{MFAOTPEnrollment: &MFAOTPEnrollmentConfiguration{SessionKeys: map[uint32][]byte{1: []byte("private-fixture-material")}}}
	if owner, err := composeMFAOTPEnrollment(c, ReferenceDependencies{}, nil, risk.Evaluator{}, nil); err == nil || owner != nil {
		t.Fatal("absent native authority accepted")
	}
	if err := (&storeState{}).composeFeatureStores(c, ReferenceDependencies{}); err == nil {
		t.Fatal("selected workflow silently disappeared")
	}
	if _, err := json.Marshal(c.MFAOTPEnrollment); err == nil {
		t.Fatal("startup keys serialized")
	}
	if got := fmt.Sprintf("%#v", *c.MFAOTPEnrollment); !strings.Contains(got, "redacted") || strings.Contains(got, "private-fixture-material") {
		t.Fatal("startup keys escaped diagnostics")
	}
}

func TestMFAOTPEnrollmentHistoryPreservesLaterLoginPrefixes(t *testing.T) {
	c := featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "session_store", signinSchema: "session_store", passwordSigninSchema: "session_store", global: "deployment"}
	s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: c, mfaOTPEnrollment: &mfaOTPEnrollmentState{}}}}
	before, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, h := range before {
		if h.namespace == "identity_mfa_otp" {
			found = true
			if len(h.history) != 3 || h.owners[16] != "" {
				t.Fatal("standalone enrollment selected login history")
			}
		}
	}
	if !found {
		t.Fatal("standalone enrollment omitted owned factor history")
	}
	s.state.features.migrations.passwordMFA, s.state.features.migrations.passwordOTP = true, true
	after, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, old := range before {
		present := false
		for _, current := range after {
			if old.namespace != current.namespace {
				continue
			}
			present = true
			for i, step := range old.history {
				if i >= len(current.history) || step != current.history[i] || old.owners[step.Version()] != current.owners[step.Version()] {
					t.Fatal("later login rewrote installed enrollment history", old.namespace)
				}
			}
		}
		if !present {
			t.Fatal("later login removed installed enrollment history", old.namespace)
		}
	}
}
