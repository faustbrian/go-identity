package reference

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/risk"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestPhonePasswordResetSelectionDeniesMissingAndClosedOwners(t *testing.T) {
	for _, f := range []FeatureSet{{}, {state: &storeState{features: &featureState{composed: true}}}, {state: &storeState{closed: true, features: &featureState{composed: true}}}} {
		if owner, err := f.PhonePasswordReset(); owner != nil || err == nil {
			t.Fatal("absent/closed graph exposed phone reset")
		}
		if owner, err := f.PhonePasswordResetPreAuth(); owner != nil || err == nil {
			t.Fatal("absent/closed graph exposed a recovery browser")
		}
	}
	if _, _, done, err := (*PhonePasswordResetService)(nil).enter(context.Background(), "tenant"); err == nil || done != nil {
		t.Fatal("zero wrapper entered native recovery")
	}
}

func TestPhonePasswordResetMigrationRetainsOwningHistories(t *testing.T) {
	c := featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "session_store", global: "deployment", resetSchema: "session_store"}
	s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: c}}}
	before, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	s.state.features.phonePasswordReset = &phonePasswordResetState{}
	after, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, old := range before {
		found := false
		for _, next := range after {
			if next.namespace != old.namespace {
				continue
			}
			found = true
			if len(next.history) < len(old.history) {
				t.Fatal("phone reset discarded an existing history")
			}
			for i, step := range old.history {
				if next.history[i] != step {
					t.Fatal("phone reset rewrote installed predecessor", old.namespace)
				}
			}
		}
		if !found {
			t.Fatal("existing owner namespace disappeared")
		}
	}
	want := map[string]ModuleID{"identity_phone_reset_kernel": "identity/postgres", "identity_phone_reset_password": "identity/password/postgres", "identity_phone_reset_session": "identity/session/postgres"}
	for _, h := range after {
		if _, err := migrations.PlanUp(h.history, nil); err != nil {
			t.Fatal("uninstallable owner history", h.namespace, err)
		}
		if owner, ok := want[h.namespace]; ok {
			if len(h.history) != 1 || len(h.guards) != 1 || h.owners[h.history[0].Version()] != owner || h.guards[0].constraintValue != "identity.phone.password-reset-complete" {
				t.Fatal("missing exact native owner/readiness mapping", h.namespace)
			}
			delete(want, h.namespace)
		}
	}
	if len(want) != 0 {
		t.Fatal("phone reset did not select required mutation/session suffixes")
	}
}

func TestPhonePasswordResetCompositionDoesNotInventOwners(t *testing.T) {
	if owner, err := composePhonePasswordReset(StoreConfiguration{}, ReferenceDependencies{}, risk.Evaluator{}, nil, nil); owner != nil || err != nil {
		t.Fatal("unselected profile changed composition")
	}
	c := StoreConfiguration{PhonePasswordReset: &PhonePasswordResetConfiguration{}}
	if owner, err := composePhonePasswordReset(c, ReferenceDependencies{}, risk.Evaluator{}, nil, nil); owner != nil || err == nil {
		t.Fatal("selected reset invented missing native owners")
	}
}

func TestPhonePasswordResetHTTPRequiresSelectedRecoveryBrowser(t *testing.T) {
	if owner, err := composePhonePasswordResetHTTP(StoreConfiguration{}, nil, nil, nil); owner != nil || err != nil {
		t.Fatal("unselected HTTP profile changed routing")
	}
	c := StoreConfiguration{HTTPPhonePasswordReset: &HTTPPhonePasswordResetConfiguration{}}
	if owner, err := composePhonePasswordResetHTTP(c, nil, nil, nil); owner != nil || err == nil {
		t.Fatal("HTTP reset invented native/browser/rate authority")
	}
}
