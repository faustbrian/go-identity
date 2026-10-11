package reference

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/email"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/risk"
)

func TestPasswordSignupGraphSelection(t *testing.T) {
	type registration interface {
		PasswordSignup() (password.SignupService, error)
		RegistrationVerification() (email.RegistrationVerificationService, error)
		SignupPreAuth() (PreAuthService, error)
	}
	selected, ok := any(FeatureSet{}).(registration)
	if !ok {
		t.Fatal("reference graph has no public signup/confirmation ports")
	}
	if service, err := selected.PasswordSignup(); err == nil || service != nil {
		t.Fatal("empty graph exposed registration")
	}
	if service, err := selected.RegistrationVerification(); err == nil || service != nil {
		t.Fatal("empty graph exposed confirmation")
	}
	if service, err := selected.SignupPreAuth(); err == nil || service != nil {
		t.Fatal("empty graph exposed signup initiation")
	}
}

func TestPasswordSignupGraphLifetime(t *testing.T) {
	lifetime, cancel := context.WithCancel(t.Context())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	state := &storeState{lifetime: lifetime, cancel: cancel, drained: drained, features: &featureState{composed: true, timeout: time.Second, passwordSignup: &passwordpg.SignupService{}}}
	f := FeatureSet{state: state}
	owner, err := f.PasswordSignup()
	if err != nil {
		t.Fatal(err)
	}
	confirmation, err := f.RegistrationVerification()
	if err != nil {
		t.Fatal(err)
	}
	for _, ready := range []bool{false, true} {
		state.features.ready = ready
		if _, err := owner.Signup(t.Context(), password.SignupRequest{}); err == nil {
			t.Fatal("inactive/foreign graph admitted signup")
		}
		if _, err := owner.RecoverSignup(t.Context(), password.SignupRecoveryRequest{}); err == nil {
			t.Fatal("malformed recovery admitted")
		}
		if _, err := confirmation.VerificationConfirm(t.Context(), email.VerificationConfirmRequest{}); err == nil {
			t.Fatal("inactive/foreign graph admitted confirmation")
		}
		if _, err := confirmation.VerificationRecover(t.Context(), email.VerificationRecoveryRequest{}); err == nil {
			t.Fatal("malformed confirmation recovery admitted")
		}
		if state.active != 0 {
			t.Fatal("registration leaked graph admission")
		}
	}
	state.closed = true
	cancel()
	if _, err := owner.(passwordhttp.SignupService).SignupRateSource(t.Context(), password.SignupAddressInput("")); err == nil {
		t.Fatal("closed graph normalized input")
	}
	if _, err := owner.Signup(t.Context(), password.SignupRequest{}); err == nil {
		t.Fatal("closed retained handle admitted signup")
	}
	if _, err := confirmation.VerificationConfirm(t.Context(), email.VerificationConfirmRequest{}); err == nil {
		t.Fatal("closed retained handle admitted confirmation")
	}
	if owner, err := f.PasswordSignup(); err == nil || owner != nil {
		t.Fatal("closed graph exported signup")
	}
	if owner, err := f.RegistrationVerification(); err == nil || owner != nil {
		t.Fatal("closed graph exported confirmation")
	}
}

func TestPasswordSignupRequiresOwnedDependencies(t *testing.T) {
	if owner, err := composePasswordSignup(StoreConfiguration{}, ReferenceDependencies{}, risk.Evaluator{}); err != nil || owner != nil {
		t.Fatal("unselected signup acquired owners", err)
	}
	selected := StoreConfiguration{PasswordSignup: &PasswordSignupConfiguration{}}
	if owner, err := composePasswordSignup(selected, ReferenceDependencies{}, risk.Evaluator{}); err == nil || owner != nil {
		t.Fatal("selected signup accepted absent custody")
	}
	if err := (&storeState{}).composeFeatureStores(selected, ReferenceDependencies{}); err == nil {
		t.Fatal("selected signup silently disappeared without graph")
	}
}

func TestPasswordSignupSelectedNativeMigrations(t *testing.T) {
	c := featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "session_store", signinSchema: "session_store", global: "deployment"}
	s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: c}}}
	before, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	s.state.features.passwordSignup = &passwordpg.SignupService{}
	after, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"identity_registration": true, "identity_registration_counters": true, "identity_password": true, "identity_mfa": true, "identity_capability": true}
	for _, h := range after {
		if want[h.namespace] {
			if len(h.history) == 0 || h.namespace != "identity_registration_counters" && len(h.guards) == 0 {
				t.Fatal("missing native registration history", h.namespace)
			}
			delete(want, h.namespace)
		}
		for _, prior := range before {
			if prior.namespace != h.namespace {
				continue
			}
			for i, step := range prior.history {
				if i >= len(h.history) || step != h.history[i] {
					t.Fatal("registration rewrote installed history", h.namespace)
				}
			}
		}
	}
	if len(want) != 0 {
		t.Fatal("registration cannot deploy its native prerequisites", want)
	}
	s.state.features.migrations.resetSchema = "session_store"
	s.state.features.migrations.passwordSigninSchema = "session_store"
	combined, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, h := range combined {
		if seen[h.namespace] {
			t.Fatal("combined password workflows duplicate physical history", h.namespace)
		}
		seen[h.namespace] = true
		for _, prior := range after {
			if prior.namespace != h.namespace {
				continue
			}
			for i, step := range prior.history {
				if i >= len(h.history) || step != h.history[i] {
					t.Fatal("late reset/signin rewrote registration history", h.namespace)
				}
			}
		}
	}
}
