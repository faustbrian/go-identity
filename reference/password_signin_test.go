package reference

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/risk"
)

func TestPasswordSigninSelectionAndGraphLifetime(t *testing.T) {
	type selectedSignin interface {
		PasswordSignin() (password.SigninService, error)
	}
	selected, ok := any(FeatureSet{}).(selectedSignin)
	if !ok {
		t.Fatal("reference graph cannot expose native password signin")
	}
	if owner, err := selected.PasswordSignin(); err == nil || owner != nil {
		t.Fatal("empty graph exposed password signin")
	}
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	state := &storeState{lifetime: lifetime, cancel: cancel, drained: drained,
		features: &featureState{composed: true, timeout: time.Second}}
	selected = any(FeatureSet{state: state}).(selectedSignin)
	if owner, err := selected.PasswordSignin(); err == nil || owner != nil {
		t.Fatal("unselected graph exposed password signin")
	}
	// Set the selected native owner without exercising database authority here.
	// The integration journey separately proves actual password/session effects.
	state.features.passwordSignin = &passwordpg.SigninService{}
	owner, err := selected.PasswordSignin()
	if err != nil || owner == nil {
		t.Fatal("selected graph did not expose password signin", err)
	}
	deny := func() {
		t.Helper()
		if _, err := owner.Signin(t.Context(), password.SigninRequest{}); err == nil {
			t.Fatal("inactive or foreign graph admitted password signin")
		}
		if _, err := owner.RecoverSignin(t.Context(), password.SigninRecoveryRequest{}); err == nil {
			t.Fatal("inactive or malformed graph admitted signin recovery")
		}
		if state.active != 0 {
			t.Fatal("password signin leaked graph admission")
		}
	}
	deny()
	state.features.ready = true
	deny()
	state.closed = true
	cancel()
	deny()
	if owner, err := selected.PasswordSignin(); err == nil || owner != nil {
		t.Fatal("closed graph exported password signin")
	}
}

func TestPasswordSigninRequiresOwnedDependencies(t *testing.T) {
	if owner, err := composePasswordSignin(StoreConfiguration{}, ReferenceDependencies{}, risk.Evaluator{}); err != nil || owner != nil {
		t.Fatal("unselected signin acquired an owner", err)
	}
	if owner, err := composePasswordSignin(StoreConfiguration{PasswordSignin: &PasswordSigninConfiguration{}}, ReferenceDependencies{}, risk.Evaluator{}); err == nil || owner != nil {
		t.Fatal("selected signin accepted absent graph custody")
	}
}

func TestPasswordSigninSelectedNativeMigrations(t *testing.T) {
	c := featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "session_store", signinSchema: "session_store", global: "deployment"}
	s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: c}}}
	before, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	s.state.features.migrations.passwordSigninSchema = "session_store"
	after, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for i, step := range before[0].history {
		if step != after[0].history[i] {
			t.Fatal("signin selection rewrote shared history")
		}
	}
	want := map[string]bool{"identity_password": true, "identity_password_session": true}
	for _, h := range after {
		if want[h.namespace] {
			if len(h.history) == 0 || len(h.guards) == 0 {
				t.Fatal("selected native signin owner omitted", h.namespace)
			}
			delete(want, h.namespace)
		}
	}
	if len(want) != 0 {
		t.Fatal("signin cannot deploy its native prerequisites", want)
	}
	s.state.features.migrations.resetSchema = "session_store"
	combined, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, h := range combined {
		if names[h.namespace] {
			t.Fatal("reset and signin duplicate a physical history", h.namespace)
		}
		names[h.namespace] = true
		for _, prior := range after {
			if prior.namespace == h.namespace {
				for i, step := range prior.history {
					if i >= len(h.history) || step != h.history[i] {
						t.Fatal("late reset changed installed signin history", h.namespace)
					}
				}
			}
		}
	}
}
