package reference

import (
	"context"
	"testing"
	"time"

	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
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
	httpOwner, ok := owner.(passwordhttp.SigninService)
	if !ok {
		t.Fatal("selected password owner cannot authenticate HTTP identifier-rate input")
	}
	deny := func() {
		t.Helper()
		if source, err := httpOwner.SigninRateSource(t.Context(), password.SigninRequest{}); err == nil || source != "" {
			t.Fatal("inactive or foreign graph disclosed password identifier-rate input")
		}
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

func TestPasswordOriginalFlowSelectionAndGraphLifetime(t *testing.T) {
	type originalPasswordFlow interface {
		PasswordPreAuth() (PreAuthService, error)
	}
	selected, ok := any(FeatureSet{}).(originalPasswordFlow)
	if !ok {
		t.Fatal("reference has no original password-flow issuer")
	}
	if owner, err := selected.PasswordPreAuth(); err == nil || owner != nil {
		t.Fatal("empty graph exposed password initiation")
	}
	lifetime, cancel := context.WithCancel(t.Context())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	state := &storeState{lifetime: lifetime, cancel: cancel, drained: drained, features: &featureState{composed: true, timeout: time.Second, passwordPreauth: &session.PreAuthIssuer{}}}
	owner, err := any(FeatureSet{state: state}).(originalPasswordFlow).PasswordPreAuth()
	if err != nil || owner == nil {
		t.Fatal("selected password issuer unavailable", err)
	}
	for _, ready := range []bool{false, true} {
		state.features.ready = ready
		if _, err := owner.Prepare(t.Context(), session.PreAuthPrepareInput{}); err == nil {
			t.Fatal("inactive/foreign flow prepared")
		}
		if _, err := owner.Issue(t.Context(), session.PreparedPreAuthIssuance{}); err == nil {
			t.Fatal("inactive/foreign flow issued")
		}
		if _, err := owner.Recover(t.Context(), session.PreAuthIssueCommand{}); err == nil {
			t.Fatal("inactive/foreign flow recovered")
		}
		if state.active != 0 {
			t.Fatal("password initiation leaked graph admission")
		}
	}
	state.closed = true
	cancel()
	if _, err := owner.Prepare(t.Context(), session.PreAuthPrepareInput{}); err == nil {
		t.Fatal("closed graph prepared flow")
	}
	if handle, err := any(FeatureSet{state: state}).(originalPasswordFlow).PasswordPreAuth(); err == nil || handle != nil {
		t.Fatal("closed graph exposed password issuer")
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
