package reference

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

func TestPasswordVerificationSelection(t *testing.T) {
	type selectedVerification interface {
		PasswordVerification() (password.VerificationService, error)
		CookiePasswordVerification() (password.CookieVerificationService, error)
	}
	selected, ok := any(FeatureSet{}).(selectedVerification)
	if !ok {
		t.Fatal("reference cannot expose native password reauthentication")
	}
	if owner, err := selected.PasswordVerification(); err == nil || owner != nil {
		t.Fatal("empty graph exposed bearer verification")
	}
	if owner, err := selected.CookiePasswordVerification(); err == nil || owner != nil {
		t.Fatal("empty graph exposed cookie verification")
	}
}

func TestPasswordVerificationSelectionRequiresAuthority(t *testing.T) {
	if owner, err := composePasswordVerification(StoreConfiguration{}, ReferenceDependencies{}, risk.Evaluator{}); err != nil || owner != nil {
		t.Fatal("unselected verification acquired dependencies", err)
	}
	c := StoreConfiguration{PasswordVerification: &PasswordVerificationConfiguration{}}
	if owner, err := composePasswordVerification(c, ReferenceDependencies{}, risk.Evaluator{}); err == nil || owner != nil {
		t.Fatal("selected verification accepted absent authority")
	}
	if err := (&storeState{}).composeFeatureStores(c, ReferenceDependencies{}); err == nil {
		t.Fatal("selected verification disappeared without its graph")
	}
}

func TestPasswordVerificationGraphLifetime(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	s := &storeState{lifetime: lifetime, cancel: cancel, drained: drained, features: &featureState{composed: true, timeout: time.Second}}
	f := FeatureSet{state: s}
	if owner, err := f.PasswordVerification(); err == nil || owner != nil {
		t.Fatal("unselected graph exposed verification")
	}
	s.features.passwordVerification = &passwordVerificationState{bearer: &passwordpg.VerificationWorkflow{}}
	bearer, err := f.PasswordVerification()
	if err != nil || bearer == nil {
		t.Fatal("selected native bearer unavailable", err)
	}
	if owner, err := f.CookiePasswordVerification(); err == nil || owner != nil {
		t.Fatal("missing cookie owner fell back to bearer")
	}
	s.features.passwordVerification.cookie = &passwordpg.CookieVerificationWorkflow{}
	cookie, err := f.CookiePasswordVerification()
	if err != nil || cookie == nil {
		t.Fatal("selected native cookie unavailable", err)
	}
	deny := func() {
		t.Helper()
		if _, err := bearer.Verify(t.Context(), password.VerificationRequest{TenantID: "foreign"}); err == nil {
			t.Fatal("inactive/foreign graph admitted bearer verification")
		}
		if _, err := cookie.Verify(t.Context(), password.CookieVerificationRequest{Request: password.VerificationRequest{TenantID: "foreign"}}); err == nil {
			t.Fatal("inactive/foreign graph admitted cookie verification")
		}
		q := identity.RecoveryQuery{TenantID: "foreign"}
		if _, err := bearer.Recover(t.Context(), q, authorization.DecisionContext{}); err == nil {
			t.Fatal("inactive/foreign graph admitted bearer recovery")
		}
		if _, err := cookie.Recover(t.Context(), q, authorization.DecisionContext{}); err == nil {
			t.Fatal("inactive/foreign graph admitted cookie recovery")
		}
		if s.active != 0 {
			t.Fatal("verification leaked graph lifetime admission")
		}
	}
	deny()
	s.features.ready = true
	deny()
	s.closed = true
	cancel()
	deny()
	if owner, err := f.PasswordVerification(); err == nil || owner != nil {
		t.Fatal("closed graph exposed bearer verification")
	}
	if owner, err := f.CookiePasswordVerification(); err == nil || owner != nil {
		t.Fatal("closed graph exposed cookie verification")
	}
}

func TestPasswordVerificationProtectedChangeSelection(t *testing.T) {
	type selectedChange interface {
		PasswordChange() (password.ChangeService, error)
		CookiePasswordChange() (password.CookieChangeService, error)
	}
	selected, ok := any(FeatureSet{}).(selectedChange)
	if !ok {
		t.Fatal("reference cannot expose native keyed password change")
	}
	if owner, err := selected.PasswordChange(); err == nil || owner != nil {
		t.Fatal("empty graph exposed bearer password change")
	}
	if owner, err := selected.CookiePasswordChange(); err == nil || owner != nil {
		t.Fatal("empty graph exposed cookie password change")
	}
}

func TestPasswordVerificationChangeMigrationsPreserveInstalledOwners(t *testing.T) {
	c := featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "preauth_store", signinSchema: "session_store", passwordSigninSchema: "session_store", global: "deployment"}
	s := &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: c}}
	stores := StoreSet{state: s}
	before, err := stores.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	s.features.passwordChange = &passwordChangeState{}
	after, err := stores.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, old := range before {
		found := false
		for _, current := range after {
			if current.namespace != old.namespace {
				continue
			}
			found = true
			if len(current.history) != len(old.history) {
				t.Fatal("change rewrote an installed owner")
			}
			for i, step := range old.history {
				if current.history[i] != step {
					t.Fatal("change rewrote an installed checksum")
				}
			}
		}
		if !found {
			t.Fatal("change discarded an installed owner")
		}
	}
	wanted := map[string]int{"identity_reset_kernel": 1, "identity_password_change_kernel": 1, "identity_password_change_session": 2}
	for _, current := range after {
		if count, ok := wanted[current.namespace]; ok {
			if len(current.history) != count {
				t.Fatal("change omitted a native migration prerequisite")
			}
			delete(wanted, current.namespace)
		}
	}
	if len(wanted) != 0 {
		t.Fatal("selected password change has no complete native migration history")
	}
	base := fixedMigrationSource(before[0].history)
	replacement, err := (kernel.CredentialReplacementMigrationSource{Base: base, Version: 1500}).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	counter, err := (kernel.CounterPreparationMigrationSource{Base: base, Version: 1700}).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	continuation, err := (sessionpg.CredentialContinuationMigrationSource{Schema: c.passwordSigninSchema, Version: 1}).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	effects, err := (sessionpg.PasswordChangeMigrationSource{Schema: c.passwordSigninSchema, Version: 2}).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range after {
		switch h.namespace {
		case "identity_reset_kernel":
			if h.history[0] != replacement[len(replacement)-1] {
				t.Fatal("replacement differs from its existing native allocation")
			}
		case "identity_password_change_kernel":
			if h.history[0] != counter[len(counter)-1] {
				t.Fatal("counter preparation differs from its native owner")
			}
		case "identity_password_change_session":
			if h.history[0] != continuation[0] || h.history[1] != effects[0] {
				t.Fatal("session change differs from its native owner")
			}
		}
	}
	// Reset already owns credential replacement. Co-selection must not create
	// that table or its independently retained history a second time.
	s.features.migrations.resetSchema = c.passwordSigninSchema
	combined, err := stores.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, h := range combined {
		if h.namespace == "identity_reset_kernel" {
			count++
			if len(h.history) != 2 || h.history[0] != replacement[len(replacement)-1] {
				t.Fatal("reset/change cannot share their native replacement history")
			}
		}
	}
	if count != 1 {
		t.Fatal("duplicate credential replacement owner")
	}
}

func TestPasswordVerificationChangeSelectionAndLifetime(t *testing.T) {
	if owner, err := composePasswordChange(StoreConfiguration{}, ReferenceDependencies{}, nil); err != nil || owner != nil {
		t.Fatal("unselected change acquired dependencies", err)
	}
	c := StoreConfiguration{PasswordChange: &PasswordChangeConfiguration{}}
	if owner, err := composePasswordChange(c, ReferenceDependencies{}, nil); err == nil || owner != nil {
		t.Fatal("change accepted absent verification/keyring authority")
	}
	if err := (&storeState{}).composeFeatureStores(c, ReferenceDependencies{}); err == nil {
		t.Fatal("selected change disappeared without verification")
	}
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	s := &storeState{lifetime: lifetime, cancel: cancel, drained: drained, features: &featureState{composed: true, timeout: time.Second}}
	f := FeatureSet{state: s}
	if owner, err := f.PasswordChange(); err == nil || owner != nil {
		t.Fatal("unselected graph exposed password change")
	}
	s.features.passwordChange = &passwordChangeState{bearer: &passwordpg.ChangeWorkflow{}}
	bearer, err := f.PasswordChange()
	if err != nil || bearer == nil {
		t.Fatal("selected native bearer change unavailable", err)
	}
	if owner, err := f.CookiePasswordChange(); err == nil || owner != nil {
		t.Fatal("cookie change fell back to bearer")
	}
	s.features.passwordChange.cookie = &passwordpg.CookieChangeWorkflow{}
	cookie, err := f.CookiePasswordChange()
	if err != nil || cookie == nil {
		t.Fatal("selected native cookie change unavailable", err)
	}
	for _, ready := range []bool{false, true} {
		s.features.ready = ready
		if _, err := bearer.Change(t.Context(), password.ChangeRequest{TenantID: "foreign"}); err == nil {
			t.Fatal("inactive/foreign graph admitted bearer replacement")
		}
		if _, err := cookie.Change(t.Context(), password.CookieChangeRequest{Request: password.ChangeRequest{TenantID: "foreign"}}); err == nil {
			t.Fatal("inactive/foreign graph admitted cookie replacement")
		}
		q := identity.RecoveryQuery{TenantID: "foreign"}
		if _, err := bearer.Recover(t.Context(), q, authorization.DecisionContext{}); err == nil {
			t.Fatal("inactive/foreign graph admitted bearer recovery")
		}
		if _, err := cookie.Recover(t.Context(), q, authorization.DecisionContext{}); err == nil {
			t.Fatal("inactive/foreign graph admitted cookie recovery")
		}
		if s.active != 0 {
			t.Fatal("change leaked graph lifetime admission")
		}
	}
	s.closed = true
	cancel()
	if owner, err := f.PasswordChange(); err == nil || owner != nil {
		t.Fatal("closed graph exposed bearer change")
	}
	if owner, err := f.CookiePasswordChange(); err == nil || owner != nil {
		t.Fatal("closed graph exposed cookie change")
	}
	if _, err := bearer.Change(t.Context(), password.ChangeRequest{}); err == nil {
		t.Fatal("closed graph admitted retained bearer handle")
	}
	if _, err := cookie.Change(t.Context(), password.CookieChangeRequest{}); err == nil {
		t.Fatal("closed graph admitted retained cookie handle")
	}
}
