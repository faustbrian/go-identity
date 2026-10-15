package reference

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestPasswordResetSelectedNativeMigrations(t *testing.T) {
	c := featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "session_store", global: "deployment"}
	s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, httpRate: &httpRateState{}, features: &featureState{migrations: c}}}
	before, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	s.state.features.migrations.resetSchema = "session_store"
	s.state.features.httpPasswordReset = &passwordResetHTTPState{}
	after, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for i, step := range before[0].history {
		if step != after[0].history[i] {
			t.Fatal("reset rewrote installed shared history")
		}
	}
	want := map[string]ModuleID{"identity_password": "identity/password/postgres", "identity_mfa": "identity/mfa/postgres", "identity_reset_kernel": "identity/postgres", "identity_reset_session": "identity/session/postgres", "identity_capability": "capability/postgres/identity"}
	for _, h := range after {
		if _, err := migrations.PlanUp(h.history, nil); err != nil {
			t.Fatal("selected owner cannot install", h.namespace, err)
		}
		if owner, ok := want[h.namespace]; ok {
			if len(h.history) == 0 || len(h.guards) == 0 {
				t.Fatal("owner lacks history or readiness objects", h.namespace)
			}
			for _, step := range h.history {
				if h.owners[step.Version()] != owner {
					t.Fatal("native owner replaced", h.namespace)
				}
			}
			delete(want, h.namespace)
		}
		if h.namespace == "identity_http_rate" && len(h.history) != 2 {
			t.Fatal("completion atomic rate history missing")
		}
	}
	if len(want) != 0 {
		t.Fatal("reset dependencies omitted", want)
	}
}

func TestPasswordResetMigrationRequiresInstalledKernel(t *testing.T) {
	kernel := planFixture(t, "identity_reset_kernel", "identity/postgres", 1)
	password := planFixture(t, "identity_password", "identity/password/postgres", 1)
	if _, err := buildMigrationPlan([]migrationSnapshot{kernel, password}, []ModuleID{"identity/password/postgres"}); err == nil {
		t.Fatal("password install accepted absent kernel prerequisite")
	}
	record, err := migrations.NewRecord(migrations.RecordKindMigration, 1, "step", kernel.history.history[0].Checksum(), time.Unix(1700000000, 0), time.Millisecond, false)
	if err != nil {
		t.Fatal(err)
	}
	kernel.records = []migrations.Record{record}
	kernel.statuses = kernel.history.project(kernel.records)
	if plan, err := buildMigrationPlan([]migrationSnapshot{kernel, password}, []ModuleID{"identity/password/postgres"}); err != nil || len(plan.Steps) != 1 {
		t.Fatal("installed prerequisite could not be reused", err)
	}
}

// This isolates graph lifetime, not the native database journey.
func TestPasswordResetSelectionAndGraphLifetime(t *testing.T) {
	for _, f := range []FeatureSet{{}, {state: &storeState{features: &featureState{composed: true}}}} {
		if service, err := f.PasswordReset(); err == nil || service != nil {
			t.Fatal("unselected reset exported a workflow")
		}
	}
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	state := &storeState{lifetime: lifetime, cancel: cancel, drained: drained,
		features: &featureState{composed: true, timeout: time.Second, reset: &passwordpg.ResetService{}}}
	service, err := (FeatureSet{state: state}).PasswordReset()
	if err != nil || service == nil {
		t.Fatal("selected reset did not expose public workflow", err)
	}
	inspection, err := (FeatureSet{state: state}).PasswordResetInspection()
	if err != nil || inspection == nil {
		t.Fatal("selected reset did not expose read-only inspection")
	}
	deny := func() {
		t.Helper()
		if _, err := service.ResetRequest(t.Context(), password.ResetRequestRequest{}); err == nil {
			t.Fatal("inactive/foreign graph admitted request")
		}
		if _, err := service.ResetComplete(t.Context(), password.ResetCompleteRequest{}); err == nil {
			t.Fatal("inactive/foreign graph admitted completion")
		}
		if result, err := inspection.ResetInspect(t.Context(), password.ResetInspectRequest{}); err == nil || result.Valid {
			t.Fatal("inactive/foreign graph returned positive inspection")
		}
		if _, err := service.RecoverResetRequest(t.Context(), identity.RecoveryQuery{}, authorization.DecisionContext{}); err == nil {
			t.Fatal("inactive/foreign graph admitted request recovery")
		}
		if _, err := service.RecoverResetComplete(t.Context(), identity.RecoveryQuery{}, authorization.DecisionContext{}); err == nil {
			t.Fatal("inactive/foreign graph admitted completion recovery")
		}
		if state.active != 0 {
			t.Fatal("reset leaked graph admission")
		}
	}
	deny()
	state.features.ready = true
	deny()
	state.closed = true
	cancel()
	deny()
	if service, err := (FeatureSet{state: state}).PasswordReset(); err == nil || service != nil {
		t.Fatal("closed graph exported a reset handle")
	}
}

func TestPasswordResetSelectedServerRoutes(t *testing.T) {
	c, d, f := serverFixture(t)
	selection := serverOTPSelection(t, c)
	preauth, err := composePreAuthHTTP(selection)
	if err != nil {
		t.Fatal(err)
	}
	rate, err := composeHTTPRate(selection.HTTPRate, d.PostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rate.limiter.Close() })
	deviceCookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	preauth.device.Cookie = deviceCookie
	f.state.httpRate = rate
	f.state.features.httpPreAuth = preauth
	f.state.features.preauth = &session.PreAuthIssuer{}
	f.state.features.reset = &passwordpg.ResetService{}
	f.state.features.timeout = time.Second
	verificationRate, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: rate.backend, Namespace: "server-reset", Key: [32]byte{11}, Now: time.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { verificationRate.Close() })
	f.state.features.httpPasswordReset = &passwordResetHTTPState{config: HTTPPasswordResetConfiguration{ActorID: "operator", PolicyRevision: 9, CallbackURL: "https://login.example/reset", VerificationNamespace: "server-reset", VerificationKey: [32]byte{11}}, rate: verificationRate, maximumDuration: time.Second}
	s, err := NewServer(c, d, f)
	if err != nil {
		t.Fatal("selected reset server construction", err)
	}
	seen := map[string]bool{}
	for _, operation := range s.OpenAPI().Operations() {
		seen[operation.Record.OperationID] = true
	}
	if !seen["identity.password.reset-request"] || !seen["identity.password.reset-complete"] || len(seen) != 5 {
		t.Fatal("selected reset routes absent or unrelated feature enabled")
	}
	f.state.features.httpPasswordReset.config.Inspect = true
	inspectionRate, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: rate.backend, Namespace: selection.HTTPRate.Namespace, Key: selection.HTTPRate.IdentifierKey, Now: time.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inspectionRate.Close() })
	f.state.features.httpPasswordReset.inspectRate = inspectionRate
	s, err = NewServer(c, d, f)
	if err != nil || len(s.OpenAPI().Operations()) != 6 {
		t.Fatal("explicit inspection selection failed", err)
	}
	seenInspection := false
	for _, operation := range s.OpenAPI().Operations() {
		seenInspection = seenInspection || operation.Record.OperationID == "identity.password.reset-inspect"
	}
	if !seenInspection {
		t.Fatal("explicit inspection missing from selected metadata")
	}
	f.state.features.httpPasswordReset = nil
	s, err = NewServer(c, d, f)
	if err != nil || len(s.OpenAPI().Operations()) != 3 {
		t.Fatal("disabled reset retained routes or metadata", err)
	}
}

func TestPasswordResetSelectionRequiresOwnedDependencies(t *testing.T) {
	if service, err := composePasswordReset(StoreConfiguration{}, ReferenceDependencies{}, risk.Evaluator{}); err != nil || service != nil {
		t.Fatal("unselected reset acquired dependencies", err)
	}
	if service, err := composePasswordReset(StoreConfiguration{PasswordReset: &PasswordResetConfiguration{}}, ReferenceDependencies{}, risk.Evaluator{}); err == nil || service != nil {
		t.Fatal("selected reset without native custody exposed a service")
	}
}
