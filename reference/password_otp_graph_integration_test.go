//go:build integration

package reference_test

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
)

// Real public selected composition and bootstrap, not login acceptance. Account
// enrollment and delivered-code completion remain separate journey assertions.
func TestReferencePasswordOTPSelectedGraphBootstrap(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false)
	c, deps, worker := otpGraphConfiguration(t, f.config)
	deps.PostgreSQL = f.pool
	configureReferencePreAuth(t, &c)
	configureReferenceSignin(t, &c)
	origin := "https://identity.example.invalid"
	configureReferencePasswordReset(t, &c, origin, f.pool, true)
	configureReferenceRegistration(t, &c, origin)
	configureReferencePasswordMFA(t, &c, origin)
	n := c.PasswordSignin.TOTP
	profile, err := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposeMFA, Alphabet: "0123456789", Length: 6, TTL: time.Minute, ResendInterval: 30 * time.Second, MaximumSends: 3, Attempts: 3, Replacement: otp.ReplacePrevious})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := otp.NewAttemptPolicy(profile, otp.CheckPolicySpec{LockoutAfter: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	requestKeys, err := kernel.NewRequestKeyConfig("reference-secondary-otp", [32]byte{191}, c.OTP.RequestKeys.Policy)
	if err != nil {
		t.Fatal(err)
	}
	c.PasswordSignin.MFA.AllowedMethods = []string{"otp"}
	c.PasswordSignin.OTP = &reference.PasswordOTPConfiguration{MaximumDuration: n.MaximumDuration, ConfigurationID: "reference-secondary-otp-v1", CompletionConfigurationID: "reference-secondary-otp-completion-v1", PolicyID: "password-otp", RequestKeys: requestKeys, IntentKey: [32]byte{192}, ActiveEnvelopeKeyID: n.ActiveEnvelopeKeyID, Counters: n.Counters, RiskKeys: n.RiskKeys, Policy: policy, AttemptKeyVersion: 7, TemplateID: c.OTP.TemplateID, TemplateVersion: c.OTP.TemplateVersion, LocaleChain: c.OTP.LocaleChain}
	c.PasswordSignin.TOTP, c.HTTPMFA = nil, nil
	c.HTTPPasswordSignin, c.HTTPPasswordSignup, c.HTTPRegistrationVerification = nil, nil, nil
	c.Velocity.PrimaryTimeout = 5 * time.Second
	stores, err := reference.ComposeStores(c, deps)
	if err != nil {
		t.Fatal("selected secondary OTP native composition failed", err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := stores.Close(bounded); err != nil {
			t.Error("selected graph cleanup failed")
		}
		if _, err := f.pool.Raw().Exec(bounded, `DO $$ DECLARE role_name text; BEGIN FOREACH role_name IN ARRAY ARRAY['audit_writer','audit_reader','audit_retention'] LOOP IF EXISTS(SELECT FROM pg_roles WHERE rolname=role_name) THEN EXECUTE format('DROP OWNED BY %I',role_name); EXECUTE format('DROP ROLE %I',role_name); END IF; END LOOP; END $$`); err != nil {
			t.Error("owned fixture audit role cleanup failed")
		}
	})
	providers, err := reference.ComposeProviders(stores)
	if err != nil {
		t.Fatal(err)
	}
	workers, err := reference.ComposeWorkers(stores, providers, worker)
	if err != nil {
		t.Fatal(err)
	}
	features, err := reference.ComposeFeatures(stores, providers, workers)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := features.PasswordOTP(); err != nil {
		t.Fatal("public selected secondary OTP handle missing", err)
	}
	if _, err := features.PasswordTOTP(); err == nil {
		t.Fatal("OTP storage predecessors enabled unselected TOTP completion")
	}
	if _, err := features.PasswordRecovery(); err == nil {
		t.Fatal("OTP storage predecessors enabled unselected recovery completion")
	}
	modules := []reference.ModuleID{"identity/postgres", "identity/risk/postgres", "identity/otp/postgres", "identity/session/postgres", "identity/delivery/postgres", "authorization/postgres", "audit/postgres", "outbox/postgres", "outbox/postgres/identity", "identity/password/postgres", "identity/mfa/postgres", "capability/postgres/identity"}
	request := applyRequest(t, ctx, stores, modules)
	if out, err := stores.ReferenceMigrationApply(ctx, request); err != nil || out.Result.State() != reference.MigrationApplied {
		t.Fatal("selected secondary OTP migration bootstrap failed", err, out.Result.State())
	}
	for range 2 {
		if err := features.Initialize(ctx); err != nil {
			t.Fatal("native selected OTP key initialization failed", err)
		}
	}
	check, err := stores.ReferenceMigrationCheck(ctx, reference.ReferenceMigrationCheckRequest{Modules: modules})
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range check.Statuses {
		if status.Compatibility != reference.MigrationCompatible {
			t.Fatal("selected OTP bootstrap left incompatible native history")
		}
	}
	var factorRows, attributedRows int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_mfa.otp_factors),(SELECT count(*) FROM identity_mfa.continuations WHERE otp_send_command_id IS NOT NULL)`).Scan(&factorRows, &attributedRows); err != nil || factorRows != 0 || attributedRows != 0 {
		t.Fatal("bootstrap invented factor enrollment or original OTP sending", err)
	}
	if _, err := features.PasswordOTP(); err != nil {
		t.Fatal(err)
	}
	// Later TOTP selection must reuse its already applied storage predecessors,
	// not reinstall older counter/session constraints over the OTP suffixes.
	c.PasswordSignin.TOTP = n
	c.PasswordSignin.MFA.AllowedMethods = []string{"otp", "totp"}
	later, err := reference.ComposeStores(c, deps)
	if err != nil {
		t.Fatal("later TOTP selection could not preserve the OTP graph", err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := later.Close(bounded); err != nil {
			t.Error("later graph cleanup failed")
		}
	})
	planned, err := later.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: modules})
	if err != nil || len(planned.Plan.Steps) != 0 {
		t.Fatal("later TOTP selection replayed installed OTP predecessors", err)
	}
	var otpStorage bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_constraint WHERE conrelid='session_store.sessions'::regclass AND conname='session_record_binding_v9')`).Scan(&otpStorage); err != nil || !otpStorage {
		t.Fatal("later TOTP selection lost OTP session storage", err)
	}
}
