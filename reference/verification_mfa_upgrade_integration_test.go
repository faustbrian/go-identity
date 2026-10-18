//go:build integration

package reference_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	magicpg "github.com/faustbrian/go-identity/magiclink/postgres"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

func TestReferencePostgresVerificationMFASigninPopulatedUpgrade(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, verificationSignin: "upgrade"}, true)
}

func TestReferencePostgresVerificationMFASigninMFAFirstUpgrade(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, verificationSignin: "upgrade-mfa-first"}, true, true, true)
}

// Start with the shipped verification-only graph and genuine populated rows.
// Exercise the public migration operator, never hand-apply DDL or rewrite its
// prior ledger to manufacture a compatible upgrade.
func proveVerificationMFAPopulatedUpgrade(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, deps reference.ReferenceDependencies, worker deliverypg.WorkerConfig, modules []reference.ModuleID, serverConfig reference.ReferenceConfig, origin string, original reference.ReferenceMigrationApplyRequest, credential session.Credential) {
	t.Helper()
	rowsIn := func(table string) map[string]bool {
		t.Helper()
		rows, err := f.pool.Raw().Query(ctx, "SELECT row_to_json(r)::text FROM "+pgx.Identifier{"public", table}.Sanitize()+" r")
		if err != nil {
			t.Fatal("populated migration ledger read failed", err)
		}
		defer rows.Close()
		result := make(map[string]bool)
		for rows.Next() {
			var row string
			if err := rows.Scan(&row); err != nil {
				t.Fatal("migration ledger row unavailable", err)
			}
			result[row] = true
		}
		if rows.Err() != nil {
			t.Fatal("migration ledger stream failed", rows.Err())
		}
		return result
	}
	ledgers := make(map[string]map[string]bool)
	rows, err := f.pool.Raw().Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname='public' AND (tablename='migrations' OR tablename LIKE 'golib_migrations_%') ORDER BY tablename`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		names = append(names, name)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(names) == 0 {
		t.Fatal("original migration histories absent", err)
	}
	for _, name := range names {
		ledgers[name] = rowsIn(name)
	}
	protected := func() [3]string {
		t.Helper()
		var result [3]string
		if err := f.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT jsonb_agg(to_jsonb(s) ORDER BY session_id)::text FROM session_store.sessions s),
 (SELECT jsonb_agg(to_jsonb(k) ORDER BY capability_id)::text FROM capability_identity_one_use k),
 (SELECT row_to_json(j)::text FROM public.golib_migration_commands j WHERE command_id=$1)`, string(original.CommandID)).Scan(&result[0], &result[1], &result[2]); err != nil {
			t.Fatal("original session/issuance/operator custody unavailable", err)
		}
		return result // Compare only; never expose retained credential material.
	}
	before := protected()
	// Existing configuration helpers consume the common policy before the
	// PostgreSQL-only selector clears the external adapter configuration.
	// Supply that same durable policy while assembling each successor, then
	// clear the scratch projection before actual public composition below.
	c.Velocity.Schema = c.DurableAdmission.Schema
	c.Velocity.Native.Policy = c.DurableAdmission.Policy
	c.Velocity.Native.Keys = c.DurableAdmission.Keys
	// Copy selected pointers: configuring a successor must not mutate the live
	// predecessor's public configuration or proof targets.
	signup := *c.PasswordSignup
	verification := *signup.VerificationSignin
	signup.VerificationSignin = &verification
	c.PasswordSignup = &signup
	signin := *c.PasswordSignin
	c.PasswordSignin = &signin
	deliveryConfiguration := *c.Delivery
	deliveryConfiguration.Templates = append([]delivery.Template(nil), deliveryConfiguration.Templates...)
	c.Delivery = &deliveryConfiguration
	if c.MagicLink != nil {
		magic := *c.MagicLink
		consume := *magic.Consume
		magic.Consume = &consume
		c.MagicLink = &magic
	}
	passwordVerification := *c.PasswordVerification
	passwordVerification.Native.Targets = append([]passwordpg.ReauthenticationTarget(nil), passwordVerification.Native.Targets...)
	c.PasswordVerification = &passwordVerification
	configureReferenceMFAEnrollment(t, &c, origin)
	if c.PasswordSignup.VerificationSessionLineage == 0 {
		c.PasswordSignup.VerificationSessionLineage = reference.VerificationBeforeMFA
	}
	issuer := c.PasswordSignup.Issuer
	issuer.Audience = c.PasswordSignin.Native.Profile.Audience
	c.PasswordSignup.VerificationSignin.TOTP = &passwordpg.MFAChallengeConfig{Lifetime: time.Minute, MaxAttempts: 3, IssuerURL: origin, Issuer: issuer, Custody: c.PasswordSignup.Preparation}
	configureReferencePasswordMFA(t, &c, origin)
	completion := *c.PasswordSignin.TOTP
	c.PasswordSignup.VerificationTOTP = (*reference.VerificationTOTPConfiguration)(&completion)
	// First upgrade adds verification MFA only. Later composition must reuse
	// its permanent session lineage rather than install historical MFA SQL.
	passwordSignin := *c.PasswordSignin
	passwordSignin.MFA, passwordSignin.TOTP = nil, nil
	c.PasswordSignin = &passwordSignin
	c.HTTPMFA = nil
	for phase := range 2 {
		if phase == 1 {
			configureReferencePasswordMFA(t, &c, origin)
			if c.MagicLink == nil {
				configureReferenceMagicLink(t, &c, origin)
			}
			c.MagicLink.Request.MFAContinuation = true
			c.MagicLink.Consume.MFA = &magicpg.MFAChallengeConfig{Lifetime: time.Minute, MaxAttempts: 3}
			magicCompletion := reference.MagicLinkTOTPConfiguration(*c.PasswordSignup.VerificationTOTP)
			c.MagicLink.TOTP = &magicCompletion
		}
		selected := c
		selected.Velocity = reference.VelocityStoreConfiguration{}
		stores, err := reference.ComposeStores(selected, deps)
		if err != nil {
			t.Fatal("populated MFA upgrade composition", phase, err)
		}
		t.Cleanup(func() {
			bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := stores.Close(bounded); err != nil {
				t.Error(err)
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
		if phase == 0 && c.PasswordSignup.VerificationSessionLineage == reference.MFABeforeVerification {
			proveUnmanagedPasswordContinuationStillDenies(t, ctx, f, stores, modules)
		}
		planned, err := stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: modules})
		if err != nil {
			status, checkErr := stores.ReferenceMigrationCheck(ctx, reference.ReferenceMigrationCheckRequest{Modules: modules})
			t.Fatal("populated successor plan rejected", phase, err, checkErr, status.Statuses)
		}
		request := reference.ReferenceMigrationApplyRequest{Plan: planned.Plan}
		request.CommandID = identity.CommandID(fmt.Sprintf("verification_mfa_upgrade_%d", phase))
		request.IdempotencyKey, err = identity.NewIdempotencyKey([]byte(fmt.Sprintf("verification-mfa-upgrade-%d", phase)))
		if err != nil || len(request.Plan.Steps) == 0 {
			t.Fatal("successor has no actual forward migration", phase, err)
		}
		for range 2 {
			out, err := stores.ReferenceMigrationApply(ctx, request)
			if err != nil || out.Result.State() != reference.MigrationApplied || protected() != before {
				t.Fatal("populated upgrade/retry changed original session/issuance/operator", phase, err)
			}
		}
		for name, prior := range ledgers {
			current := rowsIn(name)
			for row := range prior {
				if !current[row] {
					t.Fatal("upgrade changed an applied native migration record", phase, name)
				}
			}
		}
		if err := features.Initialize(ctx); err != nil {
			t.Fatal("populated successor initialize", phase, err)
		}
		server, err := reference.NewServer(serverConfig, deps, features)
		if err != nil {
			var invalid identity.InvalidInputError
			errors.As(err, &invalid)
			t.Fatal("populated successor server invalid", phase, err, invalid.Field)
		}
		if readiness := server.Readiness(ctx); !readiness.Ready {
			t.Fatal("populated successor not ready", phase, readiness.Failures)
		}
		sessions, err := features.Sessions()
		if err != nil {
			t.Fatal(err)
		}
		current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
		if err != nil || !current.Authenticated {
			t.Fatal("retained verification session lost after MFA upgrade", phase, err)
		}
	}
}

func proveUnmanagedPasswordContinuationStillDenies(t *testing.T, ctx context.Context, f liveStores, stores reference.StoreSet, modules []reference.ModuleID) {
	t.Helper()
	var predecessor string
	if err := f.pool.Raw().QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='identity_mfa.continuations'::regclass AND conname='continuations_origin_purpose_check'`).Scan(&predecessor); err != nil {
		t.Fatal("original continuation CHECK unavailable", err)
	}
	steps, err := (mfapg.PasswordContinuationMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 7}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Negative-only fault: apply the actual native owner's suffix without its
	// ledger. The public operator must reject it, not silently adopt the shape.
	if _, err := f.pool.Raw().Exec(ctx, steps[len(steps)-1].UpSQL()); err != nil {
		t.Fatal("unmanaged continuation fault unavailable", err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := f.pool.Raw().Exec(bounded, `ALTER TABLE identity_mfa.continuations DROP CONSTRAINT continuations_origin_purpose_check, ADD CONSTRAINT continuations_origin_purpose_check `+predecessor); err != nil {
			t.Error("negative migration fault cleanup failed", err)
			return
		}
		restored = true
	}
	defer restore()
	var conflict identity.ConflictError
	if _, err := stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: modules}); !errors.As(err, &conflict) {
		t.Fatal("unmanaged password continuation was not rejected", err)
	}
	restore()
}
