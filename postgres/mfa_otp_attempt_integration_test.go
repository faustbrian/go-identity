//go:build integration

package postgres

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// Real SQL proves coordinator atomicity/callback custody, not production OTP
// cryptography or the native MFA continuation store. Those are separate owners.
type sqlMFAOTPAttempt struct {
	mfaOTPAttemptProbe
	mode     string
	debits   atomic.Int32
	admitted atomic.Int32
	fenced   atomic.Int32
	retained MFAOTPAttemptWork
}

func (p *sqlMFAOTPAttempt) AdmitFeaturePreparation(ctx context.Context, w Work, command identity.Command) error {
	p.fenced.Add(1)
	b, feature, _, err := w.FeatureScope(p)
	spec, ok := command.Feature()
	if err != nil || !ok || command != p.expected || spec.Binding != b || spec.Operation != feature.Operation {
		return invalidWork()
	}
	return ctx.Err()
}

func (p *sqlMFAOTPAttempt) PrepareMFAOTPAttempt(ctx context.Context, w MFAOTPAttemptWork) (MFAAttemptDisposition, error) {
	p.admitted.Add(1)
	p.retained = w
	b, err := w.Binding(p)
	if err != nil {
		return 0, err
	}
	if w.RequireOTPDenial(p) == nil {
		return 0, invalidWork()
	}
	rows, err := w.Query(ctx, `SELECT remaining FROM public.mfa_otp_shared_budget WHERE tenant_id=$1 AND continuation_id=$2 FOR UPDATE`, string(b.Command.TenantID), string(b.Plan.ID))
	if err != nil {
		return 0, err
	}
	var remaining int
	ok := rows.Next() && rows.Scan(&remaining) == nil && !rows.Next() && rows.Err() == nil
	rows.Close()
	if !ok || remaining < 1 || p.mode == "admission-failure" {
		return 0, identity.ForbiddenError{}
	}
	choice, err := w.ReserveCommandCounters(ctx, p)
	if err != nil {
		return 0, err
	}
	if choice == CommandCounterDenied {
		return MFAAttemptDenied, nil
	}
	return MFAAttemptUnchanged, nil
}

func (p *sqlMFAOTPAttempt) RecordMFAOTPAttemptDenial(ctx context.Context, w MFAOTPAttemptWork) error {
	if err := w.RequireOTPDenial(p); err != nil {
		return err
	}
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	p.debits.Add(1)
	n, err := w.Exec(ctx, `UPDATE public.mfa_otp_shared_budget SET remaining=remaining-1 WHERE tenant_id=$1 AND continuation_id=$2 AND remaining>0`, string(b.Command.TenantID), string(b.Plan.ID))
	if err != nil {
		return err
	}
	if n != 1 || p.mode == "shared-failure" {
		return identity.UnavailableError{}
	}
	return nil
}

func testMFAOTPAttemptDenial(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	t.Helper()
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.mfa_otp_shared_budget(tenant_id text NOT NULL,continuation_id text NOT NULL,remaining integer NOT NULL,PRIMARY KEY(tenant_id,continuation_id));
CREATE TABLE IF NOT EXISTS public.otp_denial_totals(tenant_id text PRIMARY KEY,value integer NOT NULL);
CREATE TABLE IF NOT EXISTS public.otp_denial_attempts(command_id text PRIMARY KEY,attempt_id text NOT NULL UNIQUE,fingerprint bytea NOT NULL);
CREATE TABLE IF NOT EXISTS public.otp_denial_audits(command_id text PRIMARY KEY,event_id text UNIQUE NOT NULL,outcome text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"denied-replay", "concurrent", "unchanged", "admission-failure", "shared-failure", "audit-failure"} {
		t.Run(mode, func(t *testing.T) {
			b, plan := mfaCompletionPlanFixture(t, "otp-verify")
			b.CommandID, _ = identity.NewCommandID()
			b.TenantID = identity.TenantID("mfa-otp-" + mode)
			code, _ := auth.NewOneTimeCode("123456")
			command, err := identity.NewFeatureOneTimeCodePreAuthCommand(identity.FeatureCommandSpec{Binding: b, Operation: plan.Feature.Operation}, code, auth.NewBearerCredential(strings.Repeat("A", 43)))
			if err != nil {
				t.Fatal(err)
			}
			owner := &sqlMFAOTPAttempt{mode: mode, mfaOTPAttemptProbe: mfaOTPAttemptProbe{mfaCompletionValidationParticipant{magicLinkPreparationParticipant: magicLinkPreparationParticipant{outputPreparationParticipant: outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{plan.Feature.Operation}}}, expected: command, proof: *plan.Capability}, completion: *plan.MFACompletion}}}
			otpOwner := &sqlOTPAttempt{mode: mode}
			registry, err := NewContributorRegistry([]Contributor{repo, &otpDenialAudit{fail: mode == "audit-failure"}, &riskPassiveProbe{registryContributor{plan.Contributors[2]}}, owner, &magicLinkPreparationCounter{}, otpOwner, &capabilityExecutionProbe{}})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			plan.Contributors, plan.OTP.AttemptID = registry.Descriptors(), string(b.CommandID)
			seed, err := securityMutationAudit(ctx, b, 0, 0, time.Now().UTC().Truncate(time.Microsecond), "committed", plan.Audits[0].EventType, plan.SubjectType, b.AnonymousFlowID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, plan.Feature.Operation, plan.SubjectType, seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err = coordinator.PrepareOTPAttemptPlan(b, command, plan)
			if err != nil {
				t.Fatal("joined original counted plan unavailable", err)
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.mfa_otp_shared_budget VALUES($1,$2,3)`, string(b.TenantID), string(plan.MFACompletion.ID)); err != nil {
				t.Fatal(err)
			}
			if mode == "concurrent" {
				var workers sync.WaitGroup
				for range 4 {
					workers.Go(func() { _, _ = coordinator.RecordOTPAttemptDenial(ctx, b, command, plan) })
				}
				workers.Wait()
			}
			result, callErr := coordinator.RecordOTPAttemptDenial(ctx, b, command, plan)
			var remaining, otpDebits, audits int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT remaining FROM public.mfa_otp_shared_budget WHERE tenant_id=$1),(SELECT count(*) FROM public.otp_denial_attempts WHERE command_id=$2),(SELECT count(*) FROM public.otp_denial_audits WHERE command_id=$2)`, string(b.TenantID), string(b.CommandID)).Scan(&remaining, &otpDebits, &audits); err != nil {
				t.Fatal(err)
			}
			if mode == "denied-replay" || mode == "concurrent" {
				if result.Outcome != identity.CommitOutcomeNotCommitted || remaining != 2 || otpDebits != 1 || audits != 1 || owner.debits.Load() != 1 || otpOwner.calls.Load() != 1 {
					t.Fatalf("joined denial not atomic: error=%T outcome=%d remaining=%d OTP=%d audits=%d MFA-calls=%d OTP-calls=%d admission=%d fences=%d", callErr, result.Outcome, remaining, otpDebits, audits, owner.debits.Load(), otpOwner.calls.Load(), owner.admitted.Load(), owner.fenced.Load())
				}
				_, _ = coordinator.RecordOTPAttemptDenial(ctx, b, command, plan)
				if owner.debits.Load() != 1 || otpOwner.calls.Load() != 1 {
					t.Fatal("joined replay invoked factor callbacks again")
				}
			} else if callErr == nil || remaining != 3 || otpDebits != 0 || audits != 0 {
				t.Fatal("failed/unchanged joined attempt retained provisional debit")
			}
			if mode == "admission-failure" && otpOwner.calls.Load() != 0 {
				t.Fatal("failed MFA authority reached OTP comparison")
			}
			if _, err := owner.retained.Binding(owner); err == nil {
				t.Fatal("returned MFA callback retained authority")
			}
			if _, err := otpOwner.retained.Binding(otpOwner); err == nil {
				t.Fatal("returned OTP callback retained authority")
			}
		})
	}
}
