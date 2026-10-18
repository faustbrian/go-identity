//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

// The real coordinator proves target admission and retained primary locking;
// this is not an organization adapter or actor/session authentication fixture.
func testLockedTargetUserAdmission(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE IF NOT EXISTS public.identity_test_feature_audits(event_id text PRIMARY KEY,command_id text NOT NULL,event_index integer NOT NULL,retention_class text NOT NULL,UNIQUE(command_id,event_index)); CREATE TABLE IF NOT EXISTS public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE); CREATE TABLE IF NOT EXISTS public.identity_test_feature(tenant_id text,record_id text,command_id text UNIQUE,value text,PRIMARY KEY(tenant_id,record_id)); CREATE TABLE public.identity_test_target_guard(command_id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"active", "stale", "suspended", "banned", "missing", "ignored-denial", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			if _, err := pool.Raw().Exec(ctx, `DELETE FROM identity.users WHERE tenant_id='target-admission'; INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('target-admission','target','active',101)`); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "stale", "ignored-denial":
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET version=102 WHERE tenant_id='target-admission'`); err != nil {
					t.Fatal(err)
				}
			case "suspended", "banned":
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status=$1 WHERE tenant_id='target-admission'`, mode); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if _, err := pool.Raw().Exec(ctx, `DELETE FROM identity.users WHERE tenant_id='target-admission'`); err != nil {
					t.Fatal(err)
				}
			}
			phase := &featureExecutionPhase{}
			registry, err := NewContributorRegistry([]Contributor{repo, &featureExecutionAuditPhase{}, &recoveryLifecyclePhase{}, phase})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			spec := featureCodecSpec()
			spec.Fields = []identity.FeatureField{{Name: "value", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "target-admission-effect"}}}
			spec.Binding.TenantID, spec.Binding.UserID, spec.Binding.ActorID = "target-admission", "target", "different-actor"
			spec.Binding.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			spec.Binding.RecordID = string(spec.Binding.CommandID)
			command := featureCodecCommand(t, spec)
			_, _, plan := featurePlanFixture(t)
			plan.Contributors, plan.SubjectType = registry.Descriptors(), "session"
			plan.Feature = &FeatureRegistration{Contributor: phase.Descriptor(), Operation: spec.Operation}
			seed, err := securityMutationAudit(ctx, spec.Binding, 0, 1, time.Now().UTC().Truncate(time.Microsecond), "committed", "session.issue", "session", spec.Binding.RecordID, "standard", true)
			if err != nil {
				t.Fatal(err)
			}
			plan.Audits[0].RetentionClass = "standard"
			plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(spec.Binding, spec.Operation, "session", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err = coordinator.PrepareCommandPlan(spec.Binding, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, spec.Binding, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer coordinator.Abort(work, identity.UnavailableError{})
			phase.targetCheck = func(call context.Context, w Work, owner *featureExecutionPhase) error {
				if _, err := w.Exec(call, `INSERT INTO public.identity_test_target_guard(command_id) VALUES($1)`, string(spec.Binding.CommandID)); err != nil {
					return err
				}
				if mode == "canceled" {
					var cancel context.CancelFunc
					call, cancel = context.WithCancel(call)
					cancel()
				}
				err := w.RequireActiveTargetUser(call, owner, identity.User{ID: "target", TenantID: "target-admission", Status: identity.StatusActive, Version: 101})
				if err != nil {
					if mode == "canceled" {
						if !errors.Is(err, context.Canceled) {
							t.Fatal("target admission lost cancellation identity", err)
						}
					} else {
						var denied identity.ForbiddenError
						if !errors.As(err, &denied) {
							t.Fatal("stale or unavailable target did not return uniform denial", err)
						}
					}
					if mode == "ignored-denial" {
						return nil // Work poisoning must still roll back provisional writes.
					}
					return err
				}
				other, err := pool.Raw().Begin(call)
				if err != nil {
					return err
				}
				_, err = other.Exec(call, `SELECT user_id FROM identity.users WHERE tenant_id='target-admission' AND user_id='target' FOR UPDATE NOWAIT`)
				_ = other.Rollback(call)
				var blocked *pgconn.PgError
				if !errors.As(err, &blocked) || blocked.Code != "55P03" {
					t.Fatal("target lifecycle row was not held until coordinator completion", err)
				}
				return nil
			}
			result, applyErr := coordinator.ApplyFeature(ctx, work, command)
			result, commitErr := coordinator.Commit(work, result)
			var effects, provisional int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_test_feature WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_target_guard WHERE command_id=$1)`, string(spec.Binding.CommandID)).Scan(&effects, &provisional); err != nil {
				t.Fatal(err)
			}
			if mode == "active" {
				if applyErr != nil || commitErr != nil || result.Outcome != identity.CommitOutcomeCommitted || effects != 1 || provisional != 1 {
					t.Fatal("active target without credential authority was not committed", applyErr, commitErr)
				}
			} else if applyErr == nil || result.Outcome != identity.CommitOutcomeNotCommitted || effects != 0 || provisional != 0 {
				t.Fatal("target denial failed to roll back all effects", applyErr, commitErr)
			}
		})
	}
}
