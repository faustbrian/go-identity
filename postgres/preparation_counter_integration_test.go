//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// Bounded contract plan: a native counter charge must commit before generation;
// denied attempts retain their charge/audit without output; replay cannot charge
// or generate again; current counter admission still gates the final mutation.
// This tests the coordinator with real SQL, not the risk adapter's algorithms.
func testPreparedCommandCounters(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	if _, err := pool.Raw().Exec(ctx, counterPreparationSchemaSQL); err != nil {
		t.Fatal("counter preparation upgrade", err)
	}
	for _, mode := range []string{"allow", "external", "deny-apply", "lost-start", "lost-retention"} {
		t.Run(mode, func(t *testing.T) {
			phase := &preparedFeaturePhase{}
			counter := &sqlCounterAdmission{mode: mode}
			var registered FeaturePreparationContributor = phase
			if mode == "external" {
				gated := &gatedPreparedFeaturePhase{preparedFeaturePhase: phase}
				gated.prepare = func(ctx context.Context, command identity.Command) (FeaturePreparationAdmission, error) {
					return &testPreparationAdmission{phase: phase, original: command}, ctx.Err()
				}
				gated.restore = func(ctx context.Context, command identity.Command, _ uint64, _ []byte) (FeaturePreparationAdmission, error) {
					return &testPreparationAdmission{phase: phase, original: command}, ctx.Err()
				}
				registered, phase.owner = gated, gated
			}
			registry, err := NewContributorRegistry([]Contributor{repo, &featureExecutionAuditPhase{}, &recoveryLifecyclePhase{}, registered, counter})
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			input := func() (identity.Command, CommandPlan) {
				s := featureCodecSpec()
				s.Binding.TenantID = identity.TenantID("prepared-counter-" + mode)
				s.Binding.CommandID, err = identity.NewCommandID()
				if err != nil {
					t.Fatal(err)
				}
				s.Binding.RecordID = string(s.Binding.CommandID)
				s.Fields = []identity.FeatureField{{Name: "value", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "original-intent"}}}
				command := featureCodecCommand(t, s)
				_, _, plan := featurePlanFixture(t)
				plan.Contributors = registry.Descriptors()
				plan.Feature = &FeatureRegistration{Contributor: phase.Descriptor(), Operation: s.Operation}
				plan.SubjectType, plan.Audits[0].RetentionClass = "session", "standard"
				plan.CommandCounters = &CommandCounterPlan{PolicyVersion: 3, Fingerprint: [32]byte{3}}
				seed, e := securityMutationAudit(ctx, s.Binding, 0, 1, time.Now().UTC().Truncate(time.Microsecond), "committed", "session.issue", "session", s.Binding.RecordID, "standard", true)
				if e != nil {
					t.Fatal(e)
				}
				plan.Audits[0].BindingDigest, e = FeatureAuditBindingDigest(s.Binding, s.Operation, "session", seed)
				if e != nil {
					t.Fatal(e)
				}
				phase.declaration = plan
				return command, plan
			}
			command, plan := input()
			s, _ := command.Feature()
			if mode == "lost-start" || mode == "lost-retention" {
				commits := 0
				failAt := map[string]int{"lost-start": 1, "lost-retention": 2}[mode]
				c.preparationCommit = func(ctx context.Context, tx pgx.Tx) error {
					commits++
					if e := tx.Commit(ctx); e != nil {
						return e
					}
					if commits == failAt {
						return identity.UnavailableError{}
					}
					return nil
				}
			}
			phase.beforeGenerate = func(ctx context.Context, _ identity.Command, _ uint64) error {
				var charges, total int
				if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_counter_charges WHERE command_id=$1),(SELECT value FROM public.identity_counter_totals WHERE tenant_id=$2)`, string(s.Binding.CommandID), string(s.Binding.TenantID)).Scan(&charges, &total); e != nil || charges != 1 || total != 1 {
					return identity.UnavailableError{}
				}
				return nil
			}
			result, err := c.ExecutePreparedFeature(ctx, command, plan)
			if mode == "lost-start" || mode == "lost-retention" {
				if result.Outcome != identity.CommitOutcomeUnknown || !errors.As(err, new(identity.UnknownCommitError)) {
					t.Fatal("lost acknowledgement granted execution", result.Outcome, err)
				}
				id, _ := base64.RawURLEncoding.DecodeString(string(s.Binding.CommandID))
				if _, e := pool.Raw().Exec(ctx, `UPDATE identity.commands SET created_at=clock_timestamp()-interval '3 seconds',heartbeat_at=clock_timestamp()-interval '2 seconds',updated_at=clock_timestamp()-interval '2 seconds',lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); e != nil {
					t.Fatal(e)
				}
				// A new coordinator owns restart and keeps the old fingerprint key.
				c, err = NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 2, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}, 2: {2}}})
				if err != nil {
					t.Fatal(err)
				}
				changed := plan
				cp := *plan.CommandCounters
				cp.PolicyVersion++
				changed.CommandCounters = &cp
				if _, e := c.ExecutePreparedFeature(ctx, command, changed); !errors.As(e, new(identity.ConflictError)) {
					t.Fatal("restart changed frozen declaration", e)
				}
				result, err = c.ExecutePreparedFeature(ctx, command, plan)
				if mode == "lost-start" {
					var total int
					if e := pool.Raw().QueryRow(ctx, `SELECT value FROM public.identity_counter_totals WHERE tenant_id=$1`, string(s.Binding.TenantID)).Scan(&total); e != nil || total != 1 || err != nil || result.Outcome != identity.CommitOutcomeInProgress || phase.generated.Load() != 0 {
						t.Fatal("uncertain generation repeated charge/output", result.Outcome, err, e)
					}
					return
				}
			}
			want := identity.CommitOutcomeCommitted
			if mode == "deny-apply" {
				want = identity.CommitOutcomeNotCommitted
			}
			if result.Outcome != want || mode != "deny-apply" && err != nil || mode == "deny-apply" && !errors.As(err, new(identity.ForbiddenError)) || phase.generated.Load() != 1 {
				t.Fatal("prepared counter execution", result.Outcome, err)
			}
			replay, e := c.ExecutePreparedFeature(ctx, command, plan)
			if e != nil || replay.Outcome != want || phase.generated.Load() != 1 {
				t.Fatal("terminal replay repeated preparation", e)
			}
			var total, charges, effects int
			wantEffects := 1
			if mode == "deny-apply" {
				wantEffects = 0
			}
			if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT value FROM public.identity_counter_totals WHERE tenant_id=$1),(SELECT count(*) FROM public.identity_counter_charges WHERE command_id=$2),(SELECT count(*) FROM public.identity_test_feature WHERE command_id=$2)`, string(s.Binding.TenantID), string(s.Binding.CommandID)).Scan(&total, &charges, &effects); e != nil || total != 1 || charges != 1 || effects != wantEffects {
				t.Fatal("charge or domain outcome changed", e)
			}
			id, _ := base64.RawURLEncoding.DecodeString(string(s.Binding.CommandID))
			if _, e := pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_declaration=preparation_declaration || '\x01'::bytea WHERE command_id=$1`, id); e == nil {
				t.Fatal("durable declaration could be replaced")
			}
			if mode == "allow" {
				// Run the existing disclosure/copy/concurrency contract against
				// an actual counter-profile commit, not fabricated metadata.
				testPreparedFeatureQuery(t, ctx, c, phase, command, plan, true)
			}
			generatedBeforeDenial := phase.generated.Load()
			denied, deniedPlan := input()
			d, _ := denied.Feature()
			result, err = c.ExecutePreparedFeature(ctx, denied, deniedPlan)
			if result.Outcome != identity.CommitOutcomeNotCommitted || !errors.As(err, new(identity.ForbiddenError)) || phase.generated.Load() != generatedBeforeDenial {
				t.Fatal("counter denial generated output", result.Outcome, err)
			}
			var audits int
			if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT value FROM public.identity_counter_totals WHERE tenant_id=$1),(SELECT count(*) FROM public.identity_test_feature_audits WHERE command_id=$2)`, string(d.Binding.TenantID), string(d.Binding.CommandID)).Scan(&total, &audits); e != nil || total != 2 || audits != 1 {
				t.Fatal("denied charge/audit missing", e)
			}
			replay, e = c.ExecutePreparedFeature(ctx, denied, deniedPlan)
			if e != nil || replay.Outcome != identity.CommitOutcomeNotCommitted || phase.generated.Load() != generatedBeforeDenial {
				t.Fatal("denied replay repeated generation", e)
			}
		})
	}
}
