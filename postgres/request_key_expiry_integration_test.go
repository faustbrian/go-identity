//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This is the kernel's authenticated-native-codec port, not proof of the
// organization's encryption or session admission. Its consumer must prove those.
func testExpiredMappedOrigin(t *testing.T, ctx context.Context, c *Coordinator, owner *requestPreparationParticipant, input RequestKeyPreparationBinding, wire []byte, original identity.CommandBinding, intent identity.RequestIntent) {
	t.Helper()
	original.CommandID = input.Admission.CommandID
	original.TenantID, original.ActorID, original.ActorKind = input.Scope.TenantID, input.Scope.ActorID, input.Scope.ActorKind
	q, caller := queryInputs(original)
	allow := true
	c.queryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		outcome := authorization.Deny
		if allow {
			outcome = authorization.Allow
		}
		return authorization.Decision{Outcome: outcome, Revision: 9}, nil
	})}
	deadline := time.Now().UTC().Add(2*time.Second + time.Nanosecond)
	decode := func(b RequestKeyPreparationBinding) identity.CommandBinding {
		out := original
		out.CommandID = b.Admission.CommandID
		return out
	}
	owner.restore = func(_ context.Context, b RequestKeyPreparationBinding, _ []byte) (identity.CommandBinding, error) {
		return decode(b), nil
	}
	owner.expiry = func(callback context.Context, b RequestKeyPreparationBinding, got []byte) (identity.CommandBinding, time.Time, error) {
		if _, bounded := callback.Deadline(); !bounded || b.Namespace != input.Namespace || b.Scope != input.Scope || b.Feature != input.Feature || b.IntentDigest != input.IntentDigest || b.PolicyVersion != input.PolicyVersion || !bytes.Equal(got, wire) {
			t.Fatal("expiry lost original native custody or bound")
		}
		return decode(b), deadline, nil
	}
	var unknown identity.UnknownCommitError
	if result, err := c.ExpirePreparedFeatureCommand(ctx, q, caller, input.Feature, owner); !errors.As(err, &unknown) || result.Outcome != identity.CommitOutcomeUnknown || result.Binding != original {
		t.Fatal("live mapped origin was definitively refused", err)
	}
	timer := time.NewTimer(time.Until(deadline.Add(time.Microsecond)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	result, err := c.ExpirePreparedFeatureCommand(ctx, q, caller, input.Feature, owner)
	if err != nil || result.Binding != original || result.Outcome != identity.CommitOutcomeNotCommitted || result.Validate() != nil {
		t.Fatal("expired never-started mapped original lacks definitive fenced noncommit", result.Outcome, err)
	}
	for range 2 {
		restarted, err := NewCoordinatorWithRequestKeys(c.pool, c.registry, CoordinatorConfig{MaximumDuration: c.maximumDuration, LeaseDuration: c.leaseDuration, CurrentFingerprintKeyVersion: c.keys.current, RetainedFingerprintKeys: c.keys.retained, QueryPolicy: c.queryPolicy}, *c.requestKeys)
		if err != nil {
			t.Fatal(err)
		}
		out, err := restarted.ExpirePreparedFeatureCommand(ctx, q, caller, input.Feature, owner)
		if err != nil || out.Binding != original || out.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("reconstructed coordinator lost exact refusal", err)
		}
	}
	for _, altered := range []string{"subject", "record", "actor", "tenant"} {
		other := q
		switch altered {
		case "subject":
			other.UserID = "foreign"
		case "record":
			other.RecordID = "foreign"
		case "actor":
			other.ActorID = "foreign"
		case "tenant":
			other.TenantID = "foreign"
		}
		if out, err := c.ExpirePreparedFeatureCommand(ctx, other, callerForQuery(caller, other), input.Feature, owner); err == nil || out.Binding.CommandID != "" {
			t.Fatal("foreign expiry disclosed original metadata", altered)
		}
	}
	if out, err := c.RecoverPreparedFeatureCommand(ctx, q, caller, input.Feature, owner); err == nil || out.Binding.CommandID != "" {
		t.Fatal("generic recovery disclosed typed retirement")
	}
	if out, err := c.RecoverFeatureCommand(ctx, q, caller); err == nil || out.Binding.CommandID != "" {
		t.Fatal("generic retired privacy changed")
	}
	restore := owner.expiry
	for _, kind := range []string{"policy", "deadline", "current-denial"} {
		owner.expiry = func(ctx context.Context, b RequestKeyPreparationBinding, wire []byte) (identity.CommandBinding, time.Time, error) {
			out, deadline, err := restore(ctx, b, wire)
			switch kind {
			case "policy":
				out.PolicyID = "changed-policy"
			case "deadline":
				deadline = deadline.Add(time.Hour)
			case "current-denial":
				allow = false
			}
			return out, deadline, err
		}
		out, err := c.ExpirePreparedFeatureCommand(ctx, q, caller, input.Feature, owner)
		allow, owner.expiry = true, restore
		if err == nil || out.Binding.CommandID != "" {
			t.Fatal("changed original or current policy disclosed refusal", kind)
		}
	}
	raw, _ := base64.RawURLEncoding.DecodeString(string(original.CommandID))
	for _, sql := range []string{
		`UPDATE identity.identity_command_id_claims SET request_key_expiry_fingerprint=decode(repeat('02',32),'hex') WHERE command_id=$1`,
		`UPDATE identity.identity_command_id_claims SET retired=false,request_key_expiry_fingerprint=NULL,tenant_id='tenant',purpose='identity.test',fingerprint=decode(repeat('02',32),'hex'),fingerprint_key_version=1,safe_fields=decode('01','hex') WHERE command_id=$1`,
		`DELETE FROM identity.identity_command_id_claims WHERE command_id=$1`,
	} {
		_, err := c.pool.Raw().Exec(ctx, sql, raw)
		var refusal *pgconn.PgError
		if !errors.As(err, &refusal) || refusal.Code != "23514" {
			t.Fatal("typed refusal could be removed or reassigned", err)
		}
	}
	if _, err := c.pool.Raw().Exec(ctx, `TRUNCATE identity.identity_command_id_claims CASCADE`); err == nil {
		t.Fatal("typed refusal could be truncated")
	}
	tx, err := c.pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	disposition, claimErr := lockCommandClaim(ctx, tx, claimRequest{commandID: original.CommandID, tenant: original.TenantID, purpose: original.OperationID, canonical: []byte("delayed-original"), safeFields: commandSafeFields(original, &input.Feature.Operation)}, c.keys)
	_ = tx.Rollback(ctx)
	if claimErr != nil || disposition != claimConflict {
		t.Fatal("delayed ordinary/prepared claim escaped retired-ID gate", claimErr)
	}
	newOrigin := func(name string) (identity.CommandBinding, identity.RecoveryQuery, authorization.DecisionContext) {
		t.Helper()
		key, _ := identity.NewIdempotencyKey([]byte("expiry-" + name))
		b, retained, err := c.ResolvePreparedRequestKey(ctx, input.Scope, key, intent, requestKeyCaller(input.Scope), input.Feature, owner)
		clear(retained)
		if err != nil {
			t.Fatal(err)
		}
		original := decode(b)
		q, caller := queryInputs(original)
		return original, q, caller
	}
	concurrent, cq, cc := newOrigin("concurrent")
	var wait sync.WaitGroup
	for range 4 {
		wait.Go(func() {
			out, err := c.ExpirePreparedFeatureCommand(ctx, cq, cc, input.Feature, owner)
			if err != nil || out.Outcome != identity.CommitOutcomeNotCommitted || out.Binding != concurrent {
				t.Error("concurrent refusals did not converge", err)
			}
		})
	}
	wait.Wait()
	t.Run("original-reservation-wins", func(t *testing.T) {
		original, q, caller := newOrigin("reservation")
		planner, command, plan := featurePlanFixture(t)
		planner.pool, planner.keys = c.pool, c.keys
		repository, err := NewRepository(c.pool, Config{MaximumDuration: c.maximumDuration})
		if err != nil {
			t.Fatal(err)
		}
		planner.registry, err = NewContributorRegistry([]Contributor{repository, &featureExecutionAuditPhase{}, &recoveryLifecyclePhase{}, owner})
		if err != nil {
			t.Fatal(err)
		}
		plan.Contributors = planner.registry.Descriptors()
		spec, _ := command.Feature()
		spec.Binding, spec.Operation = original, input.Feature.Operation
		command, err = identity.NewFeatureCommand(spec)
		if err != nil {
			t.Fatal(err)
		}
		plan.Feature, plan.SubjectType = &input.Feature, "session"
		plan.Audits[0].RetentionClass = "standard"
		seed, err := securityMutationAudit(ctx, original, 0, 1, time.Now().UTC().Truncate(time.Microsecond), "committed", plan.Audits[0].EventType, plan.SubjectType, original.RecordID, "standard", true)
		if err != nil {
			t.Fatal(err)
		}
		plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(original, input.Feature.Operation, plan.SubjectType, seed)
		if err != nil {
			t.Fatal(err)
		}
		probe, err := prepareClaim(command, c.keys.retained[c.keys.current])
		if err != nil || !validClaim(probe, c.keys) || !bytes.Equal(probe.safeFields, commandSafeFields(original, &spec.Operation)) {
			t.Fatal("race fixture claim codec", err)
		}
		if _, err := FeaturePlanDigest(original, claimFingerprint(c.keys.retained[c.keys.current], probe.canonical), plan); err != nil {
			t.Fatal("race fixture plan codec", err)
		}
		request, frozen, _, err := planner.prepare(original, command, plan)
		if err != nil {
			t.Fatal("actual claim preparation", err)
		}
		tx, err := c.pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		race, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		defer func() {
			cancel()
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			_ = tx.Rollback(cleanup)
			<-done
		}()
		disposition, err := lockCommandClaim(ctx, tx, request, c.keys)
		if err != nil || disposition != claimNew {
			close(done)
			t.Fatal("original reservation could not own its claim", err)
		}
		if _, err := reserveJournal(ctx, tx, request, disposition, [16]byte{1}, time.Minute); err != nil {
			close(done)
			t.Fatal(err)
		}
		if _, err := planner.freezePlan(ctx, tx, original, request, disposition, frozen); err != nil {
			close(done)
			t.Fatal("original reservation plan", err)
		}
		type observed struct {
			result identity.CommandResult
			err    error
		}
		output := make(chan observed, 1)
		go func() {
			defer close(done)
			result, err := c.ExpirePreparedFeatureCommand(race, q, caller, input.Feature, owner)
			output <- observed{result, err}
		}()
		waiting := false
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for !waiting {
			if err := c.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'INSERT INTO identity.identity_command_id_claims(command_id,retired,%')`).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if !waiting {
				select {
				case got := <-output:
					t.Fatal("expiry did not arbitrate against original claim", got.err)
				case <-ticker.C:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		got := <-output
		if got.err != nil || got.result.Binding != original || got.result.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("expiry relabeled a winning original reservation", got.result.Outcome, got.err)
		}
	})
	for _, committed := range []bool{false, true} {
		name := "rollback"
		if committed {
			name = "committed"
		}
		t.Run(name+"-ack-loss", func(t *testing.T) {
			original, q, caller := newOrigin(name)
			c.requestKeyBegin = func(ctx context.Context) (pgx.Tx, error) {
				tx, err := c.pool.Raw().Begin(ctx)
				return requestKeyCommitFault{Tx: tx, committed: committed}, err
			}
			out, err := c.ExpirePreparedFeatureCommand(ctx, q, caller, input.Feature, owner)
			c.requestKeyBegin = nil
			if !errors.As(err, &unknown) || out.Outcome != identity.CommitOutcomeUnknown || out.Binding != original {
				t.Fatal("commit acknowledgement loss fabricated refusal", err)
			}
			raw, _ := base64.RawURLEncoding.DecodeString(string(original.CommandID))
			var count int
			if err := c.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1`, raw).Scan(&count); err != nil || count != map[bool]int{false: 0, true: 1}[committed] {
				t.Fatal("actual commit outcome disagrees with retained fence", err)
			}
			out, err = c.ExpirePreparedFeatureCommand(ctx, q, caller, input.Feature, owner)
			if err != nil || out.Outcome != identity.CommitOutcomeNotCommitted || out.Binding != original {
				t.Fatal("exact retry could not establish retained refusal", err)
			}
		})
	}
}
