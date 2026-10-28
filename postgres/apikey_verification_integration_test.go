//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// These native and sink seams exercise the real coordinator transaction and
// canonical records, not credential comparison or production adapter wiring.
// The genuine API-key consumer remains a separate required acceptance boundary.
type apiKeyVerificationIntegrationParticipant struct {
	*apiKeyVerificationTestParticipant
	denyFinal        bool
	negativeRecovery bool
}

func (p *apiKeyVerificationIntegrationParticipant) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	if !p.negativeRecovery {
		return RecoveryUnknown, nil
	}
	b, err := w.Scope()
	if err != nil {
		return RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, `SELECT version=7 AND permissions='read write' FROM public.identity_test_api_key_versions WHERE key_id=$1`, string(b.ActorID))
	if err != nil {
		return RecoveryUnknown, err
	}
	defer rows.Close()
	var unchanged bool
	if !rows.Next() || rows.Scan(&unchanged) != nil || rows.Next() || rows.Err() != nil {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	if unchanged {
		return RecoveryNotCommitted, nil
	}
	return RecoveryUnknown, nil
}

func (p *apiKeyVerificationIntegrationParticipant) ApplyAPIKeyVerification(ctx context.Context, w Work, command identity.Command) (identity.FeatureReceipt, APIKeyVerificationOutcome, error) {
	if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
		return identity.FeatureReceipt{}, APIKeyVerificationOutcome{}, err
	}
	spec, _ := command.Feature()
	if p.outcome.PermissionsChanged {
		count, err := w.Exec(ctx, `UPDATE public.identity_test_api_key_versions SET version=8,permissions='read' WHERE key_id=$1 AND version=7`, string(spec.Binding.ActorID))
		if err != nil || count != 1 {
			return identity.FeatureReceipt{}, APIKeyVerificationOutcome{}, identity.ConflictError{}
		}
	}
	p.verificationCalls++
	return identity.FeatureReceipt{Operation: spec.Operation}, p.outcome, nil
}

func (p *apiKeyVerificationIntegrationParticipant) CheckFeatureCommit(_ context.Context, w Work, command identity.Command) error {
	binding, feature, _, err := w.FeatureScope(p)
	spec, _ := command.Feature()
	if err != nil || binding != spec.Binding || feature.Operation != spec.Operation {
		return invalidWork()
	}
	if p.denyFinal {
		return identity.ForbiddenError{}
	}
	return nil
}

type apiKeyVerificationAuditPhase struct {
	fail             bool
	cancel           context.CancelFunc
	negativeRecovery bool
}

func (*apiKeyVerificationAuditPhase) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "audit/postgres", ContractID: "identity.security_audit", Version: 1}
}

func (p *apiKeyVerificationAuditPhase) PersistAudits(ctx context.Context, w Work) error {
	records, err := w.StagedAudits()
	if err != nil {
		return err
	}
	for _, record := range records {
		wire, err := audit.CanonicalJSON(record.Record)
		if err != nil {
			return err
		}
		if _, err := w.Exec(ctx, `INSERT INTO public.identity_test_api_key_audits(command_id,event_index,record) VALUES($1,$2,$3)`, string(w.state.binding.CommandID), int64(record.Plan.EventIndex), wire); err != nil {
			return err
		}
	}
	if p.cancel != nil {
		p.cancel()
	}
	if p.fail {
		return identity.UnavailableError{}
	}
	return nil
}

func (p *apiKeyVerificationAuditPhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	if !p.negativeRecovery {
		return RecoveryUnknown, nil
	}
	return apiKeyVerificationRecoverAbsence(ctx, w, `SELECT EXISTS(SELECT 1 FROM public.identity_test_api_key_audits WHERE command_id=$1)`)
}

type apiKeyVerificationLifecyclePhase struct{ fail, negativeRecovery bool }

func (*apiKeyVerificationLifecyclePhase) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}
}

func (p *apiKeyVerificationLifecyclePhase) PersistLifecycle(ctx context.Context, w Work) error {
	records, err := w.StagedLifecycle()
	if err != nil {
		return err
	}
	for _, record := range records {
		if _, err := w.Exec(ctx, `INSERT INTO public.identity_test_api_key_lifecycle(command_id,event_type,subject_id,before_version,after_version) VALUES($1,$2,$3,$4,$5)`, string(record.CommandID), record.EventType, record.SubjectID, strconv.FormatUint(record.BeforeVersion, 10), strconv.FormatUint(record.AfterVersion, 10)); err != nil {
			return err
		}
	}
	if p.fail {
		return identity.UnavailableError{}
	}
	return nil
}

func (p *apiKeyVerificationLifecyclePhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	if !p.negativeRecovery {
		return RecoveryUnknown, nil
	}
	return apiKeyVerificationRecoverAbsence(ctx, w, `SELECT EXISTS(SELECT 1 FROM public.identity_test_api_key_lifecycle WHERE command_id=$1)`)
}

func apiKeyVerificationRecoverAbsence(ctx context.Context, w RecoveryWork, query string) (RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil {
		return RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, query, string(b.CommandID))
	if err != nil {
		return RecoveryUnknown, err
	}
	defer rows.Close()
	var exists bool
	if !rows.Next() || rows.Scan(&exists) != nil || rows.Next() || rows.Err() != nil {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	if exists {
		return RecoveryUnknown, nil
	}
	return RecoveryNotCommitted, nil
}

func testAPIKeyVerification(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.identity_test_api_key_versions(key_id text PRIMARY KEY,version integer NOT NULL,permissions text NOT NULL);
CREATE TABLE public.identity_test_api_key_audits(command_id text,event_index integer,record bytea NOT NULL,PRIMARY KEY(command_id,event_index));
CREATE TABLE public.identity_test_api_key_lifecycle(command_id text PRIMARY KEY,event_type text,subject_id text,before_version text,after_version text);`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		anonymous bool
		outcome   APIKeyVerificationOutcome
		failure   string
	}{
		{"allowed", false, APIKeyVerificationOutcome{Authenticated: true}, ""},
		{"denied", false, APIKeyVerificationOutcome{}, ""},
		{"unknown-denied", true, APIKeyVerificationOutcome{}, ""},
		{"narrow-allowed", false, APIKeyVerificationOutcome{Authenticated: true, PermissionsChanged: true}, ""},
		{"narrow-denied", false, APIKeyVerificationOutcome{PermissionsChanged: true}, ""},
		{"audit-failure", false, APIKeyVerificationOutcome{Authenticated: true, PermissionsChanged: true}, "audit"},
		{"outbox-failure", false, APIKeyVerificationOutcome{Authenticated: true, PermissionsChanged: true}, "outbox"},
		{"final-authority-denial", false, APIKeyVerificationOutcome{Authenticated: true, PermissionsChanged: true}, "final"},
		{"cancel-after-audit", false, APIKeyVerificationOutcome{Authenticated: true, PermissionsChanged: true}, "cancel"},
		{"commit-not-sent", false, APIKeyVerificationOutcome{Authenticated: true, PermissionsChanged: true}, "commit-before"},
		{"commit-acknowledgement-lost", false, APIKeyVerificationOutcome{Authenticated: true, PermissionsChanged: true}, "commit-after"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attemptCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			native := &apiKeyVerificationIntegrationParticipant{apiKeyVerificationTestParticipant: &apiKeyVerificationTestParticipant{outcome: tc.outcome}, denyFinal: tc.failure == "final"}
			auditing, lifecycle := &apiKeyVerificationAuditPhase{fail: tc.failure == "audit"}, &apiKeyVerificationLifecyclePhase{fail: tc.failure == "outbox"}
			if tc.failure == "cancel" {
				auditing.cancel = cancel
			}
			registry, err := NewContributorRegistry([]Contributor{repo, auditing, lifecycle, native})
			if err != nil {
				t.Fatal(err)
			}
			executionPool := pool
			var fault *registrationCommitFault
			if tc.failure == "commit-before" || tc.failure == "commit-after" {
				fault = &registrationCommitFault{before: tc.failure == "commit-before", marker: []byte("public.identity_test_api_key_audits(")}
				var name string
				if err := pool.Raw().QueryRow(ctx, `SELECT current_database()`).Scan(&name); err != nil {
					t.Fatal(err)
				}
				executionPool, err = database.Connect(ctx, database.Config{DSN: os.Getenv("IDENTITY_POSTGRES_TEST_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
					c.ConnConfig.Database = name
					c.ConnConfig.DialFunc = fault.dial
					return nil
				}})
				if err != nil {
					t.Fatal("owned fault pool", err)
				}
				defer func() {
					bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					if err := executionPool.Close(bounded); err != nil {
						t.Error("fault pool cleanup", err)
					}
				}()
			}
			config := CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			})}}
			c, err := NewCoordinator(executionPool, registry, config)
			if err != nil {
				t.Fatal(err)
			}
			b, p := apiKeyVerificationPlanFixture(t, tc.anonymous)
			b.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			target := "key-" + string(b.CommandID)
			if tc.anonymous {
				b.AnonymousFlowID = string(b.CommandID)
				target = b.AnonymousFlowID
			} else {
				b.ActorID = identity.ActorID(target)
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.identity_test_api_key_versions VALUES($1,7,'read write')`, target); err != nil {
					t.Fatal(err)
				}
			}
			p.Contributors = registry.Descriptors()
			for i := range p.Audits {
				record, err := securityMutationAudit(ctx, b, 0, 0, time.Now().UTC().Truncate(time.Microsecond), "denied", p.Audits[i].EventType, p.SubjectType, target, "protected", true)
				if err != nil {
					t.Fatal(err)
				}
				p.Audits[i].BindingDigest, err = FeatureAuditBindingDigest(b, p.Feature.Operation, p.SubjectType, record)
				if err != nil {
					t.Fatal(err)
				}
			}
			command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: p.Feature.Operation})
			p, err = c.PrepareCommandPlan(b, command, p)
			if err != nil {
				t.Fatal("verification plan", err)
			}
			r, receipt, err := c.ReserveCommand(ctx, b, command, p)
			if err != nil || r.state == nil || receipt.Outcome != identity.CommitOutcomeInProgress {
				t.Fatal("verification reservation", err)
			}
			w, err := c.Begin(attemptCtx, r)
			if err != nil {
				t.Fatal("verification Begin", err)
			}
			defer func() { _, _ = c.Abort(w, identity.UnavailableError{}) }()
			provisional, err := c.ApplyFeature(attemptCtx, w, command)
			if err != nil {
				t.Fatal("verification Apply", err)
			}
			committed, err := c.Commit(w, provisional)
			if fault != nil {
				if err == nil || committed.Outcome != identity.CommitOutcomeUnknown || !fault.hit.Load() {
					t.Fatal("lost acknowledgement fabricated success/rollback or fault missed target", committed.Outcome, err)
				}
				wantVersion, wantAudits, wantEvents := 7, 0, 0
				wantOutcome := identity.CommitOutcomeInProgress
				if !fault.before {
					wantVersion, wantAudits, wantEvents, wantOutcome = 8, 2, 1, identity.CommitOutcomeCommitted
				}
				var version, audits, events int
				if err := pool.Raw().QueryRow(ctx, `SELECT version,(SELECT count(*) FROM public.identity_test_api_key_audits WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_api_key_lifecycle WHERE command_id=$1) FROM public.identity_test_api_key_versions WHERE key_id=$2`, string(b.CommandID), target).Scan(&version, &audits, &events); err != nil || version != wantVersion || audits != wantAudits || events != wantEvents {
					t.Fatalf("ambiguous commit split protected effects: %d/%d/%d: %v", version, audits, events, err)
				}
				fresh, err := NewCoordinator(pool, registry, config)
				if err != nil {
					t.Fatal(err)
				}
				query, caller := queryInputs(b)
				for range 2 {
					original, err := fresh.RecoverCommand(ctx, query, caller)
					if err != nil || original.Validate() != nil || original.Outcome != wantOutcome || original.Binding != b || native.verificationCalls != 1 {
						t.Fatal("fresh recovery reran comparison or fabricated terminal authority", original.Outcome, err)
					}
				}
				if fault.before {
					id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
					if err != nil {
						t.Fatal(err)
					}
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
						t.Fatal(err)
					}
					negative, err := NewContributorRegistry([]Contributor{repo, &apiKeyVerificationAuditPhase{negativeRecovery: true}, &apiKeyVerificationLifecyclePhase{negativeRecovery: true}, &apiKeyVerificationIntegrationParticipant{apiKeyVerificationTestParticipant: &apiKeyVerificationTestParticipant{}, negativeRecovery: true}})
					if err != nil {
						t.Fatal(err)
					}
					fresh, err = NewCoordinator(pool, negative, config)
					if err != nil {
						t.Fatal(err)
					}
					for range 2 {
						original, err := fresh.RecoverCommand(ctx, query, caller)
						var unavailable identity.UnavailableError
						if !errors.As(err, &unavailable) || original.Outcome != identity.CommitOutcomeNotCommitted || original.Binding != b {
							t.Fatal("expired unanimous negative evidence could not close original verification", original.Outcome, err)
						}
					}
					var recoveryWire []byte
					if err := pool.Raw().QueryRow(ctx, `SELECT count(*),min(event_index) FROM public.identity_test_api_key_audits WHERE command_id=$1`, string(b.CommandID)).Scan(&audits, &events); err != nil || audits != 1 || events != 0 {
						t.Fatal("negative recovery invented update audit", err)
					}
					if err := pool.Raw().QueryRow(ctx, `SELECT record FROM public.identity_test_api_key_audits WHERE command_id=$1`, string(b.CommandID)).Scan(&recoveryWire); err != nil {
						t.Fatal(err)
					}
					record, err := audit.ParseCanonicalJSON(recoveryWire, securityAuditLimits())
					if err != nil || record.Action() != "identity.api_key.authenticate" || record.Outcome() != audit.OutcomeFailed {
						t.Fatal("negative recovery reported successful authentication/update", err)
					}
				}
				return
			}
			if tc.failure != "" {
				expected := identity.CommitOutcomeNotCommitted
				wantAudits := 1
				if tc.failure == "audit" {
					expected, wantAudits = identity.CommitOutcomeUnknown, 0
				}
				if err == nil || committed.Outcome != expected {
					t.Fatal("failed required phase fabricated a durable verification outcome", committed.Outcome, err)
				}
				var audits, events, version int
				var permissions string
				if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_test_api_key_audits WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_api_key_lifecycle WHERE command_id=$1),version,permissions FROM public.identity_test_api_key_versions WHERE key_id=$2`, string(b.CommandID), target).Scan(&audits, &events, &version, &permissions); err != nil || audits != wantAudits || events != 0 || version != 7 || permissions != "read write" {
					t.Fatalf("required phase failure left partial Narrow/effects: %d/%d/%d: %v", audits, events, version, err)
				}
				if wantAudits == 1 {
					var wire []byte
					if err := pool.Raw().QueryRow(ctx, `SELECT record FROM public.identity_test_api_key_audits WHERE command_id=$1 AND event_index=0`, string(b.CommandID)).Scan(&wire); err != nil {
						t.Fatal(err)
					}
					record, err := audit.ParseCanonicalJSON(wire, securityAuditLimits())
					expectedOutcome := audit.OutcomeFailed
					if tc.failure == "final" {
						expectedOutcome = audit.OutcomeDenied
					}
					if err != nil || record.Action() != "identity.api_key.authenticate" || record.Outcome() != expectedOutcome || record.Attributes()["aggregate.before_version"] != "0" || record.Attributes()["aggregate.after_version"] != "0" {
						t.Fatal("rollback invented a successful key update or authentication", err)
					}
				}
				return
			}
			if err != nil || committed.Outcome != identity.CommitOutcomeCommitted || committed.Feature == nil || committed.Feature.BeforeVersion != 0 || committed.Feature.AfterVersion != 0 {
				t.Fatal("verification commit invented mutation or lost durable attempt", err)
			}
			var wire []byte
			if err := pool.Raw().QueryRow(ctx, `SELECT record FROM public.identity_test_api_key_audits WHERE command_id=$1 AND event_index=0`, string(b.CommandID)).Scan(&wire); err != nil {
				t.Fatal(err)
			}
			authentication, err := audit.ParseCanonicalJSON(wire, securityAuditLimits())
			expected := audit.OutcomeDenied
			if tc.outcome.Authenticated {
				expected = audit.OutcomeSucceeded
			}
			if err != nil || authentication.Outcome() != expected || authentication.Subject().ID() != target || authentication.Subject().Type() != p.SubjectType || authentication.Attributes()["aggregate.before_version"] != "0" || authentication.Attributes()["aggregate.after_version"] != "0" {
				t.Fatal("durable authentication audit conflated commit, owner or key mutation", err)
			}
			var audits, events int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_test_api_key_audits WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_api_key_lifecycle WHERE command_id=$1)`, string(b.CommandID)).Scan(&audits, &events); err != nil {
				t.Fatal(err)
			}
			if !tc.outcome.PermissionsChanged {
				if audits != 1 || events != 0 {
					t.Fatalf("ordinary verification invented update/lifecycle: %d/%d", audits, events)
				}
			} else {
				var event, subject, before, after string
				if err := pool.Raw().QueryRow(ctx, `SELECT event_type,subject_id,before_version,after_version FROM public.identity_test_api_key_lifecycle WHERE command_id=$1`, string(b.CommandID)).Scan(&event, &subject, &before, &after); err != nil || audits != 2 || events != 1 || event != "api_key.permissions_changed.v1" || subject != target || before != "7" || after != "8" {
					t.Fatal("permission reduction lost its exact independent mutation effect", err)
				}
				if err := pool.Raw().QueryRow(ctx, `SELECT record FROM public.identity_test_api_key_audits WHERE command_id=$1 AND event_index=1`, string(b.CommandID)).Scan(&wire); err != nil {
					t.Fatal(err)
				}
				update, err := audit.ParseCanonicalJSON(wire, securityAuditLimits())
				if err != nil || authentication.Context().CausationID() != string(b.CommandID) || update.Context().CausationID() == "" || update.Context().CausationID() == authentication.Context().CausationID() || update.Context().CorrelationID() != authentication.Context().CorrelationID() {
					t.Fatal("durable composed records lost distinct causation/shared original correlation", err)
				}
			}
			if !tc.anonymous {
				version, grant := 7, "read write"
				if tc.outcome.PermissionsChanged {
					version, grant = 8, "read"
				}
				var storedVersion int
				var storedGrant string
				if err := pool.Raw().QueryRow(ctx, `SELECT version,permissions FROM public.identity_test_api_key_versions WHERE key_id=$1`, target).Scan(&storedVersion, &storedGrant); err != nil || storedVersion != version || storedGrant != grant {
					t.Fatal("read-only verification mutated state or committed Narrow was lost", err)
				}
			}
			if reservation, original, err := c.ReserveCommand(ctx, b, command, p); err != nil || reservation.state != nil || original.AuditEventID != committed.AuditEventID || original.Outcome != committed.Outcome || native.verificationCalls != 1 {
				t.Fatal("original attempt replay re-executed or changed durable history", err)
			}
			changed, _ := command.Feature()
			changed.Fields = []identity.FeatureField{{Name: "verification.intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte("different committed verification intent")}}}
			conflicting := featureCodecCommand(t, changed)
			changedPlan, err := c.PrepareCommandPlan(b, conflicting, p)
			if err != nil {
				t.Fatal("changed structural intent could not reach claim conflict", err)
			}
			reservation, conflictResult, err := c.ReserveCommand(ctx, b, conflicting, changedPlan)
			var conflict identity.ConflictError
			if !errors.As(err, &conflict) || reservation.state != nil || conflictResult.Outcome != identity.CommitOutcomeConflict || native.verificationCalls != 1 {
				t.Fatal("original verification attempt ID accepted changed fingerprint or repeated comparison", err)
			}
		})
	}
	t.Run("competing-permission-reductions", func(t *testing.T) {
		testAPIKeyVerificationNarrowContention(t, ctx, pool, repo)
	})
}

func testAPIKeyVerificationNarrowContention(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	target := "key-" + string(id)
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.identity_test_api_key_versions VALUES($1,7,'read write')`, target); err != nil {
		t.Fatal(err)
	}
	type attempt struct {
		coordinator *Coordinator
		reservation Reservation
		command     identity.Command
		native      *apiKeyVerificationIntegrationParticipant
	}
	var attempts [2]attempt
	for i := range attempts {
		native := &apiKeyVerificationIntegrationParticipant{apiKeyVerificationTestParticipant: &apiKeyVerificationTestParticipant{outcome: APIKeyVerificationOutcome{Authenticated: true, PermissionsChanged: true}}}
		registry, err := NewContributorRegistry([]Contributor{repo, &apiKeyVerificationAuditPhase{}, &apiKeyVerificationLifecyclePhase{}, native})
		if err != nil {
			t.Fatal(err)
		}
		coordinator, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		})}})
		if err != nil {
			t.Fatal(err)
		}
		binding, plan := apiKeyVerificationPlanFixture(t, false)
		binding.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		binding.ActorID = identity.ActorID(target)
		plan.Contributors = registry.Descriptors()
		for j := range plan.Audits {
			record, err := securityMutationAudit(ctx, binding, 0, 0, time.Now().UTC().Truncate(time.Microsecond), "denied", plan.Audits[j].EventType, plan.SubjectType, target, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			plan.Audits[j].BindingDigest, err = FeatureAuditBindingDigest(binding, plan.Feature.Operation, plan.SubjectType, record)
			if err != nil {
				t.Fatal(err)
			}
		}
		command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: binding, Operation: plan.Feature.Operation})
		plan, err = coordinator.PrepareCommandPlan(binding, command, plan)
		if err != nil {
			t.Fatal(err)
		}
		reservation, result, err := coordinator.ReserveCommand(ctx, binding, command, plan)
		if err != nil || reservation.state == nil || result.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("independent verification reservation", err)
		}
		attempts[i] = attempt{coordinator, reservation, command, native}
	}
	type outcome struct {
		result identity.CommandResult
		err    error
	}
	start, results := make(chan struct{}), make(chan outcome, len(attempts))
	for _, attempt := range attempts {
		go func() {
			<-start
			work, err := attempt.coordinator.Begin(ctx, attempt.reservation)
			if err != nil {
				results <- outcome{err: err}
				return
			}
			provisional, err := attempt.coordinator.ApplyFeature(ctx, work, attempt.command)
			if err != nil {
				result, abortErr := attempt.coordinator.Abort(work, err)
				results <- outcome{result, abortErr}
				return
			}
			result, err := attempt.coordinator.Commit(work, provisional)
			results <- outcome{result, err}
		}()
	}
	close(start)
	winners, conflicts := 0, 0
	for range attempts {
		out := <-results
		var conflict identity.ConflictError
		switch {
		case out.err == nil && out.result.Outcome == identity.CommitOutcomeCommitted:
			winners++
		case errors.As(out.err, &conflict) && out.result.Outcome == identity.CommitOutcomeNotCommitted:
			conflicts++
		default:
			t.Errorf("competing reduction returned an unproved disposition: %v, %v", out.result.Outcome, out.err)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatalf("expected one protected Narrow and one proven rollback, got %d/%d", winners, conflicts)
	}
	var version, audits, updates, events int
	var permissions string
	if err := pool.Raw().QueryRow(ctx, `SELECT version,permissions,(SELECT count(*) FROM public.identity_test_api_key_audits WHERE record IS NOT NULL AND command_id IN ($2,$3)),(SELECT count(*) FROM public.identity_test_api_key_audits WHERE event_index=1 AND command_id IN ($2,$3)),(SELECT count(*) FROM public.identity_test_api_key_lifecycle WHERE command_id IN ($2,$3)) FROM public.identity_test_api_key_versions WHERE key_id=$1`, target, string(attempts[0].reservation.state.request.commandID), string(attempts[1].reservation.state.request.commandID)).Scan(&version, &permissions, &audits, &updates, &events); err != nil || version != 8 || permissions != "read" || audits != 3 || updates != 1 || events != 1 {
		t.Fatalf("contention duplicated or split Narrow effects: version=%d, audits=%d, updates=%d, events=%d: %v", version, audits, updates, events, err)
	}
	if attempts[0].native.verificationCalls+attempts[1].native.verificationCalls != 1 {
		t.Fatal("conflicting reduction proceeded past protected version comparison")
	}
}
