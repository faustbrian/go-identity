//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
)

// The native risk owner and its original issuance/counters are real. This
// domain-effect seam is not the phone workflow, OTP/capability integration or
// proof of the completion journey. The primary owns that separate integration.
type nativeRiskUsePhone struct {
	corruptReservation   bool
	expireBeforeFinalize bool
}

func (*nativeRiskUsePhone) Descriptor() identitypostgres.ContributorDescriptor {
	return (&nativeReservationPhone{}).Descriptor()
}
func (*nativeRiskUsePhone) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{nativeUseOperation()}
}
func (*nativeRiskUsePhone) ValidateFeatureCommand(command identity.Command, p identitypostgres.CommandPlan) error {
	s, ok := command.Feature()
	if !ok || s.Operation != nativeUseOperation() || p.RiskEvidence == nil || len(s.Fields) != 7 {
		return identity.InvalidInputError{Field: "phone"}
	}
	return nil
}
func (p *nativeRiskUsePhone) ApplyFeature(ctx context.Context, w identitypostgres.Work, command identity.Command) (identity.FeatureReceipt, error) {
	s, ok := command.Feature()
	if !ok {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if _, err := w.Exec(ctx, `INSERT INTO public.risk_use_effects(command_id) VALUES($1)`, string(s.Binding.CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.corruptReservation {
		// A domain-time divergence must fail the terminal check and roll this
		// fixture write back with the provisional effect, not finalize it.
		if _, err := w.Exec(ctx, `UPDATE risk_store.issued_evidence SET reservation_generation=reservation_generation+1 WHERE reservation_command_id=$1`, mustNativeUseID(s.Binding.CommandID)); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if p.expireBeforeFinalize {
		if _, err := w.Exec(ctx, `SELECT pg_sleep(0.6)`); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: s.Operation, AfterVersion: 1}, nil
}
func (*nativeRiskUsePhone) RecoverParticipant(context.Context, identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	return identitypostgres.RecoveryUnknown, nil
}

func mustNativeUseID(id identity.CommandID) []byte {
	raw, _ := base64.RawURLEncoding.DecodeString(string(id))
	return raw
}

func testNativeRiskCurrentExecution(t *testing.T, ctx context.Context, pool *database.Pool, executor *Executor) {
	t.Helper()
	history, err := (DurableCounterMigrationSource{Schema: "risk_store", Version: 29}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, history[0].UpSQL()); err != nil {
		t.Fatal("native durable counter schema", err)
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.risk_use_effects(command_id text PRIMARY KEY)`); err != nil {
		t.Fatal("effect fixture schema", err)
	}
	for _, mode := range []string{"committed", "at-limit", "writer-fenced", "rollback", "current-threshold", "missing-original", "corrupt-original", "missing-current", "changed-window", "changed-custody", "foreign-policy", "foreign-keys", "missing-key-history", "no-counters", "generation-diverged", "expired-before-apply", "expired-before-finalize"} {
		t.Run(mode, func(t *testing.T) {
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			var store DurableCounterStore
			at := time.Now().UTC()
			if mode == "expired-before-apply" || mode == "expired-before-finalize" {
				// Existing fixture carrier facts retain their original two-minute
				// interval. A near-expiry authentic observation shortens issuance
				// without editing a signed deadline or fabricating current time.
				at = at.Add(-119500 * time.Millisecond)
			}
			issuer, original, key := issuanceFixtureWithCounters(t, risk.PhoneResetInitiation, at, string(id), executor, false, nil, func(policy risk.Policy, keys []risk.CounterDigestKey) risk.CounterStore {
				var err error
				store, err = NewDurableCounterStore(DurableCounterConfig{Pool: pool, Schema: "risk_store", Namespace: string(id), Policy: policy, Keys: keys, ReplayKey: bytes.Repeat([]byte{0x54}, 32), Tenants: []string{"tenant"}, MaximumRecords: 1000, Timeout: 2 * time.Second})
				if err != nil {
					t.Fatal(err)
				}
				return store
			})
			issued, err := issuer.Evaluate(ctx, original)
			if err != nil || issued.Outcome != risk.EvidenceCommitted {
				t.Fatal("official issuance with native counter authority", err, issued.Outcome)
			}
			var record risk.EvidenceRecord
			var intent, proof, evidence []byte
			var version int64
			if err := pool.Raw().QueryRow(ctx, `SELECT key_version,intent_digest,proof_digest,evidence_digest,issued_at,expires_at FROM risk_store.issued_evidence WHERE command_id=$1`, mustNativeUseID(id)).Scan(&version, &intent, &proof, &evidence, &record.IssuedAt, &record.ExpiresAt); err != nil {
				t.Fatal(err)
			}
			record.KeyVersion, record.Reference = uint32(version), issued.Evidence.Reference
			copy(record.IntentDigest[:], intent)
			copy(record.ProofDigest[:], proof)
			copy(record.EvidenceDigest[:], evidence)
			record.IssuedAt, record.ExpiresAt = record.IssuedAt.UTC(), record.ExpiresAt.UTC()
			consumer, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			use, err := issuer.PrecheckUse(ctx, original, risk.EvidenceUseRequest{CommandID: string(consumer), Actor: "phone-service", Recovery: original.Recovery, Reference: record.Reference}, record)
			if err != nil {
				t.Fatal(err)
			}
			cfg := Config{Schema: "risk_store", PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{key}, EnvelopeKeys: map[string][]byte{"wrapping_v1": wrappingKey(1)}, CurrentEnvelopeKey: "wrapping_v1", UseIssuer: &issuer, UseCounters: &store}
			if mode == "no-counters" {
				cfg.UseCounters = nil
			}
			if mode == "changed-custody" {
				changed := store.state.config
				changed.ReplayKey = bytes.Repeat([]byte{0x55}, 32)
				foreign, err := NewDurableCounterStore(changed)
				if err != nil {
					t.Fatal(err)
				}
				cfg.UseCounters = &foreign
			}
			if mode == "foreign-policy" || mode == "foreign-keys" {
				changed := store.state.config
				if mode == "foreign-policy" {
					changed.Policy = protectedConfig(t).CommandCounters.Policy
				} else {
					foreignKey, err := risk.NewCounterDigestKey(7, wrappingKey(8))
					if err != nil {
						t.Fatal(err)
					}
					changed.Keys = []risk.CounterDigestKey{foreignKey}
				}
				foreign, err := NewDurableCounterStore(changed)
				if err != nil {
					t.Fatal(err)
				}
				cfg.UseCounters = &foreign
			}
			native, err := NewRepository(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if native.CheckRiskEvidence(ctx, identitypostgres.RiskApplyWork{}) == nil || native.FinalizeRiskEvidence(ctx, identitypostgres.RiskFinalizeWork{}) == nil {
				t.Fatal("configured native owner accepted unowned Work")
			}
			op := nativeUseOperation()
			binding := identity.CommandBinding{CommandID: consumer, TenantID: "tenant", UserID: "subject", ActorID: "phone-service", ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "phone-policy", PolicyVersion: 1, RecordID: "phone-record", CorrelationID: string(consumer)}
			command, riskPlan, err := native.PrepareEvidenceUse(identity.FeatureCommandSpec{Binding: binding, Operation: op}, original, use)
			if err != nil {
				t.Fatal(err)
			}
			domain, err := identitypostgres.NewRepository(pool, identitypostgres.Config{MaximumDuration: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			phone := &nativeRiskUsePhone{corruptReservation: mode == "generation-diverged", expireBeforeFinalize: mode == "expired-before-finalize"}
			registry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{domain, &issuanceAudit{}, &issuanceOutbox{fail: mode == "rollback"}, phone, native})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := identitypostgres.NewCoordinator(pool, registry, identitypostgres.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: 5 * time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: issuanceQueryPolicy{}}})
			if err != nil {
				t.Fatal(err)
			}
			builder, _ := audit.NewBuilder(audit.BuilderConfig{})
			seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: "phone.reset", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(binding.ActorID)}, Subject: audit.SubjectInput{Type: "phone", ID: binding.RecordID}, Context: audit.ContextInput{TenantID: "tenant", CorrelationID: binding.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: binding.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(binding.CommandID), "aggregate.type": "phone", "aggregate.id": binding.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := identitypostgres.FeatureAuditBindingDigest(binding, op, "phone", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := coordinator.PrepareCommandPlan(binding, command, identitypostgres.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "phone", Feature: &identitypostgres.FeatureRegistration{Contributor: phone.Descriptor(), Operation: op}, RiskEvidence: &riskPlan, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "phone.reset.v1", AfterVersion: 1}, Audits: []identitypostgres.AuditPlan{{EventType: "phone.reset", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
			if err != nil {
				t.Fatal(err)
			}
			reserved, _, err := coordinator.ReserveCommand(ctx, binding, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "at-limit":
				_, err = pool.Raw().Exec(ctx, `UPDATE risk_store.durable_counter_windows SET value=10 WHERE namespace=$1`, string(id))
			case "current-threshold":
				_, err = pool.Raw().Exec(ctx, `UPDATE risk_store.durable_counter_windows SET value=11 WHERE namespace=$1`, string(id))
			case "missing-original":
				_, err = pool.Raw().Exec(ctx, `DELETE FROM risk_store.durable_counter_attempts WHERE namespace=$1`, string(id))
			case "corrupt-original":
				_, err = pool.Raw().Exec(ctx, `UPDATE risk_store.durable_counter_attempts SET seal=$2 WHERE namespace=$1`, string(id), wrappingKey(8))
			case "missing-current":
				_, err = pool.Raw().Exec(ctx, `DELETE FROM risk_store.durable_counter_aliases WHERE namespace=$1`, string(id))
			case "missing-key-history":
				_, err = pool.Raw().Exec(ctx, `DELETE FROM risk_store.durable_counter_keys WHERE namespace=$1`, string(id))
			case "changed-window":
				_, err = pool.Raw().Exec(ctx, `UPDATE risk_store.durable_counter_windows SET started_at=started_at+interval '1 microsecond',expires_at=expires_at+interval '1 microsecond' WHERE namespace=$1`, string(id))
			}
			if err != nil {
				t.Fatal("counter divergence fixture", err)
			}
			if mode == "expired-before-apply" {
				timer := time.NewTimer(time.Until(record.ExpiresAt) + time.Millisecond)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					t.Fatal("expiry fixture deadline")
				case <-timer.C:
				}
			}
			work, err := coordinator.Begin(ctx, reserved)
			if err != nil {
				t.Fatal("native phases not admitted", err)
			}
			defer coordinator.Abort(work, identity.UnavailableError{})
			result, applyErr := coordinator.ApplyFeature(ctx, work, command)
			var writerResult chan risk.CounterResult
			var writerCommand risk.CounterCommand
			if mode == "writer-fenced" && applyErr == nil {
				counterOwner, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: store.state.config.Policy, Keys: store.state.config.Keys, Store: store, Clock: time.Now, Timeout: 2 * time.Second})
				if err != nil {
					t.Fatal(err)
				}
				writerCommand, err = counterOwner.Prepare(risk.Context{Tenant: "tenant", Operation: original.Recovery.Binding.RecoveryOperation, Attempt: "concurrent-attempt"}, original.Subject, risk.BeforeCredential)
				if err != nil {
					t.Fatal(err)
				}
				writerContext, stopWriter := context.WithTimeout(ctx, 3*time.Second)
				writerResult = make(chan risk.CounterResult, 1)
				var writers sync.WaitGroup
				writers.Add(1)
				defer func() { stopWriter(); writers.Wait() }()
				go func() {
					defer writers.Done()
					result, _ := store.Mutate(writerContext, writerCommand)
					writerResult <- result
				}()
				poll, stopPoll := context.WithTimeout(ctx, time.Second)
				defer stopPoll()
				ticker := time.NewTicker(5 * time.Millisecond)
				defer ticker.Stop()
				for {
					var blocked bool
					if err := pool.Raw().QueryRow(poll, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE a.datname=current_database() AND a.wait_event_type='Lock' AND a.query LIKE '%durable_counter_scopes%' AND cardinality(pg_blocking_pids(a.pid))>0)`).Scan(&blocked); err != nil {
						t.Fatal("counter writer did not reach native lock wait", err)
					}
					if blocked {
						break
					}
					select {
					case <-poll.Done():
						t.Fatal("current use did not fence durable counter writer")
					case <-ticker.C:
					}
				}
			}
			if applyErr == nil {
				result, applyErr = coordinator.Commit(work, result)
			} else {
				result, _ = coordinator.Abort(work, applyErr)
			}
			// Every negative case explicitly aborts (or Commit proves rollback).
			// Kernel Abort supplies terminal release proof after that rollback;
			// unknown recovery below retains reserved instead of using this path.
			wantState, wantEffects := "released", 0
			if mode == "committed" || mode == "at-limit" || mode == "writer-fenced" {
				if applyErr != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("native original did not finalize", applyErr)
				}
				wantState, wantEffects = "finalized", 1
			} else if result.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("divergent current authority lacks proved rollback", applyErr, result.Outcome)
			}
			if writerResult != nil {
				select {
				case written := <-writerResult:
					outcome, counters, err := written.Declaration(writerCommand)
					if err != nil || outcome != risk.CounterCommitted || len(counters) != 4 {
						t.Fatal("fenced writer did not resume after protected commit", err)
					}
					for _, counter := range counters {
						if counter.Value != 2 {
							t.Fatal("current check recharged or reset original counter")
						}
					}
				case <-ctx.Done():
					t.Fatal("fenced writer did not finish")
				}
			}
			var state, generation string
			var issuedAt, expiresAt time.Time
			var effects int
			if err := pool.Raw().QueryRow(ctx, `SELECT state,reservation_generation::text,issued_at,expires_at,(SELECT count(*) FROM public.risk_use_effects WHERE command_id=$2) FROM risk_store.issued_evidence WHERE command_id=$1`, mustNativeUseID(id), string(consumer)).Scan(&state, &generation, &issuedAt, &expiresAt, &effects); err != nil || state != wantState || effects != wantEffects || generation != "1" || !issuedAt.Equal(record.IssuedAt) || !expiresAt.Equal(record.ExpiresAt) {
				t.Fatal("atomic native state or original custody diverged", err, state, generation, effects)
			}
		})
	}
}
