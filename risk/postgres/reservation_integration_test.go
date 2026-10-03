//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
)

// The test-only phone participant never applies a domain mutation. Native risk
// issuance/reservation and coordinator SQL are real; this proves neither the
// phone workflow nor its eventual OTP/capability/domain phases.
type nativeReservationPhone struct{ noncommit bool }

func (*nativeReservationPhone) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}
}
func (*nativeReservationPhone) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{{Owner: "identity/phone", OperationID: "identity.phone.password-reset-request", SchemaID: "identity.phone.password-reset-request.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}}
}
func (*nativeReservationPhone) ValidateFeatureCommand(c identity.Command, p identitypostgres.CommandPlan) error {
	s, ok := c.Feature()
	if !ok || s.Operation != (&nativeReservationPhone{}).FeatureOperations()[0] || p.RiskEvidence == nil || len(s.Fields) != 1 || s.Fields[0].Name != "risk.intent" || s.Fields[0].Value.Kind != identity.FeatureBytes || string(s.Fields[0].Value.Bytes) != string(p.RiskEvidence.IntentDigest[:]) {
		return identity.InvalidInputError{Field: "phone"}
	}
	return nil
}
func (*nativeReservationPhone) ApplyFeature(context.Context, identitypostgres.Work, identity.Command) (identity.FeatureReceipt, error) {
	return identity.FeatureReceipt{}, identity.UnavailableError{}
}
func (p *nativeReservationPhone) RecoverParticipant(context.Context, identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	if p.noncommit {
		return identitypostgres.RecoveryNotCommitted, nil
	}
	return identitypostgres.RecoveryUnknown, nil
}

func nativeRecoveryCoordinator(t *testing.T, pool *database.Pool, native *Repository, phone *nativeReservationPhone, auditing *issuanceAudit) *identitypostgres.Coordinator {
	t.Helper()
	domain, err := identitypostgres.NewRepository(pool, identitypostgres.Config{MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{domain, auditing, &issuanceOutbox{}, phone, native})
	if err != nil {
		t.Fatal(err)
	}
	c, err := identitypostgres.NewCoordinator(pool, registry, identitypostgres.CoordinatorConfig{MaximumDuration: 4 * time.Second, LeaseDuration: 5 * time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: issuanceQueryPolicy{}}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func testNativeRiskReservation(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository, executor *Executor) {
	t.Helper()
	setupAt := func(t *testing.T, at time.Time) (risk.PhoneEvidenceIssuer, risk.PhoneEvidenceRequest, risk.EvidenceRecord) {
		t.Helper()
		id, _ := identity.NewCommandID()
		issuer, original, _ := issuanceFixture(t, risk.PhoneResetInitiation, at, string(id), executor, false, nil)
		result, err := issuer.Evaluate(ctx, original)
		if err != nil || result.Outcome != risk.EvidenceCommitted {
			t.Fatal("official issuance failed", err)
		}
		// Inspect native custody only in the test. No public bearer-read API is
		// introduced; the consuming workflow will use the owned orchestration.
		var record risk.EvidenceRecord
		var intent, proof, evidence []byte
		var key int64
		raw, _ := base64.RawURLEncoding.DecodeString(string(id))
		if err := pool.Raw().QueryRow(ctx, `SELECT key_version,intent_digest,proof_digest,evidence_digest,issued_at,expires_at FROM risk_store.issued_evidence WHERE command_id=$1`, raw).Scan(&key, &intent, &proof, &evidence, &record.IssuedAt, &record.ExpiresAt); err != nil {
			t.Fatal(err)
		}
		record.KeyVersion = uint32(key)
		copy(record.IntentDigest[:], intent)
		copy(record.ProofDigest[:], proof)
		copy(record.EvidenceDigest[:], evidence)
		record.Reference = result.Evidence.Reference
		record.IssuedAt, record.ExpiresAt = record.IssuedAt.UTC(), record.ExpiresAt.UTC()
		check, _, _ := issuanceFixture(t, risk.PhoneResetInitiation, time.Now().UTC(), string(id), executor, true, nil)
		return check, original, record
	}
	setup := func(t *testing.T) (risk.PhoneEvidenceIssuer, risk.PhoneEvidenceRequest, risk.EvidenceRecord) {
		return setupAt(t, time.Now().UTC().Truncate(time.Microsecond).Add(-100*time.Millisecond))
	}
	prepare := func(t *testing.T, native *Repository, issuer risk.PhoneEvidenceIssuer, original risk.PhoneEvidenceRequest, record risk.EvidenceRecord, noncommit ...bool) (*identitypostgres.Coordinator, identity.CommandBinding, identity.Command, identitypostgres.CommandPlan) {
		t.Helper()
		id, _ := identity.NewCommandID()
		use, err := issuer.PrecheckUse(ctx, original, risk.EvidenceUseRequest{CommandID: string(id), Actor: "phone-service", Recovery: original.Recovery, Reference: record.Reference}, record)
		if err != nil {
			t.Fatal("core precheck", err)
		}
		p := use.Prepared()
		r := nativeUsePlan(p)
		phone := &nativeReservationPhone{}
		if len(noncommit) == 1 {
			phone.noncommit = noncommit[0]
		}
		op := phone.FeatureOperations()[0]
		b := identity.CommandBinding{CommandID: id, TenantID: "tenant", UserID: "subject", ActorID: "phone-service", ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "phone-policy", PolicyVersion: 1, RecordID: "phone-record", CorrelationID: string(id)}
		command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{bytesField("risk.intent", r.IntentDigest)}})
		if err != nil {
			t.Fatal(err)
		}
		domain, err := identitypostgres.NewRepository(pool, identitypostgres.Config{MaximumDuration: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		registry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{domain, &issuanceAudit{}, &issuanceOutbox{}, phone, native})
		if err != nil {
			t.Fatal(err)
		}
		coordinator, err := identitypostgres.NewCoordinator(pool, registry, identitypostgres.CoordinatorConfig{MaximumDuration: 4 * time.Second, LeaseDuration: 5 * time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: issuanceQueryPolicy{}}})
		if err != nil {
			t.Fatal(err)
		}
		builder, _ := audit.NewBuilder(audit.BuilderConfig{})
		seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: "phone.reset", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "phone", ID: b.RecordID}, Context: audit.ContextInput{TenantID: "tenant", CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "phone", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
		if err != nil {
			t.Fatal(err)
		}
		digest, err := identitypostgres.FeatureAuditBindingDigest(b, op, "phone", seed)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := coordinator.PrepareCommandPlan(b, command, identitypostgres.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "phone", Feature: &identitypostgres.FeatureRegistration{Contributor: phone.Descriptor(), Operation: op}, RiskEvidence: &r, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "phone.reset.v1", AfterVersion: 1}, Audits: []identitypostgres.AuditPlan{{EventType: "phone.reset", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
		if err != nil {
			t.Fatal("native reservation preparation", err)
		}
		return coordinator, b, command, plan
	}
	assertOwned := func(t *testing.T, b identity.CommandBinding, r identitypostgres.RiskEvidencePlan, generation string) {
		t.Helper()
		raw, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		var commandGen, nativeGen string
		var same bool
		if err := pool.Raw().QueryRow(ctx, `SELECT c.generation::text,e.reservation_generation::text,e.reservation_command_id=c.command_id AND e.reservation_fingerprint=claim.fingerprint AND e.expires_at=$3 AND e.state='reserved' FROM identity.commands c JOIN identity.identity_command_id_claims claim ON claim.command_id=c.command_id JOIN risk_store.issued_evidence e ON e.reservation_command_id=c.command_id WHERE c.command_id=$1 AND e.evidence_digest=$2`, raw, r.EvidenceDigest[:], r.ExpiresAt).Scan(&commandGen, &nativeGen, &same); err != nil || !same || commandGen != generation || nativeGen != generation {
			t.Fatal("native and coordinator ownership diverged", err, commandGen, nativeGen)
		}
	}
	assertNoCommand := func(t *testing.T, b identity.CommandBinding) {
		t.Helper()
		raw, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		var count int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1`, raw).Scan(&count); err != nil || count != 0 {
			t.Fatal("failed reservation left command prefix", err)
		}
	}
	mutate := func(t *testing.T, sql string, args ...any) {
		t.Helper()
		if _, err := pool.Raw().Exec(ctx, sql, args...); err != nil {
			t.Fatal("fixture mutation failed", err)
		}
	}
	t.Run("native-terminal-release", func(t *testing.T) {
		for _, mode := range []string{"release", "live", "expired-release", "expired-unknown", "unknown-phone", "wrong-generation", "wrong-fingerprint", "wrong-proof", "wrong-expiry", "missing", "terminal", "audit-failure", "sql-failure", "policy-change", "retired-key", "unresolved-issuance"} {
			t.Run(mode, func(t *testing.T) {
				var issuer risk.PhoneEvidenceIssuer
				var original risk.PhoneEvidenceRequest
				var record risk.EvidenceRecord
				if mode == "expired-release" || mode == "expired-unknown" {
					issuer, original, record = setupAt(t, time.Now().UTC().Truncate(time.Microsecond).Add(-28*time.Second))
				} else {
					issuer, original, record = setup(t)
				}
				c, b, command, p := prepare(t, repo, issuer, original, record, true)
				if _, _, err := c.ReserveCommand(ctx, b, command, p); err != nil {
					t.Fatal(err)
				}
				id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
				if mode != "live" {
					mutate(t, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id)
				}
				native := repo
				if mode == "policy-change" || mode == "retired-key" {
					copied := *repo
					native = &copied
					if mode == "policy-change" {
						native.policy++
					} else {
						key, _ := risk.NewEvidenceKey(2, wrappingKey(6), wrappingKey(7))
						native.keys = []risk.EvidenceKey{key}
					}
				}
				c = nativeRecoveryCoordinator(t, pool, native, &nativeReservationPhone{noncommit: mode != "unknown-phone" && mode != "expired-unknown"}, &issuanceAudit{fail: mode == "audit-failure"})
				issuedID, _ := base64.RawURLEncoding.DecodeString(original.CommandID)
				switch mode {
				case "wrong-generation":
					mutate(t, `UPDATE risk_store.issued_evidence SET reservation_generation=7 WHERE command_id=$1`, issuedID)
				case "wrong-fingerprint":
					mutate(t, `UPDATE risk_store.issued_evidence SET reservation_fingerprint=$2 WHERE command_id=$1`, issuedID, wrappingKey(8))
				case "wrong-proof":
					mutate(t, `UPDATE risk_store.issued_evidence SET proof_digest=$2 WHERE command_id=$1`, issuedID, wrappingKey(8))
				case "wrong-expiry":
					mutate(t, `UPDATE risk_store.issued_evidence SET expires_at=expires_at+interval '1 microsecond' WHERE command_id=$1`, issuedID)
				case "missing":
					mutate(t, `DELETE FROM risk_store.issued_evidence WHERE command_id=$1`, issuedID)
				case "terminal":
					mutate(t, `UPDATE risk_store.issued_evidence SET state='finalized' WHERE command_id=$1`, issuedID)
				case "unresolved-issuance":
					mutate(t, `UPDATE identity.commands SET state='pending',result_version=NULL,terminal_class=NULL,result=NULL,terminal_at=NULL WHERE command_id=$1`, issuedID)
				case "sql-failure":
					mutate(t, `ALTER TABLE risk_store.issued_evidence ADD CONSTRAINT test_release_failure CHECK(state<>'released') NOT VALID`)
				}
				if mode == "expired-release" || mode == "expired-unknown" {
					mutate(t, `SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM ($1::timestamptz-clock_timestamp())))+0.02)`, record.ExpiresAt)
				}
				snapshot := func() string {
					var snap string
					if err := pool.Raw().QueryRow(ctx, `SELECT row_to_json(c)::text||COALESCE((SELECT row_to_json(e)::text FROM risk_store.issued_evidence e WHERE evidence_digest=$2),'missing') FROM identity.commands c WHERE command_id=$1`, id, p.RiskEvidence.EvidenceDigest[:]).Scan(&snap); err != nil {
						t.Fatal(err)
					}
					return snap
				}
				before := snapshot()
				q := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
				caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
				result, err := c.RecoverCommand(ctx, q, caller)
				var audits, effects int
				if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.risk_audit WHERE command_id=$1),(SELECT count(*) FROM public.risk_outbox WHERE command_id=$1)`, string(b.CommandID)).Scan(&audits, &effects); e != nil {
					t.Fatal(e)
				}
				if mode == "sql-failure" {
					mutate(t, `ALTER TABLE risk_store.issued_evidence DROP CONSTRAINT test_release_failure`)
				}
				if mode != "release" && mode != "expired-release" && mode != "policy-change" {
					if result.Outcome != identity.CommitOutcomeInProgress || snapshot() != before || audits != 0 || effects != 0 {
						t.Fatal("unproved native recovery changed custody", err, result.Outcome, audits, effects)
					}
					return
				}
				if result.Outcome != identity.CommitOutcomeNotCommitted || audits != 1 || effects != 0 {
					t.Fatal("native noncommit did not release", err, result.Outcome)
				}
				var state, generation string
				if e := pool.Raw().QueryRow(ctx, `SELECT state,reservation_generation::text FROM risk_store.issued_evidence WHERE evidence_digest=$1`, p.RiskEvidence.EvidenceDigest[:]).Scan(&state, &generation); e != nil || state != "released" || generation != "2" {
					t.Fatal("native release state", e, state, generation)
				}
				after := snapshot()
				replayed, replayErr := c.RecoverCommand(ctx, q, caller)
				var unavailable identity.UnavailableError
				if !errors.As(replayErr, &unavailable) || replayed.Outcome != result.Outcome || snapshot() != after {
					t.Fatal("terminal replay changed recovery", replayErr)
				}
				replayIssuer, _, _ := issuanceFixture(t, risk.PhoneResetInitiation, time.Now().UTC(), original.CommandID, executor, true, nil)
				reissued, e := replayIssuer.Evaluate(ctx, original)
				if e != nil || reissued.Evidence.Reference != record.Reference || !reissued.Evidence.ExpiresAt.Equal(record.ExpiresAt) {
					t.Fatal("release broke original issuance", e)
				}
				if mode == "release" {
					other, foreign, otherCommand, otherPlan := prepare(t, repo, issuer, original, record)
					if _, _, e := other.ReserveCommand(ctx, foreign, otherCommand, otherPlan); e == nil {
						t.Fatal("released evidence reserved again")
					}
					assertNoCommand(t, foreign)
				}
			})
		}
	})
	t.Run("native-atomic-reserve-replay-takeover", func(t *testing.T) {
		issuer, original, record := setup(t)
		c, b, command, p := prepare(t, repo, issuer, original, record)
		reserved, _, err := c.ReserveCommand(ctx, b, command, p)
		if err != nil {
			t.Fatal("native reserve", err)
		}
		assertOwned(t, b, *p.RiskEvidence, "1")
		if _, err := c.Begin(ctx, reserved); err == nil {
			t.Fatal("reservation enabled unfinished domain phases")
		}
		_, replay, err := c.ReserveCommand(ctx, b, command, p)
		if err != nil || replay.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("live replay did not preserve pending owner", err)
		}
		raw, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.ReserveCommand(ctx, b, command, p); err != nil {
			t.Fatal("native predecessor rebind", err)
		}
		assertOwned(t, b, *p.RiskEvidence, "2")
		// Issuance remains committed after consumption has reserved its journal.
		replayIssuer, _, _ := issuanceFixture(t, risk.PhoneResetInitiation, time.Now().UTC(), original.CommandID, executor, true, nil)
		replayed, err := replayIssuer.Evaluate(ctx, original)
		if err != nil || replayed.Outcome != risk.EvidenceCommitted || replayed.Evidence.Reference != record.Reference || !replayed.Evidence.ExpiresAt.Equal(record.ExpiresAt) {
			t.Fatal("reservation broke historical issuance", err)
		}
		issuedID, _ := base64.RawURLEncoding.DecodeString(original.CommandID)
		for _, terminal := range []string{"finalized", "released", "revoked"} {
			mutate(t, `UPDATE risk_store.issued_evidence SET state=$2 WHERE command_id=$1`, issuedID, terminal)
			recovered, err := replayIssuer.Evaluate(ctx, original)
			if err != nil || recovered != replayed {
				t.Fatal("terminal state altered historical issuance", err)
			}
		}
	})
	t.Run("native-one-winner", func(t *testing.T) {
		issuer, original, record := setup(t)
		c, first, command, p := prepare(t, repo, issuer, original, record)
		other, second, secondCommand, secondPlan := prepare(t, repo, issuer, original, record)
		var outcomes [2]error
		var group sync.WaitGroup
		group.Add(2)
		go func() { defer group.Done(); _, _, outcomes[0] = c.ReserveCommand(ctx, first, command, p) }()
		go func() {
			defer group.Done()
			_, _, outcomes[1] = other.ReserveCommand(ctx, second, secondCommand, secondPlan)
		}()
		group.Wait()
		winner := 0
		if outcomes[0] != nil {
			winner = 1
		}
		if outcomes[winner] != nil || outcomes[1-winner] == nil {
			t.Fatal("native evidence did not have exactly one winner")
		}
		var conflict identity.ConflictError
		if !errors.As(outcomes[1-winner], &conflict) {
			t.Fatal("loser did not receive uniform replay denial", outcomes[1-winner])
		}
		bindings := []identity.CommandBinding{first, second}
		assertOwned(t, bindings[winner], *p.RiskEvidence, "1")
		assertNoCommand(t, bindings[1-winner])
	})
	for _, mode := range []string{"forged-signature", "policy", "retired-key", "missing-row", "wrong-proof", "wrong-expiry", "revoked", "changed-interval", "unresolved-issuance"} {
		t.Run(mode, func(t *testing.T) {
			issuer, original, record := setup(t)
			native := repo
			if mode == "policy" || mode == "retired-key" {
				_, key := evaluatedIssue(t, risk.PhoneResetInitiation)
				policy := uint64(3)
				if mode == "policy" {
					policy = 4
				} else {
					key, _ = risk.NewEvidenceKey(2, wrappingKey(6), wrappingKey(7))
				}
				var err error
				native, err = NewRepository(Config{Schema: "risk_store", PolicyVersion: policy, EvidenceKeys: []risk.EvidenceKey{key}, EnvelopeKeys: map[string][]byte{"wrapping_v1": wrappingKey(1)}, CurrentEnvelopeKey: "wrapping_v1"})
				if err != nil {
					t.Fatal(err)
				}
			}
			c, b, command, p := prepare(t, native, issuer, original, record)
			raw, _ := base64.RawURLEncoding.DecodeString(original.CommandID)
			switch mode {
			case "forged-signature":
				p.RiskEvidence.Signature[0] ^= 1
				p.Digest = [32]byte{}
				var err error
				p, err = c.PrepareCommandPlan(b, command, p)
				if err != nil {
					t.Fatal(err)
				}
			case "missing-row":
				mutate(t, `DELETE FROM risk_store.issued_evidence WHERE command_id=$1`, raw)
			case "wrong-proof":
				mutate(t, `UPDATE risk_store.issued_evidence SET proof_digest=$2 WHERE command_id=$1`, raw, wrappingKey(8))
			case "wrong-expiry":
				mutate(t, `UPDATE risk_store.issued_evidence SET expires_at=expires_at-interval '1 microsecond' WHERE command_id=$1`, raw)
			case "revoked":
				mutate(t, `UPDATE risk_store.issued_evidence SET state='revoked' WHERE command_id=$1`, raw)
			case "changed-interval":
				mutate(t, `UPDATE risk_store.issued_evidence SET issued_at=issued_at-interval '1 day',expires_at=expires_at-interval '1 day' WHERE command_id=$1`, raw)
			case "unresolved-issuance":
				// Positive native linkage is not an invented successful command.
				// Preserve the exact issued row but remove terminal outcome evidence.
				mutate(t, `UPDATE identity.commands SET state='pending',result_version=NULL,terminal_class=NULL,result=NULL,terminal_at=NULL WHERE command_id=$1`, raw)
			}
			_, _, err := c.ReserveCommand(ctx, b, command, p)
			if err == nil {
				t.Fatal("invalid evidence reserved")
			}
			var invalid identity.InvalidInputError
			var conflict identity.ConflictError
			if !errors.As(err, &invalid) && !errors.As(err, &conflict) {
				t.Fatal("unstable reservation error", err)
			}
			assertNoCommand(t, b)
		})
	}
	for _, mode := range []string{"wrong-generation", "wrong-fingerprint", "terminal", "missing"} {
		t.Run("takeover-"+mode, func(t *testing.T) {
			issuer, original, record := setup(t)
			c, b, command, p := prepare(t, repo, issuer, original, record)
			if _, _, err := c.ReserveCommand(ctx, b, command, p); err != nil {
				t.Fatal(err)
			}
			issuedID, _ := base64.RawURLEncoding.DecodeString(original.CommandID)
			switch mode {
			case "wrong-generation":
				mutate(t, `UPDATE risk_store.issued_evidence SET reservation_generation=7 WHERE command_id=$1`, issuedID)
			case "wrong-fingerprint":
				mutate(t, `UPDATE risk_store.issued_evidence SET reservation_fingerprint=$2 WHERE command_id=$1`, issuedID, wrappingKey(9))
			case "terminal":
				mutate(t, `UPDATE risk_store.issued_evidence SET state='released' WHERE command_id=$1`, issuedID)
			case "missing":
				mutate(t, `DELETE FROM risk_store.issued_evidence WHERE command_id=$1`, issuedID)
			}
			consumerID, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			mutate(t, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, consumerID)
			var before, after string
			if err := pool.Raw().QueryRow(ctx, `SELECT row_to_json(c)::text FROM identity.commands c WHERE command_id=$1`, consumerID).Scan(&before); err != nil {
				t.Fatal(err)
			}
			_, _, err := c.ReserveCommand(ctx, b, command, p)
			var conflict identity.ConflictError
			if !errors.As(err, &conflict) {
				t.Fatal("invalid predecessor obtained ownership", err)
			}
			if err := pool.Raw().QueryRow(ctx, `SELECT row_to_json(c)::text FROM identity.commands c WHERE command_id=$1`, consumerID).Scan(&after); err != nil || before != after {
				t.Fatal("takeover failure changed command generation/lease", err)
			}
		})
	}
	t.Run("primary-expiry-after-row-lock", func(t *testing.T) {
		issuer, original, record := setupAt(t, time.Now().UTC().Truncate(time.Microsecond).Add(-28*time.Second))
		c, b, command, p := prepare(t, repo, issuer, original, record)
		issuedID, _ := base64.RawURLEncoding.DecodeString(original.CommandID)
		lock, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Rollback(ctx)
		if _, err := lock.Exec(ctx, `SELECT 1 FROM risk_store.issued_evidence WHERE command_id=$1 FOR UPDATE`, issuedID); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, _, err := c.ReserveCommand(ctx, b, command, p); done <- err }()
		// Hold the primary row through exclusive expiry using database time,
		// while the authentic consuming command waits on its real row lock.
		_, sleepErr := lock.Exec(ctx, `SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM ($1::timestamptz-clock_timestamp())))+0.02)`, record.ExpiresAt)
		rollbackErr := lock.Rollback(ctx)
		reserveErr := <-done
		if sleepErr != nil || rollbackErr != nil {
			t.Fatal("expiry interleaving failed")
		}
		var conflict identity.ConflictError
		if !errors.As(reserveErr, &conflict) {
			t.Fatal("lock wait preserved expired evidence", reserveErr)
		}
		assertNoCommand(t, b)
	})
	t.Run("native-sql-failure-rolls-back-command-prefix", func(t *testing.T) {
		issuer, original, record := setup(t)
		c, b, command, p := prepare(t, repo, issuer, original, record)
		mutate(t, `ALTER TABLE risk_store.issued_evidence ADD CONSTRAINT test_reservation_failure CHECK(state<>'reserved') NOT VALID`)
		_, _, reserveErr := c.ReserveCommand(ctx, b, command, p)
		mutate(t, `ALTER TABLE risk_store.issued_evidence DROP CONSTRAINT test_reservation_failure`)
		var unavailable identity.UnavailableError
		if !errors.As(reserveErr, &unavailable) {
			t.Fatal("SQL failure not classified", reserveErr)
		}
		assertNoCommand(t, b)
		var state string
		if err := pool.Raw().QueryRow(ctx, `SELECT state FROM risk_store.issued_evidence WHERE evidence_digest=$1`, record.EvidenceDigest[:]).Scan(&state); err != nil || state != "issued" {
			t.Fatal("failed native write survived rollback", err)
		}
	})
}
