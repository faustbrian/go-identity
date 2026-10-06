//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
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

// Only the protected feature boundary is a seam: production risk cryptography,
// issuance, row ownership, coordinator reservation and takeover are real.
type nativeCaptchaProtectedFeature struct {
	mode   string
	expiry time.Time
}

func (*nativeCaptchaProtectedFeature) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (*nativeCaptchaProtectedFeature) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{{Owner: "identity/password", OperationID: "identity.password.signin", SchemaID: "native-captcha-protected-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}}
}
func (*nativeCaptchaProtectedFeature) ValidateFeatureCommand(c identity.Command, p identitypostgres.CommandPlan) error {
	s, ok := c.Feature()
	if !ok || s.Operation != (&nativeCaptchaProtectedFeature{}).FeatureOperations()[0] || p.CaptchaEvidence == nil {
		return identity.InvalidInputError{Field: "captcha_fixture"}
	}
	return nil
}
func (p *nativeCaptchaProtectedFeature) ApplyFeature(ctx context.Context, w identitypostgres.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if _, _, _, err := w.FeatureScope(p); err != nil {
		return identity.FeatureReceipt{}, err
	}
	s, _ := c.Feature()
	if _, err := w.Exec(ctx, `INSERT INTO risk_store.captcha_protected_fixture(command_id) VALUES($1)`, string(s.Binding.CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.mode == "native-domain-rollback" {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	if p.mode == "native-domain-expiry" {
		if _, err := w.Exec(ctx, `SELECT pg_sleep(GREATEST(0,extract(epoch FROM ($1::timestamptz-clock_timestamp()))+0.02))`, p.expiry); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: s.Operation, BeforeVersion: 4, AfterVersion: 5}, nil
}
func (p *nativeCaptchaProtectedFeature) RecoverParticipant(ctx context.Context, w identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	if p.mode == "native-domain-recover-unknown" {
		return identitypostgres.RecoveryUnknown, nil
	}
	return issuanceEffect(ctx, w, "risk_store.captcha_protected_fixture")
}

func testNativeCaptchaUse(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository, cfg risk.CaptchaEvidenceIssuerConfig, issue risk.CaptchaEvidenceIssue, record risk.CaptchaEvidenceRecord, mode string) {
	t.Helper()
	native := &nativeCaptchaProtectedFeature{mode: mode, expiry: record.ExpiresAt}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE IF NOT EXISTS risk_store.captcha_protected_fixture(command_id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	domain, err := identitypostgres.NewRepository(pool, identitypostgres.Config{MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{domain, &issuanceAudit{}, &issuanceOutbox{}, native, repo})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := identitypostgres.NewCoordinator(pool, registry, identitypostgres.CoordinatorConfig{MaximumDuration: 6 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: issuanceQueryPolicy{}}})
	if err != nil {
		t.Fatal(err)
	}
	prepare := func() (identity.CommandBinding, identity.Command, identitypostgres.CommandPlan) {
		t.Helper()
		var at time.Time
		if err := pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
			t.Fatal(err)
		}
		current := cfg
		current.Clock = func() time.Time { return at.UTC() }
		issuer, err := risk.NewCaptchaEvidenceIssuer(current)
		if err != nil {
			t.Fatal(err)
		}
		flow, err := risk.NewFlowContext(issue.Prepared().Binding.Replay.Flow)
		if err != nil {
			t.Fatal(err)
		}
		b := captchaCommandBinding(issue.Prepared())
		b.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		op := native.FeatureOperations()[0]
		b.OperationID, b.SchemaID, b.SchemaVersion, b.RecordID, b.PolicyVersion = op.OperationID, op.SchemaID, 1, "protected-target", 17
		use, err := issuer.PrecheckUse(ctx, issue, risk.CaptchaEvidenceUseRequest{CommandID: string(b.CommandID), Actor: string(b.ActorID), Flow: flow, Reference: record.Reference}, record)
		if err != nil {
			t.Fatal(err)
		}
		command, captcha, err := MapCaptchaUse(use, identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{uintField("expected-version", 4)}})
		if err != nil {
			t.Fatal(err)
		}
		builder, _ := audit.NewBuilder(audit.BuilderConfig{})
		seed, err := builder.Build(audit.RecordInput{OccurredAt: at.UTC(), Action: "password.signin", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "17"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "session", "aggregate.id": b.RecordID, "aggregate.before_version": "4", "aggregate.after_version": "5", "retention.class": "protected"}})
		if err != nil {
			t.Fatal(err)
		}
		digest, err := identitypostgres.FeatureAuditBindingDigest(b, op, "session", seed)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := coordinator.PrepareCommandPlan(b, command, identitypostgres.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "session", Feature: &identitypostgres.FeatureRegistration{Contributor: native.Descriptor(), Operation: op}, CaptchaEvidence: &captcha, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "password.signed_in.v1", BeforeVersion: 4, AfterVersion: 5}, Audits: []identitypostgres.AuditPlan{{EventType: "password.signin", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
		if err != nil {
			t.Fatal("native use preparation", err)
		}
		return b, command, plan
	}
	assertNoCommand := func(b identity.CommandBinding) {
		t.Helper()
		raw, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		var n int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.commands WHERE command_id=$1)+(SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1)`, raw).Scan(&n); err != nil || n != 0 {
			t.Fatal("failed reservation left command prefix", err, n)
		}
	}
	if strings.HasPrefix(mode, "native-domain-") {
		b, command, plan := prepare()
		reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
		if err != nil {
			t.Fatal("native domain reservation", err)
		}
		raw, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		wantState, wantJournal, wantGeneration, wantEffects := "released", "aborted", "1", 0
		if strings.Contains(mode, "recover") {
			wantGeneration = "2"
			if mode == "native-domain-recover-profile-removed" {
				// Restart with a changed policy and no current CAPTCHA verifier.
				// Historical primary proof permits cleanup, never new admission.
				replacement, err := NewRepository(Config{Schema: "risk_store", PolicyVersion: 4, EvidenceKeys: repo.keys, EnvelopeKeys: map[string][]byte{"wrapping_v1": wrappingKey(1)}, CurrentEnvelopeKey: "wrapping_v1"})
				if err != nil {
					t.Fatal(err)
				}
				if replacement.ValidateCaptchaUseCommand(command, *plan.CaptchaEvidence) == nil {
					t.Fatal("removed current profile admitted use")
				}
				updated, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{domain, &issuanceAudit{}, &issuanceOutbox{}, native, replacement})
				if err != nil {
					t.Fatal(err)
				}
				coordinator, err = identitypostgres.NewCoordinator(pool, updated, identitypostgres.CoordinatorConfig{MaximumDuration: 6 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: issuanceQueryPolicy{}}})
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "native-domain-recover-expired" {
				if _, err := pool.Raw().Exec(ctx, `SELECT pg_sleep(GREATEST(0,extract(epoch FROM ($1::timestamptz-clock_timestamp()))+0.02))`, record.ExpiresAt); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "native-domain-recover-divergent" {
				if _, err := pool.Raw().Exec(ctx, `UPDATE risk_store.captcha_issued_evidence SET consumer_generation=7 WHERE consumer_command_id=$1`, raw); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "native-domain-recover-signature" {
				if _, err := pool.Raw().Exec(ctx, `UPDATE risk_store.captcha_issued_evidence SET consumer_signature=decode(repeat('11',32),'hex') WHERE consumer_command_id=$1`, raw); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "native-domain-recover-revoked" {
				if _, err := pool.Raw().Exec(ctx, `UPDATE risk_store.captcha_issued_evidence SET state='revoked',terminal_at=clock_timestamp() WHERE consumer_command_id=$1`, raw); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); err != nil {
				t.Fatal(err)
			}
			query := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
			caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Tenant: authorization.TenantID(b.TenantID), Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(b.AnonymousFlowID)}}}
			_, err = coordinator.RecoverFeatureCommand(ctx, query, caller)
			var unavailable identity.UnavailableError
			if !errors.As(err, &unavailable) {
				t.Fatal("recovery fabricated success", err)
			}
			if mode == "native-domain-recover-unknown" || mode == "native-domain-recover-divergent" || mode == "native-domain-recover-signature" || mode == "native-domain-recover-revoked" {
				wantState, wantJournal, wantGeneration = "reserved", "pending", "1"
				if mode == "native-domain-recover-revoked" {
					wantState = "revoked"
				}
			}
		} else {
			if mode == "native-domain-tamper" {
				if _, err := pool.Raw().Exec(ctx, `UPDATE risk_store.captcha_issued_evidence SET hostname='foreign.example' WHERE consumer_command_id=$1`, raw); err != nil {
					t.Fatal(err)
				}
			}
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal("native domain Begin", err)
			}
			defer coordinator.Abort(work, identity.UnavailableError{})
			result, applyErr := coordinator.ApplyFeature(ctx, work, command)
			if mode == "native-domain-success" || mode == "native-domain-expiry" {
				if applyErr != nil {
					t.Fatal("native protected apply", applyErr)
				}
				result, err = coordinator.Commit(work, result)
				if mode == "native-domain-success" {
					if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
						t.Fatal("native atomic commit", err)
					}
					wantState, wantJournal, wantEffects = "finalized", "committed", 1
				} else if err == nil || result.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("expired native evidence committed")
				}
			} else {
				if applyErr == nil {
					t.Fatal("native failed protected apply accepted")
				}
				if _, err = coordinator.Abort(work, applyErr); err == nil {
					t.Fatal("abort lost original failure")
				}
			}
		}
		var state, journal, generation string
		var mutation, successAudit, outbox int
		var conserved bool
		err = pool.Raw().QueryRow(ctx, `SELECT e.state,c.state,c.generation::text,e.issued_at=$2 AND e.expires_at=$3 AND e.reserved_at>=e.issued_at AND (e.terminal_at IS NULL OR e.terminal_at>=e.reserved_at),
 (SELECT count(*) FROM risk_store.captcha_protected_fixture WHERE command_id=$4),
 (SELECT count(*) FROM public.risk_audit WHERE command_id=$4 AND record->>'outcome'='1'),
 (SELECT count(*) FROM public.risk_outbox WHERE command_id=$4)
 FROM risk_store.captcha_issued_evidence e JOIN identity.commands c ON c.command_id=e.consumer_command_id WHERE c.command_id=$1`, raw, record.IssuedAt, record.ExpiresAt, string(b.CommandID)).Scan(&state, &journal, &generation, &conserved, &mutation, &successAudit, &outbox)
		if err != nil || state != wantState || journal != wantJournal || generation != wantGeneration || !conserved || mutation != wantEffects || successAudit != wantEffects || outbox != wantEffects {
			t.Fatalf("native phase state=%s journal=%s gen=%s conserved=%t effects=%d/%d/%d: %v", state, journal, generation, conserved, mutation, successAudit, outbox, err)
		}
		return
	}
	if mode == "native-consuming-expiry" {
		b, command, plan := prepare()
		lock, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		rollback := func() {
			cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = lock.Rollback(cleanup)
		}
		defer rollback()
		if _, err := lock.Exec(ctx, `SELECT 1 FROM risk_store.captcha_issued_evidence WHERE evidence_digest=$1 FOR UPDATE`, record.EvidenceDigest[:]); err != nil {
			t.Fatal(err)
		}
		var result identity.CommandResult
		var reserveErr error
		done := make(chan struct{})
		go func() { defer close(done); _, result, reserveErr = coordinator.ReserveCommand(ctx, b, command, plan) }()
		// Cleanup releases exclusion and joins the worker even on an assertion
		// failure. The owned operation is bounded by coordinator/parent contexts.
		defer func() { rollback(); <-done }()
		poll := time.NewTicker(time.Millisecond)
		defer poll.Stop()
		for {
			var waiting bool
			if err := pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND position('captcha_issued_evidence' in query)>0)`).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("native reservation never waited for evidence", ctx.Err())
			case <-done:
				t.Fatal("reservation skipped the issued-row lock", reserveErr)
			case <-poll.C:
			}
		}
		if _, err := lock.Exec(ctx, `SELECT pg_sleep(GREATEST(0,extract(epoch FROM ($1::timestamptz-clock_timestamp()))+0.02))`, record.ExpiresAt); err != nil {
			t.Fatal(err)
		}
		if err := lock.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		<-done
		var conflict identity.ConflictError
		if !errors.As(reserveErr, &conflict) || result.Outcome == identity.CommitOutcomeInProgress {
			t.Fatal("lock wait preserved stale positive precheck", reserveErr, result.Outcome)
		}
		assertNoCommand(b)
		var state string
		if err := pool.Raw().QueryRow(ctx, `SELECT state FROM risk_store.captcha_issued_evidence WHERE evidence_digest=$1`, record.EvidenceDigest[:]).Scan(&state); err != nil || state != "issued" {
			t.Fatal("expired wait changed native custody", err, state)
		}
		return
	}
	// Pure signed precheck cannot substitute for the actual matching issued row.
	missing, missingCmd, missingPlan := prepare()
	if _, err := pool.Raw().Exec(ctx, `UPDATE risk_store.captcha_issued_evidence SET hostname='foreign.example' WHERE evidence_digest=$1`, record.EvidenceDigest[:]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := coordinator.ReserveCommand(ctx, missing, missingCmd, missingPlan); err == nil {
		t.Fatal("altered primary evidence accepted")
	}
	assertNoCommand(missing)
	if _, err := pool.Raw().Exec(ctx, `UPDATE risk_store.captcha_issued_evidence SET hostname=$2 WHERE evidence_digest=$1`, record.EvidenceDigest[:], record.Hostname); err != nil {
		t.Fatal(err)
	}
	// Two independently valid commands contend for the same native evidence.
	bindings := make([]identity.CommandBinding, 2)
	commands := make([]identity.Command, 2)
	plans := make([]identitypostgres.CommandPlan, 2)
	for i := range bindings {
		bindings[i], commands[i], plans[i] = prepare()
	}
	reservations := make([]identitypostgres.Reservation, 2)
	failures := make([]error, 2)
	var group sync.WaitGroup
	for i := range bindings {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			reservations[i], _, failures[i] = coordinator.ReserveCommand(ctx, bindings[i], commands[i], plans[i])
		}(i)
	}
	group.Wait()
	winner, count := -1, 0
	for i, e := range failures {
		if e == nil {
			winner = i
			count++
		} else {
			assertNoCommand(bindings[i])
		}
	}
	if count != 1 {
		t.Fatal("native evidence did not have exactly one winner", count, failures)
	}
	b, cmd, plan := bindings[winner], commands[winner], plans[winner]
	raw, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	assertOwned := func(generation string) {
		t.Helper()
		var state, commandGen, evidenceGen string
		var matched bool
		if err := pool.Raw().QueryRow(ctx, `SELECT e.state,c.generation::text,e.consumer_generation::text,e.consumer_fingerprint=k.fingerprint AND e.consumer_command_id=c.command_id AND e.expires_at=$2 AND e.reserved_at>=e.issued_at AND e.reserved_at<e.expires_at AND e.command_id<>c.command_id FROM risk_store.captcha_issued_evidence e JOIN identity.commands c ON c.command_id=e.consumer_command_id JOIN identity.identity_command_id_claims k ON k.command_id=c.command_id WHERE c.command_id=$1`, raw, record.ExpiresAt).Scan(&state, &commandGen, &evidenceGen, &matched); err != nil || state != "reserved" || commandGen != generation || evidenceGen != generation || !matched {
			t.Fatal("native ownership diverged", err, state, commandGen, evidenceGen, matched)
		}
	}
	assertOwned("1")
	if _, result, err := coordinator.ReserveCommand(ctx, b, cmd, plan); err != nil || result.Outcome != identity.CommitOutcomeInProgress {
		t.Fatal("matching live replay failed", err)
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); err != nil {
		t.Fatal(err)
	}
	if _, result, err := coordinator.ReserveCommand(ctx, b, cmd, plan); err != nil || result.Outcome != identity.CommitOutcomeInProgress {
		t.Fatal("native exact takeover", err)
	}
	assertOwned("2")
	for _, column := range []string{"consumer_fingerprint", "consumer_binding_digest", "consumer_signature"} {
		var original []byte
		if err := pool.Raw().QueryRow(ctx, `SELECT `+column+` FROM risk_store.captcha_issued_evidence WHERE consumer_command_id=$1`, raw).Scan(&original); err != nil {
			t.Fatal(err)
		}
		altered := append([]byte(nil), original...)
		altered[0] ^= 1
		if _, err := pool.Raw().Exec(ctx, `UPDATE risk_store.captcha_issued_evidence SET `+column+`=$2 WHERE consumer_command_id=$1`, raw, altered); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); err != nil {
			t.Fatal(err)
		}
		if _, _, err := coordinator.ReserveCommand(ctx, b, cmd, plan); err == nil {
			t.Fatal("altered native consuming ownership transferred", column)
		}
		var commandGen string
		if err := pool.Raw().QueryRow(ctx, `SELECT generation::text FROM identity.commands WHERE command_id=$1`, raw).Scan(&commandGen); err != nil || commandGen != "2" {
			t.Fatal("failed linkage takeover advanced command", err, commandGen)
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE risk_store.captcha_issued_evidence SET `+column+`=$2 WHERE consumer_command_id=$1`, raw, original); err != nil {
			t.Fatal(err)
		}
	}
	// Divergent participant generation cannot transfer the command prefix.
	if _, err := pool.Raw().Exec(ctx, `UPDATE risk_store.captcha_issued_evidence SET consumer_generation=1 WHERE consumer_command_id=$1`, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); err != nil {
		t.Fatal(err)
	}
	if _, _, err := coordinator.ReserveCommand(ctx, b, cmd, plan); err == nil {
		t.Fatal("divergent native predecessor transferred")
	}
	var generation string
	if err := pool.Raw().QueryRow(ctx, `SELECT generation::text FROM identity.commands WHERE command_id=$1`, raw).Scan(&generation); err != nil || generation != "2" {
		t.Fatal("failed takeover changed journal prefix", err, generation)
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE risk_store.captcha_issued_evidence SET consumer_generation=2,state='revoked',terminal_at=clock_timestamp() WHERE consumer_command_id=$1`, raw); err != nil {
		t.Fatal(err)
	}
	if _, _, err := coordinator.ReserveCommand(ctx, b, cmd, plan); err == nil {
		t.Fatal("terminal evidence resurrected on takeover")
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT generation::text FROM identity.commands WHERE command_id=$1`, raw).Scan(&generation); err != nil || generation != "2" {
		t.Fatal("terminal denial advanced command", err, generation)
	}
}
