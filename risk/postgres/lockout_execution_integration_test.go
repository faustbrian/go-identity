//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
)

func testNativeLockoutTransitions(t *testing.T, ctx context.Context, pool *database.Pool,
	protected func(*Repository, string, ...time.Time) (*identitypostgres.Coordinator, identity.CommandBinding, identity.Command, identitypostgres.CommandPlan)) {
	t.Helper()
	history, err := (LockoutTransitionMigrationSource{Base: lockoutStateHistory(), Version: 26}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Raw().Exec(ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal(err)
	}
	m, err := authority.AuthoritySchemaMigration(27)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Raw().Exec(ctx, m.Up); err != nil {
		t.Fatal(err)
	}
	r, err := NewRepository(lockoutMutationConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	scope := authority.AuthorityScope{TenantID: "native-lockout", PolicyNamespace: "identity-admin", SubjectID: "administrator"}
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = authority.InitializeAuthority(ctx, tx, scope, time.Second); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	kernel, err := identitypostgres.NewRepository(pool, identitypostgres.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	auditing, outbox := &issuanceAudit{}, &issuanceOutbox{}
	registry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{kernel, auditing, outbox, r})
	if err != nil {
		t.Fatal(err)
	}
	coord, err := identitypostgres.NewCoordinator(pool, registry, identitypostgres.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: lockoutTestPolicy{}}})
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(mode risk.LockoutMode, expected uint64, record string) (identity.CommandBinding, identity.Command, identitypostgres.CommandPlan) {
		t.Helper()
		q := lockoutInput(t, mode, expected)
		if record != "" {
			q.Binding.RecordID = record
		}
		var now time.Time
		if err := pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			t.Fatal(err)
		}
		now = now.UTC()
		c, err := r.PrepareLockoutCommand(ctx, q, now)
		if err != nil {
			t.Fatal("prepare native command", err)
		}
		b := q.Binding
		s, _ := c.Feature()
		action, event := lockoutEvents(mode)
		builder, _ := audit.NewBuilder(audit.BuilderConfig{})
		seed, err := builder.Build(audit.RecordInput{OccurredAt: now, Action: action, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "risk_lockout", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "risk_lockout", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(expected, 10), "aggregate.after_version": strconv.FormatUint(expected+1, 10), "retention.class": "protected"}})
		if err != nil {
			t.Fatal("build native audit", err)
		}
		digest, err := identitypostgres.FeatureAuditBindingDigest(b, s.Operation, "risk_lockout", seed)
		if err != nil {
			t.Fatal("bind native audit", err)
		}
		p, err := coord.PrepareCommandPlan(b, c, identitypostgres.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "risk_lockout", Feature: &identitypostgres.FeatureRegistration{Contributor: r.Descriptor(), Operation: s.Operation}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: event, BeforeVersion: expected, AfterVersion: expected + 1}, Audits: []identitypostgres.AuditPlan{{EventType: action, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
		if err != nil {
			t.Fatal("prepare native plan", err)
		}
		return b, c, p
	}
	execute := func(b identity.CommandBinding, c identity.Command, p identitypostgres.CommandPlan) (identity.CommandResult, error) {
		res, result, err := coord.ReserveCommand(ctx, b, c, p)
		if err != nil || result.Outcome == identity.CommitOutcomeCommitted {
			return result, err
		}
		w, err := coord.Begin(ctx, res)
		if err != nil {
			return identity.CommandResult{}, err
		}
		defer coord.Abort(w, identity.UnavailableError{})
		result, err = coord.ApplyFeature(ctx, w, c)
		if err != nil {
			return coord.Abort(w, err)
		}
		return coord.Commit(w, result)
	}
	checkProtected := func(allow bool) {
		t.Helper()
		pc, b, c, p := protected(r, "native-lockout")
		res, _, err := pc.ReserveCommand(ctx, b, c, p)
		if err != nil {
			t.Fatal(err)
		}
		w, err := pc.Begin(ctx, res)
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Abort(w, identity.UnavailableError{})
		result, err := pc.ApplyFeature(ctx, w, c)
		if allow {
			if err != nil {
				t.Fatal("ended native lockout denied protected command", err)
			}
			if result, err = pc.Commit(w, result); err != nil || result.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal(err)
			}
		} else {
			var denied identity.ForbiddenError
			if !errors.As(err, &denied) {
				t.Fatal("native start did not deny protected command", err)
			}
			pc.Abort(w, err)
		}
	}
	b, c, p := prepare(risk.StartLockout, 0, "")
	result, err := execute(b, c, p)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("start", err, result.Outcome)
	}
	var start, expiry time.Time
	var version string
	var charged int
	if err = pool.Raw().QueryRow(ctx, `SELECT version::text,started_at,expires_at,(SELECT count(*) FROM risk_store.counter_charges WHERE tenant_id=$1) FROM risk_store.counter_lockouts WHERE tenant_id=$1`, string(b.TenantID)).Scan(&version, &start, &expiry, &charged); err != nil || version != "1" || charged != 0 {
		t.Fatal("start reset/charged root", err, version, charged)
	}
	checkProtected(false)
	if result, err = execute(b, c, p); err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("exact original replay", err)
	}
	extend, xc, xp := prepare(risk.StartLockout, 1, b.RecordID)
	if _, err = execute(extend, xc, xp); !errors.As(err, new(identity.ConflictError)) {
		t.Fatal("active start implicitly extended restriction", err)
	}
	// Effects and domain state share the sole coordinator transaction. A late
	// lifecycle failure cannot make an end effective or leave a domain version.
	failedEnd, fc, fp := prepare(risk.EndLockout, 1, b.RecordID)
	outbox.fail = true
	_, err = execute(failedEnd, fc, fp)
	outbox.fail = false
	if err == nil {
		t.Fatal("lifecycle failure committed native end")
	}
	var rolledBack bool
	if err = pool.Raw().QueryRow(ctx, `SELECT version=1 AND ended_at IS NULL AND NOT EXISTS(SELECT 1 FROM risk_store.lockout_transitions WHERE command_id=(SELECT command_id FROM identity.commands WHERE tenant_id=$1 AND purpose='identity.risk.end-lockout')) FROM risk_store.counter_lockouts WHERE tenant_id=$1`, string(b.TenantID)).Scan(&rolledBack); err != nil || !rolledBack {
		t.Fatal("failed end escaped rollback", err)
	}
	checkProtected(false)
	end, ec, ep := prepare(risk.EndLockout, 1, b.RecordID)
	if result, err = execute(end, ec, ep); err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("end", err)
	}
	var same bool
	if err = pool.Raw().QueryRow(ctx, `SELECT version=2 AND ended_at IS NOT NULL AND started_at=$2 AND expires_at=$3 FROM risk_store.counter_lockouts WHERE tenant_id=$1`, string(b.TenantID), start, expiry).Scan(&same); err != nil || !same {
		t.Fatal("end lost original interval", err)
	}
	checkProtected(true)
	stale, sc, sp := prepare(risk.EndLockout, 1, b.RecordID)
	if _, err = execute(stale, sc, sp); !errors.As(err, new(identity.ConflictError)) {
		t.Fatal("stale CAS accepted", err)
	}
	// A valid signed policy decision cannot outlive the existing owner's actor
	// epoch. Mutation must recheck it under the sole domain transaction.
	blocked, bc, bp := prepare(risk.StartLockout, 2, b.RecordID)
	tx, err = pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = authority.AdvanceAuthority(ctx, tx, scope, 1, time.Second); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = execute(blocked, bc, bp); !errors.As(err, new(identity.ForbiddenError)) {
		t.Fatal("removed admin retained mutation authority", err)
	}
	var transitions, audits, events int
	if err = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM risk_store.lockout_transitions WHERE tenant_id=$1),(SELECT count(*) FROM public.risk_audit WHERE command_id IN ($2,$3)),(SELECT count(*) FROM public.risk_outbox WHERE command_id IN ($2,$3))`, string(b.TenantID), string(b.CommandID), string(end.CommandID)).Scan(&transitions, &audits, &events); err != nil || transitions != 2 || audits != 2 || events != 2 {
		t.Fatal("native effects missing/duplicated", err, transitions, audits, events)
	}
	t.Run("owned-workflow-original-result", func(t *testing.T) {
		q := lockoutInput(t, risk.StartLockout, 2)
		q.Binding.RecordID = b.RecordID
		q.AuthorityVersion = 2
		cfg := LockoutExecutorConfig{Pool: pool, Repository: r, Audit: auditing, Lifecycle: outbox, Coordinator: identitypostgres.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: lockoutTestPolicy{}}, AdmissionPolicy: &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: lockoutTestPolicy{}}}, Caller: q.Scope, PolicyID: "risk-policy", RetentionPolicyVersion: 1}
		x, err := NewLockoutExecutor(cfg)
		if err != nil {
			t.Fatal(err)
		}
		input := LockoutExecutionRequest{CommandID: q.Binding.CommandID, RecordID: b.RecordID, Request: q.Request}
		first, err := x.Execute(ctx, input)
		if err != nil || first.Command.Outcome != identity.CommitOutcomeCommitted || first.Snapshot == nil || first.Snapshot.Version != 3 || first.Snapshot.EndedAt != nil {
			t.Fatal("owned start", err)
		}
		eq := lockoutInput(t, risk.EndLockout, 3)
		eq.Binding.RecordID = b.RecordID
		cfg.Caller = eq.Scope
		ex, err := NewLockoutExecutor(cfg)
		if err != nil {
			t.Fatal(err)
		}
		ending := LockoutExecutionRequest{CommandID: eq.Binding.CommandID, RecordID: b.RecordID, Request: eq.Request}
		last, err := ex.Execute(ctx, ending)
		if err != nil || last.Snapshot == nil || last.Snapshot.Version != 4 || last.Snapshot.EndedAt == nil {
			t.Fatal("owned end", err)
		}
		original, err := x.Recover(ctx, input)
		if err != nil || original.Snapshot == nil || original.Snapshot.Version != 3 || original.Snapshot.EndedAt != nil || original.Snapshot.StartedAt != first.Snapshot.StartedAt || original.Snapshot.ExpiresAt != first.Snapshot.ExpiresAt {
			t.Fatal("recovery substituted latest state", err)
		}
		foreign := input
		foreign.Request.Subject.Actor = "unbound-actor"
		if changed, err := x.Recover(ctx, foreign); err == nil || changed.Snapshot != nil {
			t.Fatal("unbound subject fact replayed", err)
		}
		denied := cfg
		denied.Caller = q.Scope
		queryPolicy := *cfg.Coordinator.QueryPolicy
		queryPolicy.Authorization = lockoutTestPolicy{deny: true}
		denied.Coordinator.QueryPolicy = &queryPolicy
		dx, err := NewLockoutExecutor(denied)
		if err != nil {
			t.Fatal(err)
		}
		if forbidden, err := dx.Recover(ctx, input); err == nil || forbidden.Snapshot != nil {
			t.Fatal("historical success bypassed current disclosure policy", err)
		}
		// Retained signing-key rotation can recover the original version; it
		// must not relabel the result with the new key or current domain state.
		rotated := lockoutMutationConfig(t)
		rotated.LockoutMutations.SigningKeys[2] = [32]byte{2}
		rotated.LockoutMutations.CurrentSigningKeyVersion = 2
		rr, err := NewRepository(rotated)
		if err != nil {
			t.Fatal(err)
		}
		rc := cfg
		rc.Repository = rr
		rc.Caller = q.Scope
		rx, err := NewLockoutExecutor(rc)
		if err != nil {
			t.Fatal(err)
		}
		if historical, err := rx.Recover(ctx, input); err != nil || historical.Snapshot == nil || historical.Snapshot.Version != 3 {
			t.Fatal("retained signer lost original result", err)
		}
		input.Request.Duration += time.Microsecond
		if changed, err := x.Execute(ctx, input); err == nil || changed.Snapshot != nil {
			t.Fatal("changed original intent replayed", err)
		}
		// Independent command IDs with one expected version must have one
		// winner, including when both observe absence before either writes.
		var wg sync.WaitGroup
		ready := make(chan struct{})
		outcomes := make(chan LockoutExecution, 2)
		errors := make(chan error, 2)
		for range 2 {
			competing := lockoutInput(t, risk.StartLockout, 4)
			attempt := LockoutExecutionRequest{CommandID: competing.Binding.CommandID, RecordID: b.RecordID, Request: competing.Request}
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-ready
				result, err := x.Execute(ctx, attempt)
				outcomes <- result
				errors <- err
			}()
		}
		close(ready)
		wg.Wait()
		close(outcomes)
		close(errors)
		winners, losers := 0, 0
		for result := range outcomes {
			if result.Snapshot != nil {
				if result.Snapshot.Version != 5 {
					t.Fatal("concurrent transition skipped version")
				}
				winners++
			}
		}
		for err := range errors {
			if err != nil {
				losers++
			}
		}
		if winners != 1 || losers != 1 {
			t.Fatal("concurrent CAS did not have one winner", winners, losers)
		}
		lost := lockoutInput(t, risk.EndLockout, 5)
		raw, _ := base64.RawURLEncoding.DecodeString(string(lost.Binding.CommandID))
		faultPool, fault := newCommitAckPool(t, ctx, os.Getenv("IDENTITY_RISK_POSTGRES_TEST_DSN"), pool.Raw().Config().ConnConfig.Database, raw)
		faultCfg := cfg
		faultCfg.Pool = faultPool
		faultCfg.Caller = lost.Scope
		fx, err := NewLockoutExecutor(faultCfg)
		if err != nil {
			t.Fatal(err)
		}
		lostRequest := LockoutExecutionRequest{CommandID: lost.Binding.CommandID, RecordID: b.RecordID, Request: lost.Request}
		uncertain, err := fx.Execute(ctx, lostRequest)
		if fault.hits.Load() != 1 || uncertain.Command.Outcome != identity.CommitOutcomeUnknown || uncertain.Snapshot != nil {
			t.Fatal("lost acknowledgement guessed commitment", err)
		}
		recovered, err := ex.Recover(ctx, lostRequest)
		if err != nil || recovered.Snapshot == nil || recovered.Snapshot.Version != 6 || recovered.Snapshot.EndedAt == nil {
			t.Fatal("lost acknowledgement did not recover original end", err)
		}
		var domain, audits, messages int
		if err = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM risk_store.lockout_transitions WHERE command_id=$1),(SELECT count(*) FROM public.risk_audit WHERE command_id=$2),(SELECT count(*) FROM public.risk_outbox WHERE command_id=$2)`, raw, string(lost.Binding.CommandID)).Scan(&domain, &audits, &messages); err != nil || domain != 1 || audits != 1 || messages != 1 {
			t.Fatal("ambiguity duplicated effects", err, domain, audits, messages)
		}
	})
}
