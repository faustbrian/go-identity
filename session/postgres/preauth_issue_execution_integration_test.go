//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	authorization "github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

func testOwnedPreAuthIssue(t *testing.T, ctx context.Context, pool *database.Pool, base IssueExecutorConfig) {
	t.Helper()
	base.Coordinator.FinalAuthentication = nil
	config := PreAuthIssueExecutorConfig{Repository: base.Repository, Coordinator: base.Coordinator, Authorization: base.Authorization, Clock: base.Clock, ActorID: "preauth-service", Action: "identity.otp.signin", Origin: "https://identity.test", CallbackURL: "https://app.test/return", PolicyID: "login", PolicyVersion: 1, AuditRetentionVersion: 1}
	executor, err := NewPreAuthIssueExecutor(pool, config)
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(t *testing.T) PreAuthIssueCommand {
		t.Helper()
		s, _ := testPreAuth(t, time.Now().UTC()).Bindings()
		flow, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		command, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		s.Binding.ID = identity.PreAuthTransactionID(flow)
		s.Binding.Intent.TenantID = "issue"
		s.Binding.Intent.PolicyVersion = 1
		if _, err = rand.Read(s.Cookie.Sum[:]); err != nil {
			t.Fatal(err)
		}
		record, err := session.NewPreAuthTransaction(s)
		if err != nil {
			t.Fatal(err)
		}
		return PreAuthIssueCommand{CommandID: command, CorrelationID: "preauth-test", Record: record}
	}
	query := func(b identity.CommandBinding) identity.RecoveryQuery {
		return identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
	}
	counts := func(t *testing.T, input PreAuthIssueCommand, want, wantAudits int) {
		t.Helper()
		s, _ := input.Record.Bindings()
		var flows, evidence, audits, events int
		err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2),(SELECT count(*) FROM session_store.preauth_issuances WHERE command_id=$3),(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$3),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$3)`, string(s.Binding.Intent.TenantID), string(s.Binding.ID), mustCommandBytes(t, input.CommandID)).Scan(&flows, &evidence, &audits, &events)
		if err != nil || flows != want || evidence != want || audits != wantAudits || events != want {
			t.Fatal("flow/evidence/audit/lifecycle conservation", flows, evidence, audits, events, err)
		}
	}
	t.Run("exact retry and restart do not reissue", func(t *testing.T) {
		input := prepare(t)
		result, err := executor.ExecutePreAuthIssue(ctx, input)
		if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Binding.UserID != "" || result.Binding.ActorID != config.ActorID || result.Feature == nil || result.Feature.AfterVersion != 1 {
			t.Fatal("native anonymous initiation", err, result.Outcome)
		}
		counts(t, input, 1, 1)
		s, _ := input.Record.Bindings()
		var payload []byte
		if err = pool.Raw().QueryRow(ctx, `SELECT record FROM session_store.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2`, string(s.Binding.Intent.TenantID), string(s.Binding.ID)).Scan(&payload); err != nil {
			t.Fatal(err)
		}
		original, _ := encodePreAuth(input.Record)
		if !bytes.Equal(payload, original) {
			t.Fatal("persisted original flow changed")
		}
		if replay, err := executor.ExecutePreAuthIssue(ctx, input); err != nil || !reflect.DeepEqual(replay, result) {
			t.Fatal("exact replay changed receipt", err)
		}
		changed := input
		s.Binding.Intent.CallbackURL = "https://app.test/other"
		changed.Record, err = session.NewPreAuthTransaction(s)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := executor.ExecutePreAuthIssue(ctx, changed); err == nil || got.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("changed callback borrowed original receipt")
		}
		// Complete valid changed intent under the same command reaches fingerprint
		// conflict, rather than relying only on the configured allowlist guard.
		s.Binding.Intent.CallbackURL = config.CallbackURL
		s.Binding.Intent.Nonce[1] = 1
		changed.Record, err = session.NewPreAuthTransaction(s)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := executor.ExecutePreAuthIssue(ctx, changed); err == nil || got.Outcome != identity.CommitOutcomeConflict {
			t.Fatal("changed original intent did not conflict", err, got.Outcome)
		}
		restarted, err := NewPreAuthIssueExecutor(pool, config)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := restarted.RecoverPreAuthIssue(ctx, query(result.Binding)); err != nil || !reflect.DeepEqual(got, result) {
			t.Fatal("restart lost historical receipt", err)
		}
		counts(t, input, 1, 1)
		// Retiring a live payload cannot change retained historical outcome.
		if _, err = pool.Raw().Exec(ctx, `DELETE FROM session_store.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2`, string(s.Binding.Intent.TenantID), string(s.Binding.ID)); err != nil {
			t.Fatal(err)
		}
		if got, err := restarted.RecoverPreAuthIssue(ctx, query(result.Binding)); err != nil || !reflect.DeepEqual(got, result) {
			t.Fatal("payload absence fabricated noncommit", err)
		}
		if got, err := restarted.ExecutePreAuthIssue(ctx, input); err != nil || !reflect.DeepEqual(got, result) {
			t.Fatal("terminal replay reactivated flow", err)
		}
		var rows int
		if err = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM session_store.preauth_transactions WHERE flow_id=$1`, string(s.Binding.ID)).Scan(&rows); err != nil || rows != 0 {
			t.Fatal("retired flow resurrected", err)
		}
		resurrection := input
		resurrection.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		if got, err := restarted.ExecutePreAuthIssue(ctx, resurrection); err == nil || got.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("new command resurrected retained flow identity", err)
		}
		counts(t, resurrection, 0, 1)
	})
	t.Run("rollback and expired reservation recovery", func(t *testing.T) {
		input := prepare(t)
		b, command, err := executor.preparePreAuth(input)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := executor.preAuthPlan(b, command)
		if err != nil {
			t.Fatal(err)
		}
		reservation, result, err := executor.owned.coordinator.ReserveCommand(ctx, b, command, plan)
		if err != nil || reservation == (kernel.Reservation{}) || result.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("reservation", err)
		}
		if got, err := executor.RecoverPreAuthIssue(ctx, query(b)); err != nil || got.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("live receipt lease lost", err)
		}
		work, err := executor.owned.coordinator.Begin(ctx, reservation)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = executor.owned.coordinator.ApplyFeature(ctx, work, command); err != nil {
			t.Fatal(err)
		}
		if got, _ := executor.owned.coordinator.Abort(work, identity.ForbiddenError{}); got.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("staged flow did not roll back")
		}
		// The domain prefix rolls back; the kernel retains the required denial
		// audit with the aborted receipt in its existing cleanup transaction.
		counts(t, input, 0, 1)
		pending := prepare(t)
		pb, pc, err := executor.preparePreAuth(pending)
		if err != nil {
			t.Fatal(err)
		}
		pp, err := executor.preAuthPlan(pb, pc)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = executor.owned.coordinator.ReserveCommand(ctx, pb, pc, pp); err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, mustCommandBytes(t, pb.CommandID)); err != nil {
			t.Fatal(err)
		}
		recovered, err := executor.RecoverPreAuthIssue(ctx, query(pb))
		if err == nil || recovered.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("expired incomplete command failed to prove noncommit", err, recovered.Outcome)
		}
		counts(t, pending, 0, 1)
	})
	t.Run("expired flow and missing recovery fail closed", func(t *testing.T) {
		input := prepare(t)
		s, _ := input.Record.Bindings()
		s.Binding.IssuedAt = s.Binding.IssuedAt.Add(-10 * time.Minute)
		s.Binding.ExpiresAt = s.Binding.ExpiresAt.Add(-10 * time.Minute)
		input.Record, err = session.NewPreAuthTransaction(s)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := executor.ExecutePreAuthIssue(ctx, input); err == nil || got.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("expired issuance committed", err)
		}
		counts(t, input, 0, 1)
		missing := prepare(t)
		b, _, err := executor.preparePreAuth(missing)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := executor.RecoverPreAuthIssue(ctx, query(b)); err == nil || got.Binding.CommandID != "" {
			t.Fatal("missing recovery disclosed scope")
		}
		var claims int
		if err = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1`, mustCommandBytes(t, b.CommandID)).Scan(&claims); err != nil || claims != 0 {
			t.Fatal("recovery created claim", err)
		}
	})
	t.Run("current policy denial reserves no command", func(t *testing.T) {
		denied := config
		denied.Authorization = issueDecision(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
			if dc.Request.Resource.Type != "identity.anonymous-flow" || dc.Request.Subject.ID != authorization.SubjectID(config.ActorID) {
				t.Fatal("flow confused with actor")
			}
			return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
		})
		service, err := NewPreAuthIssueExecutor(pool, denied)
		if err != nil {
			t.Fatal(err)
		}
		input := prepare(t)
		if got, err := service.ExecutePreAuthIssue(ctx, input); err == nil || got.Binding.CommandID != "" {
			t.Fatal("denied initiation gained command")
		}
		counts(t, input, 0, 0)
	})
	t.Run("concurrent identical commands issue once", func(t *testing.T) {
		input := prepare(t)
		type observed struct {
			result identity.CommandResult
			err    error
		}
		out := make(chan observed, 8)
		var group sync.WaitGroup
		for range 8 {
			group.Add(1)
			go func() {
				defer group.Done()
				r, err := executor.ExecutePreAuthIssue(ctx, input)
				out <- observed{r, err}
			}()
		}
		group.Wait()
		close(out)
		committed := false
		for value := range out {
			if value.err != nil || value.result.Outcome != identity.CommitOutcomeCommitted && value.result.Outcome != identity.CommitOutcomeInProgress {
				t.Fatal("concurrent original command changed outcome", value.err, value.result.Outcome)
			}
			committed = committed || value.result.Outcome == identity.CommitOutcomeCommitted
		}
		if !committed {
			t.Fatal("no original command committed")
		}
		counts(t, input, 1, 1)
	})
	t.Run("invalid configuration and canceled initiation create no state", func(t *testing.T) {
		for _, alter := range []func(*PreAuthIssueExecutorConfig){
			func(c *PreAuthIssueExecutorConfig) { c.Origin = "https://identity.test/path" },
			func(c *PreAuthIssueExecutorConfig) { c.CallbackURL = "http://unsafe.test/" },
			func(c *PreAuthIssueExecutorConfig) { c.Action = "" },
			func(c *PreAuthIssueExecutorConfig) { c.ActorID = "" },
			func(c *PreAuthIssueExecutorConfig) { c.Authorization = nil },
			func(c *PreAuthIssueExecutorConfig) { c.Clock = nil },
			func(c *PreAuthIssueExecutorConfig) { c.PolicyVersion = 0 },
			func(c *PreAuthIssueExecutorConfig) { c.Repository.MaximumDuration = 0 },
		} {
			bad := config
			alter(&bad)
			if e, err := NewPreAuthIssueExecutor(pool, bad); err == nil || e != nil {
				t.Fatal("invalid profile created executor")
			}
		}
		input := prepare(t)
		canceled, stop := context.WithCancel(ctx)
		stop()
		got, err := executor.ExecutePreAuthIssue(canceled, input)
		var cancellation identity.CancelledError
		if !errors.As(err, &cancellation) || got.Binding.CommandID != "" {
			t.Fatal("canceled initiation lost classification", err)
		}
		counts(t, input, 0, 0)
	})
}
