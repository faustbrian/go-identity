//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"

	authorization "github.com/faustbrian/go-authorization/v3"
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
	t.Run("core preparation and commit-gated cookie composition", func(t *testing.T) {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			t.Fatal(err)
		}
		key, err := session.NewDigestKey(7, raw[:])
		clear(raw[:])
		if err != nil {
			t.Fatal(err)
		}
		cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
		if err != nil {
			t.Fatal(err)
		}
		issuerConfig := session.PreAuthIssuerConfig{ActorID: config.ActorID, Action: config.Action, Origin: config.Origin, CallbackURL: config.CallbackURL, PolicyID: config.PolicyID, PolicyVersion: config.PolicyVersion, Clock: config.Clock, MaximumDuration: 2 * time.Second, FlowTTL: 5 * time.Minute, LookupKey: key, TokenSize: 32, Cookie: cookie}
		issuer, err := session.NewPreAuthIssuer(executor, issuerConfig)
		if err != nil {
			t.Fatal(err)
		}
		for _, choice := range []session.RememberChoice{session.BrowserSession, session.PersistentSession} {
			remember, err := session.ResolveRememberPolicy(choice, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := issuer.Prepare(session.PreAuthPrepareInput{CommandID: id, TenantID: "issue", CorrelationID: "preauth-core", Remember: remember})
			if err != nil {
				t.Fatal(err)
			}
			command, _ := prepared.Command()
			spec, _ := command.Record.Bindings()
			out, err := issuer.Issue(ctx, prepared)
			if err != nil || out.CommitOutcome != identity.CommitOutcomeCommitted || out.Replayed {
				t.Fatal("composed new issuance withheld delivery", err)
			}
			if out.Cookie.Name != "__Host-identity_flow" || out.Cookie.Value != "" || out.Cookie.MaxAge <= 0 || out.Cookie.MaxAge > 300 || out.Cookie.Expires.After(spec.Binding.ExpiresAt) || !out.Cookie.Secure || !out.Cookie.HttpOnly || out.Cookie.SameSite != http.SameSiteLaxMode {
				t.Fatal("composed flow cookie weakened scope or original expiry")
			}
			wire, err := out.Token.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := session.ParseToken(wire)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := parsed.PreAuthDigest(key, spec.Binding)
			if err != nil || digest != spec.Cookie || spec.Binding.Intent.Remember != remember {
				t.Fatal("original cookie commitment or remember choice changed")
			}
			counts(t, command, 1, 1)
			var payload []byte
			if err = pool.Raw().QueryRow(ctx, `SELECT record FROM session_store.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2`, string(spec.Binding.Intent.TenantID), string(spec.Binding.ID)).Scan(&payload); err != nil {
				t.Fatal(err)
			}
			original, _ := encodePreAuth(command.Record)
			if !bytes.Equal(payload, original) {
				t.Fatal("native storage changed server-prepared original")
			}
			replayed, err := executor.ExecutePreAuthIssuance(ctx, command)
			if err != nil || !replayed.Replayed || replayed.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("native replay enabled repeated cookie delivery", err)
			}
			restarted, err := NewPreAuthIssueExecutor(pool, config)
			if err != nil {
				t.Fatal(err)
			}
			recoveryIssuer, err := session.NewPreAuthIssuer(restarted, issuerConfig)
			if err != nil {
				t.Fatal(err)
			}
			recovered, err := recoveryIssuer.Recover(ctx, command)
			if err != nil || recovered.CommitOutcome != identity.CommitOutcomeCommitted || !recovered.Replayed || recovered.Flow != (session.PreAuthTransaction{}) || !reflect.DeepEqual(recovered.Cookie, http.Cookie{}) {
				t.Fatal("restart recovery changed outcome or claimed delivery", err)
			}
			if _, err = recovered.Token.Reveal(); !errors.Is(err, session.ErrInvalidToken) {
				t.Fatal("restart recovery redelivered cookie")
			}
		}
	})
	t.Run("exact retry and restart do not reissue", func(t *testing.T) {
		input := prepare(t)
		execution, err := executor.ExecutePreAuthIssuance(ctx, input)
		result := execution.Receipt
		if execution.Replayed {
			t.Fatal("new execution withheld original delivery eligibility")
		}
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
		if replay, err := executor.ExecutePreAuthIssuance(ctx, input); err != nil || !replay.Replayed || !reflect.DeepEqual(replay.Receipt, result) {
			t.Fatal("historical replay gained original delivery eligibility", err)
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
		if got, err := executor.ExecutePreAuthIssuance(ctx, changed); err == nil || !got.Replayed || got.Receipt.Outcome != identity.CommitOutcomeConflict {
			t.Fatal("conflicting input gained execution custody", err)
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
		if got, err := restarted.ExecutePreAuthIssuance(ctx, input); err != nil || !got.Replayed || !reflect.DeepEqual(got.Receipt, result) {
			t.Fatal("retired flow replay gained delivery eligibility", err)
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
		if got, err := executor.ExecutePreAuthIssuance(ctx, input); err != nil || !got.Replayed || got.Receipt.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("live pending observation gained execution custody", err)
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
			result session.PreAuthIssueExecution
			err    error
		}
		out := make(chan observed, 8)
		var group sync.WaitGroup
		for range 8 {
			group.Add(1)
			go func() {
				defer group.Done()
				r, err := executor.ExecutePreAuthIssuance(ctx, input)
				out <- observed{r, err}
			}()
		}
		group.Wait()
		close(out)
		newlyCommitted := 0
		for value := range out {
			if value.err != nil || value.result.Receipt.Outcome != identity.CommitOutcomeCommitted && value.result.Receipt.Outcome != identity.CommitOutcomeInProgress {
				t.Fatal("concurrent original command changed outcome", value.err, value.result.Receipt.Outcome)
			}
			if value.result.Receipt.Outcome == identity.CommitOutcomeCommitted && !value.result.Replayed {
				newlyCommitted++
			}
		}
		if newlyCommitted != 1 {
			t.Fatal("delivery eligibility must have exactly one winner", newlyCommitted)
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
