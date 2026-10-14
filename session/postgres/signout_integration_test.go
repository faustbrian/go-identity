//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

func testPublicSignOut(t *testing.T, ctx context.Context, pool *database.Pool, input session.GetRequest, original session.Session, execution IssueExecutorConfig, validation session.ServiceConfig, cookie session.CookiePolicy) {
	t.Helper()
	execution.Coordinator.FinalAuthentication = nil
	validation.Clock = nil
	config := SignOutServiceConfig{Execution: execution, Validation: validation, Cookie: cookie, MaximumDuration: 2 * time.Second}
	newRequest := func() session.SignOutRequest {
		t.Helper()
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		return session.SignOutRequest{TenantID: input.TenantID, CommandID: id, CorrelationID: "native-signout", Transport: session.CredentialCookie, Credential: input.Credential}
	}
	claims := func(r session.SignOutRequest, want int) {
		t.Helper()
		var count int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1`, mustCommandBytes(t, r.CommandID)).Scan(&count); err != nil || count != want {
			t.Fatal("logout reservation", err, count)
		}
	}
	native, err := NewRepository(pool, execution.Repository)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := original.Bindings()
	var siblingsBefore, familiesBefore string
	var activeSiblings int
	if err := pool.Raw().QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY tenant_id,session_id)::text,'[]'),count(*) FILTER(WHERE state='active') FROM session_store.sessions s WHERE NOT(tenant_id=$1 AND session_id=$2)`, string(spec.TenantID), spec.SessionID).Scan(&siblingsBefore, &activeSiblings); err != nil || activeSiblings < 1 {
		t.Fatal("missing live sibling fixture", err, activeSiblings)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(f) ORDER BY tenant_id,family_id)::text,'[]') FROM session_store.families f`).Scan(&familiesBefore); err != nil {
		t.Fatal(err)
	}
	assertState := func(revoked bool) {
		t.Helper()
		stored, err := native.Get(ctx, spec.TenantID, spec.SessionID)
		if err != nil || stored.Revoked != revoked || stored.FamilyRevoked || stored.CurrentFamilyVersion != spec.FamilyVersion {
			t.Fatal("logout target/family state", err)
		}
		a, _, _ := encodeRecord(stored.Session)
		b, _, _ := encodeRecord(original)
		if string(a) != string(b) {
			t.Fatal("logout rewrote original authority")
		}
		var siblingsAfter, familiesAfter string
		if err := pool.Raw().QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY tenant_id,session_id)::text,'[]') FROM session_store.sessions s WHERE NOT(tenant_id=$1 AND session_id=$2)`, string(spec.TenantID), spec.SessionID).Scan(&siblingsAfter); err != nil || siblingsAfter != siblingsBefore {
			t.Fatal("logout changed a sibling", err)
		}
		if err := pool.Raw().QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(f) ORDER BY tenant_id,family_id)::text,'[]') FROM session_store.families f`).Scan(&familiesAfter); err != nil || familiesAfter != familiesBefore {
			t.Fatal("logout changed family authority", err)
		}
	}
	t.Run("public logout denies current policy without reservation", func(t *testing.T) {
		denied := config
		denied.Execution.Authorization = issueDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{Outcome: authorization.Deny, Revision: authorization.Revision(execution.PolicyVersion)}, nil
		})
		service, err := NewSignOutService(pool, denied)
		if err != nil {
			t.Fatal(err)
		}
		r := newRequest()
		out, err := service.SignOut(ctx, r)
		if err == nil || out.SignedOut || out.ClearCookie || out.ClearBearer {
			t.Fatal("denial became logout", err)
		}
		claims(r, 0)
		assertState(false)
	})
	t.Run("public logout fails closed on primary outage", func(t *testing.T) {
		service, err := NewSignOutService(pool, config)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Raw().Exec(ctx, `ALTER TABLE identity.credential_references RENAME TO signout_credentials_unavailable`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := pool.Raw().Exec(ctx, `ALTER TABLE identity.signout_credentials_unavailable RENAME TO credential_references`); err != nil {
				t.Error("restore primary fixture", err)
			}
		}()
		r := newRequest()
		out, err := service.SignOut(ctx, r)
		if err == nil || out.SignedOut || out.ClearCookie || out.ClearBearer {
			t.Fatal("outage became logout", err)
		}
		claims(r, 0)
		assertState(false)
	})
	t.Run("public logout commits once and remains absent after restart", func(t *testing.T) {
		service, err := NewSignOutService(pool, config)
		if err != nil {
			t.Fatal(err)
		}
		r := newRequest()
		out, err := service.SignOut(ctx, r)
		if err != nil || !out.SignedOut || !out.ClearCookie || out.ClearBearer || out.CommitOutcome != identity.CommitOutcomeCommitted || out.Cookie.Name != "__Host-session" || out.Cookie.Value != "" || out.Cookie.MaxAge != -1 || !out.Cookie.Secure || !out.Cookie.HttpOnly {
			t.Fatal("public native logout", err, out.CommitOutcome)
		}
		assertState(true)
		claims(r, 1)
		var revocations, audits, events int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.session_revocations WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$1 AND r.outcome=$2),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, mustCommandBytes(t, r.CommandID), int64(audit.OutcomeSucceeded)).Scan(&revocations, &audits, &events); err != nil || revocations != 1 || audits != 1 || events != 1 {
			t.Fatal("logout atomic effects", err, revocations, audits, events)
		}
		restarted, err := NewSignOutService(pool, config)
		if err != nil {
			t.Fatal(err)
		}
		repeat := newRequest()
		again, err := restarted.SignOut(ctx, repeat)
		if err != nil || !again.SignedOut || !again.ClearCookie || again.CommitOutcome != identity.CommitOutcomeInvalid {
			t.Fatal("inactive credential not idempotent", err)
		}
		claims(repeat, 0)
		readerConfig := validation
		readerConfig.Clock = execution.Clock
		reader, err := NewSessionService(pool, SessionServiceConfig{Repository: execution.Repository, Profile: IdentifierAdmissionConfig(execution.Profile), Validation: readerConfig})
		if err != nil {
			t.Fatal(err)
		}
		executor, err := NewRevokeOneExecutor(pool, RevokeOneExecutorConfig{Execution: execution, Sessions: reader})
		if err != nil {
			t.Fatal(err)
		}
		caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(execution.PolicyVersion), CorrelationID: r.CorrelationID, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(spec.UserID), Kind: authorization.SubjectUser}, Action: authorization.Action(session.RevokeOneOperation().OperationID), Tenant: authorization.TenantID(spec.TenantID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(spec.UserID)}}}
		history, err := executor.RecoverRevokeOneCommand(ctx, out.Recovery, caller)
		if err != nil || history.Outcome != identity.CommitOutcomeCommitted || history.Binding.CommandID != r.CommandID {
			t.Fatal("restart logout recovery", err)
		}
	})
}
