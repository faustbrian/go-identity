//go:build integration

package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	authorization "github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

func testOwnedCookieRevoke(t *testing.T, ctx context.Context, pool *database.Pool, reader *session.SessionService, config IssueExecutorConfig, cookie session.CookiePolicy, key session.CSRFKey, issue func(*testing.T) (session.GetRequest, session.GetResult, session.CSRFToken)) {
	t.Helper()
	config.Coordinator.FinalAuthentication = nil
	makeExecutor := func(t *testing.T, keys []session.CSRFKey) *CookieRevokeOneExecutor {
		t.Helper()
		e, err := NewCookieRevokeOneExecutor(pool, RevokeOneExecutorConfig{Execution: config, Sessions: reader}, keys)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	prepare := func(t *testing.T, caller session.GetResult, token session.CSRFToken) session.RevokeOneRequest {
		t.Helper()
		spec, _ := caller.Session.Bindings()
		b := revokeBinding()
		op := session.RevokeOneOperation()
		b.OperationID, b.SchemaID, b.RecordID = op.OperationID, op.SchemaID, spec.SessionID
		b.TenantID, b.UserID, b.ActorID = spec.TenantID, spec.UserID, identity.ActorID(spec.UserID)
		b.CommandID, _ = identity.NewCommandID()
		command, err := session.NewRevokeOneCommand(b, caller.Session)
		if err != nil {
			t.Fatal(err)
		}
		request, err := reader.PrepareRevokeOneWithCSRF(caller, command, token, key)
		if err != nil {
			t.Fatal(err)
		}
		return request
	}
	assertEffects := func(t *testing.T, request session.RevokeOneRequest, revoked bool, effects int) {
		t.Helper()
		command, _ := request.Command()
		one, _ := command.RevokeOne()
		spec, _ := one.Session.Bindings()
		native, _ := NewRepository(pool, config.Repository)
		stored, err := native.Get(ctx, spec.TenantID, spec.SessionID)
		if err != nil || stored.Revoked != revoked {
			t.Fatal("wrong native state", err)
		}
		var transitions, audits, events int
		// A denied command retains its required failure audit. Only successful
		// protected effects must roll back; audit suppression would be a defect.
		err = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.session_revocations WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$1 AND r.outcome=$2),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, mustCommandBytes(t, one.Binding.CommandID), int64(audit.OutcomeSucceeded)).Scan(&transitions, &audits, &events)
		if err != nil || transitions != effects || audits != effects || events != effects {
			t.Fatal("non-atomic/duplicate effects", err)
		}
	}
	t.Run("strict public composition clears only committed cookie", func(t *testing.T) {
		input, caller, token := issue(t)
		e := makeExecutor(t, []session.CSRFKey{key})
		base, err := session.NewSignOutService(reader, e, session.SignOutConfig{Cookie: cookie, PolicyID: config.PolicyID, PolicyVersion: config.PolicyVersion, MaximumDuration: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		strict, err := session.NewCookieSignOutService(base, []session.CSRFKey{key})
		if err != nil {
			t.Fatal(err)
		}
		id, _ := identity.NewCommandID()
		result, err := strict.SignOut(ctx, session.SignOutRequest{TenantID: input.TenantID, CommandID: id, CorrelationID: "strict-test", Transport: session.CredentialCookie, Credential: input.Credential}, token)
		if err != nil || !result.SignedOut || !result.ClearCookie || result.CommitOutcome != identity.CommitOutcomeCommitted || result.Cookie.Value != "" || result.Cookie.MaxAge != -1 {
			t.Fatal("strict commit did not safely clear transport", err)
		}
		if got, err := reader.Get(ctx, input); err != nil || got.Authenticated {
			t.Fatal("revoked strict cookie still authenticates", err)
		}
		if caller.Session == (session.Session{}) {
			t.Fatal("missing original fixture")
		}
	})
	t.Run("public native key denial never reports unknown commit", func(t *testing.T) {
		wrong, _ := session.NewCSRFKey(key.Version(), []byte("different-independent-key-material"))
		retired, _ := session.NewCSRFKey(key.Version()+1, []byte("different-independent-key-material"))
		for _, nativeKey := range []session.CSRFKey{wrong, retired} {
			input, _, token := issue(t)
			e := makeExecutor(t, []session.CSRFKey{nativeKey})
			base, err := session.NewSignOutService(reader, e, session.SignOutConfig{Cookie: cookie, PolicyID: config.PolicyID, PolicyVersion: config.PolicyVersion, MaximumDuration: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			strict, err := session.NewCookieSignOutService(base, []session.CSRFKey{key})
			if err != nil {
				t.Fatal(err)
			}
			id, _ := identity.NewCommandID()
			result, err := strict.SignOut(ctx, session.SignOutRequest{TenantID: input.TenantID, CommandID: id, CorrelationID: "key-denial", Transport: session.CredentialCookie, Credential: input.Credential}, token)
			if !errors.Is(err, session.ErrCSRFDenied) || result.CommitOutcome != identity.CommitOutcomeInvalid || result.SignedOut || result.ClearCookie {
				t.Fatal("pre-reservation CSRF rejection became ambiguous", err)
			}
			var claims int
			if err = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1`, mustCommandBytes(t, id)).Scan(&claims); err != nil || claims != 0 {
				t.Fatal("public denial reserved a command", err)
			}
			if got, err := reader.Get(ctx, input); err != nil || !got.Authenticated {
				t.Fatal("public denial changed active session", err)
			}
		}
	})
	t.Run("native replay and restart recovery retain one command", func(t *testing.T) {
		_, caller, token := issue(t)
		request := prepare(t, caller, token)
		e := makeExecutor(t, []session.CSRFKey{key})
		result, err := e.ExecuteRevokeOneWithCSRF(ctx, request)
		if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("strict native execution", err)
		}
		replayed, err := e.ExecuteRevokeOneWithCSRF(ctx, request)
		if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted || replayed.AuditEventID != result.AuditEventID {
			t.Fatal("strict terminal replay changed", err)
		}
		assertEffects(t, request, true, 1)
		restarted := makeExecutor(t, []session.CSRFKey{key})
		b := result.Binding
		q := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
		access := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Action: authorization.Action(b.OperationID), Tenant: authorization.TenantID(b.TenantID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
		history, err := restarted.RecoverRevokeOneCommand(ctx, q, access)
		if err != nil || history.Outcome != identity.CommitOutcomeCommitted || history.Binding != b {
			t.Fatal("strict restart recovery", err)
		}
	})
	t.Run("wrong native key and legacy dispatch deny before reservation", func(t *testing.T) {
		_, caller, token := issue(t)
		request := prepare(t, caller, token)
		wrong, _ := session.NewCSRFKey(key.Version(), []byte("different-independent-key-material"))
		e := makeExecutor(t, []session.CSRFKey{wrong})
		result, err := e.ExecuteRevokeOneWithCSRF(ctx, request)
		if !errors.Is(err, session.ErrCSRFDenied) || result.Outcome != identity.CommitOutcomeInvalid {
			t.Fatal("native key substitution admitted", err)
		}
		if _, err = e.base.ExecuteRevokeOne(ctx, request); !errors.Is(err, session.ErrCSRFDenied) {
			t.Fatal("legacy execution downgraded strict custody", err)
		}
		command, _ := request.Command()
		one, _ := command.RevokeOne()
		var claims int
		if err = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1`, mustCommandBytes(t, one.Binding.CommandID)).Scan(&claims); err != nil || claims != 0 {
			t.Fatal("denial reserved command", err)
		}
		assertEffects(t, request, false, 0)
	})
	t.Run("token checked inside registered primary invocation", func(t *testing.T) {
		_, caller, token := issue(t)
		request := prepare(t, caller, token)
		invocation, err := NewRevokeOneExecutor(pool, RevokeOneExecutorConfig{Execution: config, Sessions: reader})
		if err != nil {
			t.Fatal(err)
		}
		wrong, _ := session.NewCSRFToken()
		invocation.owned.native.cookieRevoke = &revokeCSRFInput{token: wrong, key: key}
		b, command, plan, _, err := invocation.prepare(request)
		if err != nil {
			t.Fatal(err)
		}
		reservation, _, err := invocation.owned.coordinator.ReserveCommand(ctx, b, command, plan)
		if err != nil || reservation == (kernel.Reservation{}) {
			t.Fatal("strict native fixture reservation", err)
		}
		work, err := invocation.owned.coordinator.Begin(ctx, reservation)
		if err != nil {
			t.Fatal(err)
		}
		defer invocation.owned.coordinator.Abort(work, identity.UnavailableError{})
		_, err = invocation.owned.coordinator.ApplyFeature(ctx, work, command)
		var forbidden identity.ForbiddenError
		if !errors.As(err, &forbidden) {
			t.Fatal("wrong ephemeral token survived original primary check", err)
		}
		if _, err = invocation.owned.coordinator.Abort(work, err); err == nil {
			t.Fatal("denied transaction lost its failure")
		}
		assertEffects(t, request, false, 0)
	})
	t.Run("changed primary digest cannot use original token admission", func(t *testing.T) {
		_, caller, token := issue(t)
		request := prepare(t, caller, token)
		spec, _ := caller.Session.Bindings()
		changed, _, _ := csrfAdmissionFixture(t, caller.Session)
		payload, _, err := encodeRecord(changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET record=$1::jsonb WHERE tenant_id=$2 AND session_id=$3`, string(payload), string(spec.TenantID), spec.SessionID); err != nil {
			t.Fatal(err)
		}
		e := makeExecutor(t, []session.CSRFKey{key})
		result, err := e.ExecuteRevokeOneWithCSRF(ctx, request)
		if err == nil || result.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("cached old CSRF state authenticated changed primary", err)
		}
		assertEffects(t, request, false, 0)
	})
	t.Run("constructor freezes keys and coordinator configuration", func(t *testing.T) {
		_, caller, token := issue(t)
		request := prepare(t, caller, token)
		keys := []session.CSRFKey{key}
		ownedConfig := config
		ownedConfig.Coordinator.RetainedFingerprintKeys = map[uint32][32]byte{1: {1}}
		e, err := NewCookieRevokeOneExecutor(pool, RevokeOneExecutorConfig{Execution: ownedConfig, Sessions: reader}, keys)
		if err != nil {
			t.Fatal(err)
		}
		keys[0] = session.CSRFKey{}
		ownedConfig.Coordinator.RetainedFingerprintKeys[1] = [32]byte{}
		result, err := e.ExecuteRevokeOneWithCSRF(ctx, request)
		if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("caller mutation changed trusted configuration", err)
		}
		assertEffects(t, request, true, 1)
	})
	t.Run("concurrent calls have isolated ephemeral custody", func(t *testing.T) {
		requests := make([]session.RevokeOneRequest, 2)
		for i := range requests {
			_, caller, token := issue(t)
			requests[i] = prepare(t, caller, token)
		}
		e := makeExecutor(t, []session.CSRFKey{key})
		var wg sync.WaitGroup
		results := make([]identity.CommandResult, len(requests))
		failures := make([]error, len(requests))
		for i := range requests {
			wg.Add(1)
			go func() { defer wg.Done(); results[i], failures[i] = e.ExecuteRevokeOneWithCSRF(ctx, requests[i]) }()
		}
		wg.Wait()
		for i := range requests {
			if failures[i] != nil || results[i].Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("concurrent strict execution", failures[i])
			}
			assertEffects(t, requests[i], true, 1)
		}
	})
}
