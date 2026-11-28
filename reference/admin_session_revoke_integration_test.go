//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/jackc/pgx/v5"
)

func TestReferencePostgresAdminSessionRevokeHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, mfaEnrollment: true, passwordMFA: true, adminSessionRevokeHTTP: true,
	}, true)
}

type referenceAdminSessionRevokePolicy struct {
	actor, target identity.UserID
	calls         atomic.Int64
}

func (p *referenceAdminSessionRevokePolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Action != "identity.admin.session-revoke" {
		return (referenceRegistrationPolicy{}).Decide(ctx, c)
	}
	p.calls.Add(1)
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	r := c.Request
	if p.actor != "" && p.target != "" && c.PolicyRevision == 9 && r.Tenant == otpTenant && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID == authorization.SubjectID(p.actor) && r.Resource.Type == "identity.user" && r.Resource.ID == authorization.ResourceID(p.target) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	}
	return authorization.Decision{Outcome: authorization.Deny, Revision: 9}, nil
}

func configureReferenceAdminSessionRevokeHTTP(t *testing.T, c *reference.StoreConfiguration) {
	t.Helper()
	c.HTTPAdminSessionRevoke = &reference.HTTPAdminSessionRevokeConfiguration{
		PolicyID: "reference-admin-session-revoke", PolicyRevision: 9, MaximumDuration: time.Second,
		AdminNamespace: "reference-session-revoke-admin", AdminKey: [32]byte{223},
		Denied: func(ctx context.Context, event organizationhttp.AdminRateEvent) error {
			if event.Operation != "identity.admin.session-revoke" || event.Reason != "limited" && event.Reason != "unavailable" {
				t.Error("administrator session revoke quota lost exact operation or redacted denial reason")
			}
			return ctx.Err()
		},
	}
}

func proveReferenceAdminSessionRevokeHTTP(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, config reference.StoreConfiguration, policy *referenceAdminSessionRevokePolicy, client *http.Client, base, origin string, messages <-chan string) {
	t.Helper()
	if !strings.HasPrefix(base, "https://") || config.HTTPAdminSessionRevoke == nil || config.HTTPRate == nil || config.HTTPAdminSessionList != nil || config.UserStatusAdministration != nil || config.Impersonation != nil {
		t.Fatal("administrator session revoke requires standalone HTTPS selection and canonical rate owner")
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	transport := *client
	transport.Jar = nil
	actorCookies, actorCSRF := referenceImpersonationAdmin(t, ctx, &transport, base, origin, features, workers, messages, "session-revoke-administrator")
	actor := organizationHumanFromSession(t, ctx, sessions, actorCookies, actorCSRF)
	otherCookies, otherCSRF := referenceImpersonationAdmin(t, ctx, &transport, base, origin, features, workers, messages, "session-revoke-unauthorized")
	other := organizationHumanFromSession(t, ctx, sessions, otherCookies, otherCSRF)
	target := registerReferenceOrganizationHuman(t, ctx, &transport, base, origin, features, workers, messages, "session-revoke-target")
	sibling, siblingToken := referencePasswordLogin(t, ctx, f, &transport, base, origin, nil, config.PasswordSignin.Native, "synthetic-registration-password", "session-revoke-target@example.invalid")
	if actor.user == other.user || actor.user == target.user || other.user == target.user || !sibling.SignedIn || sibling.SessionID == target.sessionID {
		t.Fatal("administrator revoke requires independent genuine actors and two target sessions")
	}
	siblingWire, err := siblingToken.Reveal()
	if err != nil {
		t.Fatal("second genuine target credential unavailable")
	}
	policy.actor, policy.target = actor.user, target.user
	originalToken, err := session.ParseToken(target.cookies[0].Value)
	if err != nil {
		t.Fatal("original genuine target credential unavailable")
	}
	assertAuthentication := func(token session.Token, user identity.UserID, sessionID string, authenticated bool) uint64 {
		t.Helper()
		credential, err := session.NewCredential(session.CredentialCookie, token)
		if err != nil {
			t.Fatal("cannot read original credential")
		}
		observed, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
		if err != nil || observed.Authenticated != authenticated {
			t.Fatal("administrator revoke left incorrect primary credential authority", err)
		}
		if !authenticated {
			return 0
		}
		binding, err := observed.Session.Bindings()
		if err != nil || observed.ValidateAt(time.Now()) != nil || binding.UserID != user || binding.SessionID != sessionID {
			t.Fatal("administrator revoke changed an independent genuine session")
		}
		return binding.Version
	}
	originalVersion := assertAuthentication(originalToken, target.user, target.sessionID, true)
	assertAuthentication(siblingToken, target.user, sibling.SessionID, true)
	actorToken, err := session.ParseToken(actorCookies[0].Value)
	if err != nil {
		t.Fatal("original administrator credential unavailable")
	}
	assertAuthentication(actorToken, actor.user, actor.sessionID, true)
	quotaCount := func() int64 {
		t.Helper()
		var count int64
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.rate_limit_atomic_commands`).Scan(&count); err != nil {
			t.Fatal("administrator session revoke lacks native durable atomic quota", err)
		}
		return count
	}
	schema := config.Session.Native.Execution.Repository.Schema
	snapshot := func() []string {
		t.Helper()
		tables := [][2]string{{schema, "sessions"}, {schema, "families"}, {schema, "session_issuances"}, {schema, "session_revocations"}, {"identity", "users"}, {"identity", "identity_command_id_claims"}, {"identity", "commands"}, {"identity", "request_key_mappings"}, {"audit", "identity_command_bindings"}, {"audit", "records"}, {"public", "identity_outbox_bindings"}, {"public", "outbox_messages"}}
		state := make([]string, len(tables))
		for i, table := range tables {
			query := `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM ` + pgx.Identifier{table[0], table[1]}.Sanitize() + ` r`
			if err := f.pool.Raw().QueryRow(ctx, query).Scan(&state[i]); err != nil {
				t.Fatal("cannot observe administrator revoke protected state", table)
			}
		}
		return state
	}
	invoke := func(body map[string]string, cookies []*http.Cookie, csrf, requestOrigin string) (int, []byte) {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/admin/session-revoke", bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", requestOrigin)
		request.Header.Set("X-CSRF-Token", csrf)
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response, err := transport.Do(request)
		if err != nil {
			t.Fatal("administrator session revoke HTTPS transport unavailable", err)
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		contentType := response.Header.Get("Content-Type")
		originDenial := requestOrigin != origin && response.StatusCode == http.StatusForbidden && contentType == "text/plain; charset=utf-8" && string(data) == "identity.http.origin_denied\n"
		if readErr != nil || closeErr != nil || len(data) > 16384 || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || (contentType != "application/json" && !originDenial) || len(response.Header.Values("Set-Cookie")) != 0 || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("administrator session revoke violated bounded credential-free response custody")
		}
		for _, secret := range []string{actorCookies[0].Value, actorCSRF, otherCookies[0].Value, otherCSRF, target.cookies[0].Value, target.csrf, siblingWire} {
			if secret != "" && bytes.Contains(data, []byte(secret)) {
				t.Fatal("administrator session revoke disclosed original credential custody")
			}
		}
		if response.StatusCode != http.StatusOK && !originDenial {
			var failure map[string]json.RawMessage
			if json.Unmarshal(data, &failure) != nil || len(failure) != 1 || failure["error"] == nil {
				t.Fatal("denied administrator revoke disclosed partial outcome or target metadata")
			}
		}
		return response.StatusCode, data
	}
	decode := func(data []byte, revoked bool, version uint64) {
		t.Helper()
		var fields map[string]json.RawMessage
		var result struct {
			Revoked bool   `json:"revoked"`
			Version uint64 `json:"version"`
		}
		if json.Unmarshal(data, &fields) != nil || json.Unmarshal(data, &result) != nil || fields["revoked"] == nil || result.Revoked != revoked || result.Version != version {
			t.Fatal("administrator revoke lost exact confirmed mutation or non-disclosing no-op")
		}
		if revoked && (len(fields) != 2 || fields["version"] == nil) || !revoked && len(fields) != 1 {
			t.Fatal("administrator revoke returned fields outside its safe outcome contract")
		}
	}
	body := map[string]string{"userID": string(target.user), "sessionID": target.sessionID}
	before, quota := snapshot(), quotaCount()
	for _, attempt := range []struct {
		name    string
		body    map[string]string
		cookies []*http.Cookie
		csrf    string
		origin  string
		status  int
	}{
		{"unauthorized genuine MFA actor", body, otherCookies, otherCSRF, origin, http.StatusForbidden},
		{"spoofed actor field", map[string]string{"userID": string(target.user), "sessionID": target.sessionID, "actorID": string(actor.user)}, otherCookies, otherCSRF, origin, http.StatusBadRequest},
		{"wrong original synchronizer", body, actorCookies, otherCSRF, origin, http.StatusForbidden},
		{"foreign origin", body, actorCookies, actorCSRF, "https://foreign.example.invalid", http.StatusForbidden},
	} {
		status, _ := invoke(attempt.body, attempt.cookies, attempt.csrf, attempt.origin)
		if status != attempt.status || quotaCount() != quota || !reflect.DeepEqual(snapshot(), before) {
			t.Fatal(attempt.name, "changed quota or protected domain state", status)
		}
	}
	status, wrongTarget := invoke(map[string]string{"userID": string(target.user), "sessionID": actor.sessionID}, actorCookies, actorCSRF, origin)
	if status != http.StatusOK || quotaCount() != quota+1 || !reflect.DeepEqual(snapshot(), before) {
		t.Fatal("out-of-scope target session was not an admitted mutation-free no-op", status)
	}
	decode(wrongTarget, false, 0)
	status, success := invoke(body, actorCookies, actorCSRF, origin)
	if status != http.StatusOK || quotaCount() != quota+2 {
		t.Fatal("authorized target revoke did not charge canonical native quota once", status)
	}
	decode(success, true, originalVersion+1)
	assertAuthentication(originalToken, target.user, target.sessionID, false)
	assertAuthentication(siblingToken, target.user, sibling.SessionID, true)
	assertAuthentication(actorToken, actor.user, actor.sessionID, true)
	journal := pgx.Identifier{schema, "session_revocations"}.Sanitize()
	var commands, revocations, audits, events int64
	query := `SELECT
		(SELECT count(*) FROM identity.commands WHERE tenant_id=$1 AND purpose='identity.admin.session-revoke'),
		(SELECT count(*) FROM ` + journal + ` WHERE tenant_id=$1 AND purpose='identity.admin.session-revoke'),
		(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id JOIN identity.commands c ON c.command_id=b.command_id WHERE c.tenant_id=$1 AND c.purpose='identity.admin.session-revoke' AND r.outcome=$2),
		(SELECT count(*) FROM public.identity_outbox_bindings b JOIN identity.commands c ON c.command_id=b.command_id WHERE c.tenant_id=$1 AND c.purpose='identity.admin.session-revoke')`
	if err := f.pool.Raw().QueryRow(ctx, query, otpTenant, int64(audit.OutcomeSucceeded)).Scan(&commands, &revocations, &audits, &events); err != nil || commands != 1 || revocations != 1 || audits != 1 || events != 1 {
		t.Fatal("administrator revoke omitted or duplicated root command, native journal, success audit or lifecycle event", err)
	}
	var canonical []byte
	var beforeVersion, afterVersion string
	query = `SELECT a.canonical_record,j.before_version::text,j.after_version::text FROM ` + journal + ` j JOIN identity.commands c ON c.command_id=j.command_id JOIN audit.identity_command_bindings b ON b.command_id=j.command_id JOIN audit.records a ON a.record_id=b.event_id WHERE j.tenant_id=$1 AND j.user_id=$2 AND j.session_id=$3 AND j.purpose='identity.admin.session-revoke' AND c.purpose=j.purpose`
	if err := f.pool.Raw().QueryRow(ctx, query, otpTenant, string(target.user), target.sessionID).Scan(&canonical, &beforeVersion, &afterVersion); err != nil {
		t.Fatal("administrator revoke effects did not share the exact native target command", err)
	}
	audited, err := audit.ParseCanonicalJSON(canonical, audit.DefaultLimits())
	if err != nil || audited.Outcome() != audit.OutcomeSucceeded || audited.Action() != "identity.admin.session-revoke" || audited.Actor().ID() != string(actor.user) || audited.Subject().Type() != "session" || audited.Subject().ID() != target.sessionID || audited.Attributes()["retention.class"] != "protected" || beforeVersion != strconv.FormatUint(originalVersion, 10) || afterVersion != strconv.FormatUint(originalVersion+1, 10) {
		t.Fatal("administrator revoke lost protected human attribution or exact target version transition", err)
	}
	settled := snapshot()
	ordinary, login := config.Session.Native, config.PasswordSignin.Native
	execution, validation := ordinary.Execution, ordinary.Validation
	execution.Authorization, execution.PolicyID, execution.PolicyVersion = policy, config.HTTPAdminSessionRevoke.PolicyID, uint64(config.HTTPAdminSessionRevoke.PolicyRevision)
	validation.Clock = execution.Clock
	reader, err := sessionpg.NewMFAPasswordSessionService(f.pool, sessionpg.SessionServiceConfig{Repository: execution.Repository, Profile: login.Profile, Validation: validation})
	if err != nil {
		t.Fatal("reconstruct native receipt reader", err)
	}
	executor, err := sessionpg.NewAdminRevokeExecutor(f.pool, sessionpg.AdminRevokeExecutorConfig{Execution: execution, Sessions: reader, Actor: login.Profile, CSRFKey: login.CSRFKey})
	if err != nil {
		t.Fatal("reconstruct native read-only recovery owner", err)
	}
	commandID, err := identity.ParseCommandID(audited.Attributes()["command.id"])
	if err != nil {
		t.Fatal("exact journal did not retain command correlation", err)
	}
	queryReceipt := identity.RecoveryQuery{CommandID: commandID, TenantID: otpTenant, UserID: target.user, ActorID: identity.ActorID(actor.user), ActorKind: authorization.SubjectUser, OperationID: "identity.admin.session-revoke", RecordID: target.sessionID}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{
		Tenant: otpTenant, Action: "identity.admin.session-revoke",
		Subject:  authorization.Subject{ID: authorization.SubjectID(actor.user), Kind: authorization.SubjectUser},
		Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(target.user)},
	}}
	receipt, err := executor.RecoverAdminSessionRevoke(ctx, queryReceipt, caller)
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Feature == nil || receipt.Feature.BeforeVersion != originalVersion || receipt.Feature.AfterVersion != originalVersion+1 {
		t.Fatal("original native transition could not be observed through exact recovery", err)
	}
	queryReceipt.RecordID = sibling.SessionID
	if _, err := executor.RecoverAdminSessionRevoke(ctx, queryReceipt, caller); err == nil || !reflect.DeepEqual(snapshot(), settled) {
		t.Fatal("mismatched native receipt query disclosed or mutated state", err)
	}
	status, repeated := invoke(body, actorCookies, actorCSRF, origin)
	if status != http.StatusOK || quotaCount() != quota+3 || !reflect.DeepEqual(snapshot(), settled) {
		t.Fatal("repeated administrator revoke duplicated protected effects or changed target state", status)
	}
	decode(repeated, false, 0)
	assertAuthentication(originalToken, target.user, target.sessionID, false)
	assertAuthentication(siblingToken, target.user, sibling.SessionID, true)
	assertAuthentication(actorToken, actor.user, actor.sessionID, true)
	proveReferenceAdminSessionRevokeFinalFreshness(t, ctx, f, config, actor.user, actor.sessionID, target.user, sibling.SessionID, actorCookies[0].Value, actorCSRF, policy)
}
