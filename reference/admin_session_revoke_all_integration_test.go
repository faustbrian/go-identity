//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
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

func TestReferencePostgresAdminSessionRevokeAllHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, mfaEnrollment: true, passwordMFA: true, adminSessionRevokeAllHTTP: true,
	}, true)
}

type referenceAdminSessionRevokeAllPolicy struct {
	actor, target identity.UserID
	calls         atomic.Int64
}

func (p *referenceAdminSessionRevokeAllPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Action != "identity.admin.session-revoke-all" {
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

func configureReferenceAdminSessionRevokeAllHTTP(t *testing.T, c *reference.StoreConfiguration) {
	t.Helper()
	c.HTTPAdminSessionRevokeAll = &reference.HTTPAdminSessionRevokeAllConfiguration{
		PolicyID: "reference-admin-session-revoke-all", PolicyRevision: 9, MaximumDuration: time.Second,
		AdminNamespace: "reference-session-revoke-all-admin", AdminKey: [32]byte{227},
		Denied: func(ctx context.Context, event organizationhttp.AdminRateEvent) error {
			if event.Operation != "identity.admin.session-revoke-all" || event.Reason != "limited" && event.Reason != "unavailable" {
				t.Error("administrator bulk session quota lost exact operation or redacted denial reason")
			}
			return ctx.Err()
		},
	}
}

func proveReferenceAdminSessionRevokeAllHTTP(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, config reference.StoreConfiguration, policy *referenceAdminSessionRevokeAllPolicy, client *http.Client, base, origin string, messages <-chan string) {
	t.Helper()
	if !strings.HasPrefix(base, "https://") || config.HTTPAdminSessionRevokeAll == nil || config.HTTPRate == nil || config.HTTPAdminSessionRevoke != nil || config.HTTPAdminSessionList != nil || config.UserStatusAdministration != nil || config.Impersonation != nil {
		t.Fatal("administrator bulk session revoke requires standalone HTTPS selection and canonical rate owner")
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	transport := *client
	transport.Jar = nil
	actorCookies, actorCSRF := referenceImpersonationAdmin(t, ctx, &transport, base, origin, features, workers, messages, "session-revoke-all-administrator")
	actor := organizationHumanFromSession(t, ctx, sessions, actorCookies, actorCSRF)
	otherCookies, otherCSRF := referenceImpersonationAdmin(t, ctx, &transport, base, origin, features, workers, messages, "session-revoke-all-unauthorized")
	other := organizationHumanFromSession(t, ctx, sessions, otherCookies, otherCSRF)
	target := registerReferenceOrganizationHuman(t, ctx, &transport, base, origin, features, workers, messages, "session-revoke-all-target")
	sibling, siblingToken := referencePasswordLogin(t, ctx, f, &transport, base, origin, nil, config.PasswordSignin.Native, "synthetic-registration-password", "session-revoke-all-target@example.invalid")
	if actor.user == other.user || actor.user == target.user || other.user == target.user || !sibling.SignedIn || sibling.SessionID == target.sessionID {
		t.Fatal("administrator bulk revoke requires independent genuine actors and two target sessions")
	}
	policy.actor, policy.target = actor.user, target.user
	parseToken := func(wire string) session.Token {
		t.Helper()
		token, err := session.ParseToken(wire)
		if err != nil {
			t.Fatal("genuine session credential unavailable")
		}
		return token
	}
	originalToken := parseToken(target.cookies[0].Value)
	actorToken := parseToken(actorCookies[0].Value)
	otherToken := parseToken(otherCookies[0].Value)
	siblingWire, err := siblingToken.Reveal()
	if err != nil {
		t.Fatal("second genuine target credential unavailable")
	}
	assertAuthentication := func(token session.Token, user identity.UserID, sessionID string, authenticated bool) {
		t.Helper()
		credential, err := session.NewCredential(session.CredentialCookie, token)
		if err != nil {
			t.Fatal("cannot observe original credential")
		}
		observed, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
		if err != nil || observed.Authenticated != authenticated {
			t.Fatal("administrator bulk revoke left incorrect primary credential authority", err)
		}
		if authenticated {
			binding, err := observed.Session.Bindings()
			if err != nil || observed.ValidateAt(time.Now()) != nil || binding.UserID != user || binding.SessionID != sessionID {
				t.Fatal("administrator bulk revoke changed an independent genuine session")
			}
		}
	}
	assertAuthentication(originalToken, target.user, target.sessionID, true)
	assertAuthentication(siblingToken, target.user, sibling.SessionID, true)
	assertAuthentication(actorToken, actor.user, actor.sessionID, true)
	assertAuthentication(otherToken, other.user, other.sessionID, true)
	proveReferenceAdminSessionRevokeAllFinalFreshness(t, ctx, f, config, actor.user, actor.sessionID, target.user, actorCookies[0].Value, actorCSRF, policy)
	assertAuthentication(originalToken, target.user, target.sessionID, true)
	assertAuthentication(siblingToken, target.user, sibling.SessionID, true)
	schema := config.Session.Native.Execution.Repository.Schema
	readTable := func(table [2]string) string {
		t.Helper()
		query := `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM ` + pgx.Identifier{table[0], table[1]}.Sanitize() + ` r`
		var state string
		if err := f.pool.Raw().QueryRow(ctx, query).Scan(&state); err != nil {
			t.Fatal("cannot observe administrator bulk revoke protected state", table)
		}
		return state
	}
	snapshot := func() []string {
		t.Helper()
		tables := [][2]string{{schema, "sessions"}, {schema, "families"}, {schema, "session_issuances"}, {schema, "session_revocations"}, {schema, "admin_set_revocations"}, {"identity", "users"}, {"identity", "identity_command_id_claims"}, {"identity", "commands"}, {"identity", "request_key_mappings"}, {"audit", "identity_command_bindings"}, {"audit", "records"}, {"public", "identity_outbox_bindings"}, {"public", "outbox_messages"}}
		state := make([]string, len(tables))
		for i, table := range tables {
			state[i] = readTable(table)
		}
		return state
	}
	quotaCount := func() int64 {
		t.Helper()
		var count int64
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.rate_limit_atomic_commands`).Scan(&count); err != nil {
			t.Fatal("administrator bulk revoke lacks native durable atomic quota", err)
		}
		return count
	}
	invoke := func(body map[string]string, cookies []*http.Cookie, csrf, requestOrigin string) (int, []byte) {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/admin/session-revoke-all", bytes.NewReader(wire))
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
			t.Fatal("administrator bulk session revoke HTTPS transport unavailable", err)
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		contentType := response.Header.Get("Content-Type")
		originDenial := requestOrigin != origin && response.StatusCode == http.StatusForbidden && contentType == "text/plain; charset=utf-8" && string(data) == "identity.http.origin_denied\n"
		if readErr != nil || closeErr != nil || len(data) > 16384 || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || contentType != "application/json" && !originDenial || len(response.Header.Values("Set-Cookie")) != 0 || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("administrator bulk revoke violated bounded credential-free response custody")
		}
		for _, secret := range []string{actorCookies[0].Value, actorCSRF, otherCookies[0].Value, otherCSRF, target.cookies[0].Value, target.csrf, siblingWire} {
			if secret != "" && bytes.Contains(data, []byte(secret)) {
				t.Fatal("administrator bulk revoke disclosed original credential custody")
			}
		}
		if response.StatusCode != http.StatusOK && !originDenial {
			var failure map[string]json.RawMessage
			if json.Unmarshal(data, &failure) != nil || len(failure) != 1 || failure["error"] == nil {
				t.Fatal("denied administrator bulk revoke disclosed partial outcome or target metadata")
			}
		}
		return response.StatusCode, data
	}
	decode := func(data []byte, count uint32, version uint64) {
		t.Helper()
		var fields map[string]json.RawMessage
		var result struct {
			RevokedCount   uint32 `json:"revokedCount"`
			SubjectVersion uint64 `json:"subjectVersion"`
		}
		if json.Unmarshal(data, &fields) != nil || json.Unmarshal(data, &result) != nil || len(fields) != 2 || fields["revokedCount"] == nil || fields["subjectVersion"] == nil || result.RevokedCount != count || result.SubjectVersion != version {
			t.Fatal("administrator bulk revoke lost exact confirmed count and session-only version")
		}
	}
	body := map[string]string{"userID": string(target.user)}
	before, quota := snapshot(), quotaCount()
	users := readTable([2]string{"identity", "users"})
	var originalCommands int64
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.commands WHERE tenant_id=$1 AND purpose='identity.admin.session-revoke-all'`, otpTenant).Scan(&originalCommands); err != nil {
		t.Fatal("observe bulk command baseline after the independently identified freshness denial", err)
	}
	for _, attempt := range []struct {
		name    string
		body    map[string]string
		cookies []*http.Cookie
		csrf    string
		origin  string
		status  int
	}{
		{"unauthorized genuine MFA actor", body, otherCookies, otherCSRF, origin, http.StatusForbidden},
		{"foreign target user", map[string]string{"userID": string(other.user)}, actorCookies, actorCSRF, origin, http.StatusForbidden},
		{"spoofed actor field", map[string]string{"userID": string(target.user), "actorID": string(actor.user)}, otherCookies, otherCSRF, origin, http.StatusBadRequest},
		{"single-session selector", map[string]string{"userID": string(target.user), "sessionID": target.sessionID}, actorCookies, actorCSRF, origin, http.StatusBadRequest},
		{"caller-selected request key", map[string]string{"userID": string(target.user), "requestKey": "not-a-native-command"}, actorCookies, actorCSRF, origin, http.StatusBadRequest},
		{"wrong original synchronizer", body, actorCookies, otherCSRF, origin, http.StatusForbidden},
		{"foreign origin", body, actorCookies, actorCSRF, "https://foreign.example.invalid", http.StatusForbidden},
	} {
		status, _ := invoke(attempt.body, attempt.cookies, attempt.csrf, attempt.origin)
		if status != attempt.status || quotaCount() != quota || !reflect.DeepEqual(snapshot(), before) {
			t.Fatal(attempt.name, "changed quota or protected domain state", status)
		}
	}
	status, success := invoke(body, actorCookies, actorCSRF, origin)
	if status != http.StatusOK || quotaCount() != quota+1 {
		t.Fatal("authorized bulk revoke did not charge canonical native quota once", status)
	}
	decode(success, 2, 1)
	assertAuthentication(originalToken, target.user, target.sessionID, false)
	assertAuthentication(siblingToken, target.user, sibling.SessionID, false)
	assertAuthentication(actorToken, actor.user, actor.sessionID, true)
	assertAuthentication(otherToken, other.user, other.sessionID, true)
	journal := pgx.Identifier{schema, "admin_set_revocations"}.Sanitize()
	assertEffects := func(want int64) {
		t.Helper()
		var commands, revocations, audits, events int64
		query := `SELECT
			(SELECT count(*) FROM identity.commands WHERE tenant_id=$1 AND purpose='identity.admin.session-revoke-all'),
			(SELECT count(*) FROM ` + journal + ` WHERE tenant_id=$1 AND purpose='identity.admin.session-revoke-all'),
			(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id JOIN identity.commands c ON c.command_id=b.command_id WHERE c.tenant_id=$1 AND c.purpose='identity.admin.session-revoke-all' AND r.outcome=$2),
			(SELECT count(*) FROM public.identity_outbox_bindings b JOIN identity.commands c ON c.command_id=b.command_id WHERE c.tenant_id=$1 AND c.purpose='identity.admin.session-revoke-all')`
		if err := f.pool.Raw().QueryRow(ctx, query, otpTenant, int64(audit.OutcomeSucceeded)).Scan(&commands, &revocations, &audits, &events); err != nil || commands != originalCommands+want || revocations != want || audits != want || events != want {
			t.Fatal("bulk revoke omitted or duplicated root command, exact receipt, success audit or lifecycle event", err)
		}
		if readTable([2]string{"identity", "users"}) != users {
			t.Fatal("session-only bulk invalidation changed a global user security version")
		}
	}
	assertEffects(1)
	var canonical []byte
	var beforeVersion, afterVersion string
	var revokedCount int64
	query := `SELECT a.canonical_record,j.before_version::text,j.subject_version::text,j.revoked_count FROM ` + journal + ` j JOIN identity.commands c ON c.command_id=j.command_id JOIN audit.identity_command_bindings b ON b.command_id=j.command_id JOIN audit.records a ON a.record_id=b.event_id WHERE j.tenant_id=$1 AND j.user_id=$2 AND j.subject_version=1 AND j.purpose='identity.admin.session-revoke-all' AND c.purpose=j.purpose`
	if err := f.pool.Raw().QueryRow(ctx, query, otpTenant, string(target.user)).Scan(&canonical, &beforeVersion, &afterVersion, &revokedCount); err != nil {
		t.Fatal("bulk revoke effects did not share the exact native target-set command", err)
	}
	audited, err := audit.ParseCanonicalJSON(canonical, audit.DefaultLimits())
	if err != nil || audited.Outcome() != audit.OutcomeSucceeded || audited.Action() != "identity.admin.session-revoke-all" || audited.Actor().ID() != string(actor.user) || audited.Subject().Type() != "session_set" || audited.Subject().ID() != string(target.user) || audited.Attributes()["retention.class"] != "protected" || beforeVersion != "0" || afterVersion != "1" || revokedCount != 2 {
		t.Fatal("bulk revoke lost protected human attribution or exact target-set transition", err)
	}
	ordinary, login := config.Session.Native, config.PasswordSignin.Native
	execution, validation := ordinary.Execution, ordinary.Validation
	execution.Authorization, execution.PolicyID, execution.PolicyVersion = policy, config.HTTPAdminSessionRevokeAll.PolicyID, uint64(config.HTTPAdminSessionRevokeAll.PolicyRevision)
	validation.Clock = execution.Clock
	reader, err := sessionpg.NewMFAPasswordSessionService(f.pool, sessionpg.SessionServiceConfig{Repository: execution.Repository, Profile: login.Profile, Validation: validation})
	if err != nil {
		t.Fatal("reconstruct native bulk receipt reader", err)
	}
	executor, err := sessionpg.NewAdminRevokeExecutor(f.pool, sessionpg.AdminRevokeExecutorConfig{Execution: execution, Sessions: reader, Actor: login.Profile, CSRFKey: login.CSRFKey})
	if err != nil {
		t.Fatal("reconstruct native bulk recovery owner", err)
	}
	commandID, err := identity.ParseCommandID(audited.Attributes()["command.id"])
	if err != nil {
		t.Fatal("exact bulk journal did not retain command correlation", err)
	}
	queryReceipt := identity.RecoveryQuery{CommandID: commandID, TenantID: otpTenant, UserID: target.user, ActorID: identity.ActorID(actor.user), ActorKind: authorization.SubjectUser, OperationID: "identity.admin.session-revoke-all", RecordID: string(target.user)}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{
		Tenant: otpTenant, Action: "identity.admin.session-revoke-all",
		Subject:  authorization.Subject{ID: authorization.SubjectID(actor.user), Kind: authorization.SubjectUser},
		Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(target.user)},
	}}
	checkOriginalReceipt := func() sessionpg.AdminRevokeAllRecoveryResult {
		t.Helper()
		receipt, err := executor.RecoverAdminSessionRevokeAll(ctx, queryReceipt, caller)
		if err != nil || receipt.Command.Outcome != identity.CommitOutcomeCommitted || receipt.Command.Feature == nil || receipt.Command.Feature.BeforeVersion != 0 || receipt.Command.Feature.AfterVersion != 1 || receipt.Result != (session.AdminSessionRevokeAllResult{RevokedCount: 2, SubjectVersion: 1}) {
			t.Fatal("original bulk count and version were not retained by exact native recovery", err)
		}
		return receipt
	}
	checkOriginalReceipt()
	status, repeated := invoke(body, actorCookies, actorCSRF, origin)
	if status != http.StatusOK || quotaCount() != quota+2 {
		t.Fatal("distinct bulk HTTP attempt did not charge quota once", status)
	}
	decode(repeated, 0, 2)
	assertEffects(2)
	settled := snapshot()
	receipt := checkOriginalReceipt()
	queryReceipt.RecordID = target.sessionID
	if _, err := executor.RecoverAdminSessionRevokeAll(ctx, queryReceipt, caller); err == nil || !reflect.DeepEqual(snapshot(), settled) {
		t.Fatal("session ID substituted for target-user recovery record disclosed or mutated state", err)
	}
	service, err := session.NewAdminRevokeAllService(reader, executor, session.AdminRevokeConfig{
		Authorization: policy, PolicyID: execution.PolicyID, PolicyRevision: authorization.Revision(execution.PolicyVersion), CSRFKey: login.CSRFKey, MaximumDuration: time.Second,
	})
	if err != nil {
		t.Fatal("reconstruct public native bulk service", err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, actorToken)
	if err != nil {
		t.Fatal("original native administrator credential unavailable")
	}
	csrf, err := session.ParseCSRFToken(actorCSRF)
	if err != nil {
		t.Fatal("original native administrator synchronizer unavailable")
	}
	replayed, err := service.AdminSessionRevokeAll(ctx, session.AdminSessionRevokeAllRequest{
		TenantID: otpTenant, ActorID: identity.SubjectID(actor.user), TargetSubjectID: identity.SubjectID(target.user), CommandID: commandID,
		CorrelationID: receipt.Command.Binding.CorrelationID, Credential: credential, CSRF: csrf,
	})
	if err != nil || replayed != receipt.Result || quotaCount() != quota+2 || !reflect.DeepEqual(snapshot(), settled) {
		t.Fatal("same native bulk command recomputed its outcome or duplicated effects after the next generation", err)
	}
	assertAuthentication(originalToken, target.user, target.sessionID, false)
	assertAuthentication(siblingToken, target.user, sibling.SessionID, false)
	assertAuthentication(actorToken, actor.user, actor.sessionID, true)
	assertAuthentication(otherToken, other.user, other.sessionID, true)
}
