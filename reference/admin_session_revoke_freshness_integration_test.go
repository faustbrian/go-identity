//go:build integration

package reference_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/jackc/pgx/v5"
)

func proveReferenceAdminSessionRevokeFinalFreshness(t *testing.T, ctx context.Context, f liveStores, config reference.StoreConfiguration, actor identity.UserID, actorSession string, target identity.UserID, targetSessionID string, actorWire string, actorCSRF string, policy *referenceAdminSessionRevokePolicy) {
	t.Helper()
	if actor == target || policy.actor != actor || policy.target != target {
		t.Fatal("late administrator revoke requires the original authorized actor and distinct target")
	}
	profile := referenceAdminSessionRevokeFreshnessProfile{
		policy: policy, policyID: config.HTTPAdminSessionRevoke.PolicyID, revision: config.HTTPAdminSessionRevoke.PolicyRevision,
		operation: "identity.admin.session-revoke", journal: "session_revocations",
		provisionalMutation: func(schema string) string {
			return `EXISTS (SELECT 1 FROM ` + pgx.Identifier{schema, "sessions"}.Sanitize() + ` WHERE tenant_id=NEW.tenant_id AND session_id=NEW.subject_id AND state='revoked')`
		},
		newCall: func(reader *session.SessionService, executor *sessionpg.AdminRevokeExecutor, c session.AdminRevokeConfig) (referenceAdminSessionRevokeFreshnessCall, error) {
			service, err := session.NewAdminRevokeService(reader, executor, c)
			return func(ctx context.Context, id identity.CommandID, credential session.Credential, csrf session.CSRFToken) (bool, error) {
				result, revokeErr := service.AdminSessionRevoke(ctx, session.AdminSessionRevokeRequest{
					TenantID: otpTenant, ActorID: identity.SubjectID(actor), TargetSubjectID: identity.SubjectID(target),
					SessionID: targetSessionID, CommandID: id, CorrelationID: string(id), Credential: credential, CSRF: csrf,
				})
				return result != (session.AdminSessionRevokeResult{}), revokeErr
			}, err
		},
	}
	proveReferenceAdminSessionRevokeFreshness(t, ctx, f, config, actor, actorSession, actorWire, actorCSRF, profile)
}

func proveReferenceAdminSessionRevokeAllFinalFreshness(t *testing.T, ctx context.Context, f liveStores, config reference.StoreConfiguration, actor identity.UserID, actorSession string, target identity.UserID, actorWire, actorCSRF string, policy *referenceAdminSessionRevokeAllPolicy) {
	t.Helper()
	if actor == target || policy.actor != actor || policy.target != target {
		t.Fatal("late administrator bulk revoke requires the original authorized actor and distinct target")
	}
	profile := referenceAdminSessionRevokeFreshnessProfile{
		policy: policy, policyID: config.HTTPAdminSessionRevokeAll.PolicyID, revision: config.HTTPAdminSessionRevokeAll.PolicyRevision,
		operation: "identity.admin.session-revoke-all", journal: "admin_set_revocations",
		provisionalMutation: func(schema string) string {
			return `(SELECT count(*) FROM ` + pgx.Identifier{schema, "sessions"}.Sanitize() + ` WHERE tenant_id=NEW.tenant_id AND user_id=NEW.subject_id AND state='revoked')=2
 AND EXISTS (SELECT 1 FROM ` + pgx.Identifier{schema, "admin_set_revocations"}.Sanitize() + ` WHERE tenant_id=NEW.tenant_id AND user_id=NEW.subject_id
 AND command_id=decode(translate(NEW.correlation_id,'-_','+/') || '==','base64')
 AND purpose=NEW.action AND before_version=0 AND subject_version=1 AND revoked_count=2)`
		},
		newCall: func(reader *session.SessionService, executor *sessionpg.AdminRevokeExecutor, c session.AdminRevokeConfig) (referenceAdminSessionRevokeFreshnessCall, error) {
			service, err := session.NewAdminRevokeAllService(reader, executor, c)
			return func(ctx context.Context, id identity.CommandID, credential session.Credential, csrf session.CSRFToken) (bool, error) {
				result, revokeErr := service.AdminSessionRevokeAll(ctx, session.AdminSessionRevokeAllRequest{
					TenantID: otpTenant, ActorID: identity.SubjectID(actor), TargetSubjectID: identity.SubjectID(target),
					CommandID: id, CorrelationID: string(id), Credential: credential, CSRF: csrf,
				})
				return result != (session.AdminSessionRevokeAllResult{}), revokeErr
			}, err
		},
	}
	proveReferenceAdminSessionRevokeFreshness(t, ctx, f, config, actor, actorSession, actorWire, actorCSRF, profile)
}

type referenceAdminSessionRevokeFreshnessCall func(context.Context, identity.CommandID, session.Credential, session.CSRFToken) (bool, error)

type referenceAdminSessionRevokeFreshnessProfile struct {
	policy              authorization.Service
	policyID            string
	revision            authorization.Revision
	operation           string
	journal             string
	provisionalMutation func(string) string
	newCall             func(*session.SessionService, *sessionpg.AdminRevokeExecutor, session.AdminRevokeConfig) (referenceAdminSessionRevokeFreshnessCall, error)
}

func proveReferenceAdminSessionRevokeFreshness(t *testing.T, ctx context.Context, f liveStores, config reference.StoreConfiguration, actor identity.UserID, actorSession, actorWire, actorCSRF string, profile referenceAdminSessionRevokeFreshnessProfile) {
	t.Helper()
	ordinary, login := config.Session.Native, config.PasswordSignin.Native
	execution, validation := ordinary.Execution, ordinary.Validation
	execution.Authorization = profile.policy
	execution.PolicyID = profile.policyID
	execution.PolicyVersion = uint64(profile.revision)
	// The ordinary timeout must outlive the injected phase. Only the original
	// actor freshness deadline should prevent the final native commit.
	execution.Coordinator.MaximumDuration = 4 * time.Second
	execution.Coordinator.LeaseDuration = 10 * time.Second
	validation.Clock = execution.Clock
	reader, err := sessionpg.NewMFAPasswordSessionService(f.pool, sessionpg.SessionServiceConfig{
		Repository: execution.Repository, Profile: login.Profile, Validation: validation,
	})
	if err != nil {
		t.Fatal("configure native late-freshness reader", err)
	}
	executor, err := sessionpg.NewAdminRevokeExecutor(f.pool, sessionpg.AdminRevokeExecutorConfig{
		Execution: execution, Sessions: reader, Actor: login.Profile, CSRFKey: login.CSRFKey,
	})
	if err != nil {
		t.Fatal("configure native late-freshness executor", err)
	}
	invoke, err := profile.newCall(reader, executor, session.AdminRevokeConfig{
		Authorization: profile.policy, PolicyID: execution.PolicyID, PolicyRevision: authorization.Revision(execution.PolicyVersion),
		CSRFKey: login.CSRFKey, MaximumDuration: 4 * time.Second,
	})
	if err != nil {
		t.Fatal("configure native late-freshness service", err)
	}
	token, err := session.ParseToken(actorWire)
	if err != nil {
		t.Fatal("original administrator cookie unavailable")
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal("original administrator credential unavailable")
	}
	csrf, err := session.ParseCSRFToken(actorCSRF)
	if err != nil {
		t.Fatal("original administrator synchronizer unavailable")
	}
	original, err := reader.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !original.Authenticated {
		t.Fatal("late-freshness fixture lost genuine administrator authentication", err)
	}
	source, err := original.Session.Bindings()
	if err != nil || source.UserID != actor || source.SessionID != actorSession {
		t.Fatal("late-freshness fixture changed original administrator scope")
	}
	factor, err := original.Session.MFAAuthentication().Bindings()
	if err != nil || factor.Method != "totp" {
		t.Fatal("late-freshness fixture requires genuine completed password/TOTP authentication")
	}
	schema := execution.Repository.Schema
	sessions := pgx.Identifier{schema, "sessions"}.Sanitize()
	var originalRecord []byte
	var originalExpiry string
	if err := f.pool.Raw().QueryRow(ctx, `SELECT record::text,expires_at FROM `+sessions+` WHERE tenant_id=$1 AND user_id=$2 AND session_id=$3`, otpTenant, string(actor), actorSession).Scan(&originalRecord, &originalExpiry); err != nil {
		t.Fatal("read original isolated administrator record", err)
	}
	snapshot := func(t *testing.T) []string {
		t.Helper()
		tables := [][2]string{
			{schema, "sessions"}, {schema, "families"}, {schema, profile.journal},
			{"public", "identity_outbox_bindings"}, {"public", "outbox_messages"},
		}
		state := make([]string, len(tables)+1)
		for i, table := range tables {
			query := `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM ` + pgx.Identifier{table[0], table[1]}.Sanitize() + ` r`
			if err := f.pool.Raw().QueryRow(ctx, query).Scan(&state[i]); err != nil {
				t.Fatal("observe protected late-freshness state", err)
			}
		}
		if err := f.pool.Raw().QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM audit.records r WHERE action=$1 AND outcome=$2`, profile.operation, int64(audit.OutcomeSucceeded)).Scan(&state[len(tables)]); err != nil {
			t.Fatal("observe protected administrator success audits", err)
		}
		return state
	}
	t.Run("original primary freshness", func(t *testing.T) {
		commandID, err := identity.NewCommandID()
		if err != nil {
			t.Fatal("allocate original delayed command correlation", err)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			if _, err := f.pool.Raw().Exec(cleanup, `DROP TRIGGER IF EXISTS admin_revoke_freshness_delay ON audit.records; DROP FUNCTION IF EXISTS public.admin_revoke_freshness_delay(); DROP SEQUENCE IF EXISTS public.admin_revoke_freshness_phase`); err != nil {
				t.Error("remove owned late-phase fixture", err)
			}
			n, err := f.pool.Raw().Exec(cleanup, `UPDATE `+sessions+` SET record=$1::jsonb,expires_at=$2 WHERE tenant_id=$3 AND user_id=$4 AND session_id=$5`, string(originalRecord), originalExpiry, otpTenant, string(actor), actorSession)
			if err != nil || n.RowsAffected() != 1 {
				t.Error("restore original isolated administrator record", err)
			}
		}()
		// nextval survives the aborted Work transaction. The exact command's
		// success audit also observes the provisional target mutation, so an
		// early authentication failure cannot masquerade as this regression.
		delay := `CREATE SEQUENCE public.admin_revoke_freshness_phase;
CREATE FUNCTION public.admin_revoke_freshness_delay() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.action='` + profile.operation + `' AND NEW.outcome=1 AND NEW.correlation_id=TG_ARGV[0] THEN
  IF NOT (` + profile.provisionalMutation(schema) + `) THEN
   RAISE EXCEPTION 'late-phase fixture did not observe provisional target revocation';
  END IF;
  PERFORM nextval('public.admin_revoke_freshness_phase');
  PERFORM pg_sleep(3);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER admin_revoke_freshness_delay BEFORE INSERT ON audit.records FOR EACH ROW
EXECUTE FUNCTION public.admin_revoke_freshness_delay('` + string(commandID) + `')`
		if _, err := f.pool.Raw().Exec(ctx, delay); err != nil {
			t.Fatal("install exact-command late audit delay", err)
		}

		now := time.Now().UTC()
		cutoff := now.Add(2 * time.Second)
		remember, err := source.Remember.Bindings()
		if err != nil || remember.FreshFor != 15*time.Minute {
			t.Fatal("late-freshness fixture requires the selected original fifteen-minute primary policy", err)
		}
		agedSource, agedFactor := source, factor
		agedSource.Authentication.Proof.IssuedAt = cutoff.Add(-remember.FreshFor)
		agedFactor.VerifiedAt = agedSource.Authentication.Proof.IssuedAt.Add(time.Minute)
		agedSource.Authentication.Proof.ExpiresAt = agedSource.Authentication.Proof.IssuedAt.Add(5 * time.Minute)
		agedFactor.ValidUntil = agedFactor.VerifiedAt.Add(time.Minute)
		agedSource.IssuedAt = agedFactor.VerifiedAt.Add(time.Millisecond)
		agedSource.LastActivityAt = now
		completed, err := session.NewMFAAuthentication(agedFactor)
		if err != nil {
			t.Fatal("construct coherent original TOTP timeline", err)
		}
		aged, err := session.NewSessionWithPasswordMFAAndCSRF(agedSource, completed, original.Session.CSRFState())
		if err != nil {
			t.Fatal("construct coherent original administrator timeline", err)
		}
		lifetime, err := aged.Lifetime(now)
		if err != nil || !lifetime.Fresh || !lifetime.ExpiresAt.After(cutoff.Add(4*time.Second)) {
			t.Fatal("freshness fixture accidentally expired ordinary session lifetime", err)
		}
		var stored map[string]json.RawMessage
		if json.Unmarshal(originalRecord, &stored) != nil {
			t.Fatal("decode original isolated administrator record")
		}
		for key, value := range map[string]any{
			"Authentication": agedSource.Authentication, "Remember": remember, "MFA": agedFactor,
			"IssuedAt": agedSource.IssuedAt, "LastActivityAt": agedSource.LastActivityAt,
		} {
			stored[key], err = json.Marshal(value)
			if err != nil {
				t.Fatal("encode coherent isolated administrator timeline")
			}
		}
		payload, err := json.Marshal(stored)
		if err != nil {
			t.Fatal("encode isolated administrator record")
		}
		const storedTime = "2006-01-02T15:04:05.000000000Z"
		n, err := f.pool.Raw().Exec(ctx, `UPDATE `+sessions+` SET record=$1::jsonb,expires_at=$2 WHERE tenant_id=$3 AND user_id=$4 AND session_id=$5`, string(payload), lifetime.ExpiresAt.UTC().Format(storedTime), otpTenant, string(actor), actorSession)
		if err != nil || n.RowsAffected() != 1 {
			t.Fatal("store coherent isolated administrator freshness boundary", err)
		}
		before := snapshot(t)
		caller, err := reader.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
		if err != nil || !caller.Authenticated || caller.ValidateAt(time.Now()) != nil {
			t.Fatal("near-expiry original administrator must still authenticate before delayed Work", err)
		}
		confirmed, revokeErr := invoke(ctx, commandID, credential, csrf)
		if revokeErr == nil || confirmed {
			t.Fatal("administrator revoke confirmed a mutation after original freshness expired")
		}
		var reached bool
		var visits int64
		if err := f.pool.Raw().QueryRow(ctx, `SELECT is_called,last_value FROM public.admin_revoke_freshness_phase`).Scan(&reached, &visits); err != nil || !reached || visits != 1 {
			t.Fatal("late-freshness denial did not reach exact post-mutation success-audit phase", err)
		}
		if time.Now().Before(cutoff) {
			t.Fatal("late-freshness fixture failed before its original deadline")
		}
		if !reflect.DeepEqual(snapshot(t), before) {
			t.Fatal("expired administrator committed target, sibling, family, revocation, success audit or outbox changes")
		}
		stillActor, err := reader.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
		if err != nil || !stillActor.Authenticated {
			t.Fatal("freshness denial changed the original administrator credential", err)
		}
		binding, err := stillActor.Session.Bindings()
		if err != nil || binding.UserID != actor || binding.SessionID != actorSession || binding.Version != source.Version {
			t.Fatal("freshness denial changed original administrator identity or session version")
		}
	})
}
