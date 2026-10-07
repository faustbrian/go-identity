//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	authoritypg "github.com/faustbrian/go-authorization/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
)

// The protected email and audit/outbox effects are existing deliberate SQL
// seams. Session/credential authority, OTP and coordinator execution are real.
func TestNativeSessionOTPPrimaryComposition(t *testing.T) {
	for _, mode := range []string{"consume", "wrong-denial", "takeover", "rollback", "recovery-revoked", "recovery-unknown", "session-revoked", "family-revoked", "user-blocked", "credential-disabled", "stale-authorization", "stale-directory", "user-epoch", "identifier-epoch", "credential-epoch", "credential-version", "session-expired", "freshness-expired", "freshness-lock-expiry", "credential-lock-expiry"} {
		t.Run(mode, func(t *testing.T) {
			ctx, db, peer := otpDatabase(t)
			directory := kernel.DirectoryAuthorityMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 12}, Version: 13}, Version: 14, GlobalAuthorityID: "deployment", TenantIDs: []identity.TenantID{"tenant"}}
			for i, source := range []migrations.Source{directory, MigrationSource{Schema: "otp_store", Version: 100}, LockoutMigrationSource{Schema: "otp_store", Version: 101}, ConsumingMigrationSource{Schema: "otp_store", Version: 102}, sessionpg.MigrationSource{Schema: "session_store", Version: 200}} {
				h, err := source.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, m := range h {
					if i == 0 && m.Version() < 12 {
						continue
					}
					if _, err := db.Exec(ctx, m.UpSQL()); err != nil {
						t.Fatal(err)
					}
				}
			}
			m, _ := authoritypg.AuthoritySchemaMigration(300)
			if _, err := db.Exec(ctx, m.Up); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, `UPDATE identity.global_authorities SET version=2; UPDATE identity.tenant_authorities SET version=3; INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES('tenant','user','active',101,4,5,6); INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('tenant','user','credential',1,'identity/password',14,true); INSERT INTO authorization_subject_authorities VALUES('tenant','users','user',9); INSERT INTO otp_store.digest_keys VALUES(3,'hmac-sha256-v1'); CREATE TABLE public.native_otp_audits(event_id text PRIMARY KEY,command_id text UNIQUE NOT NULL,outcome text NOT NULL); CREATE TABLE public.native_otp_domain(command_id text PRIMARY KEY); CREATE TABLE public.native_otp_lifecycle(command_id text PRIMARY KEY,event_id text UNIQUE NOT NULL)`); err != nil {
				t.Fatal(err)
			}
			config, command, attempt, original := nativeSessionFixture(t)
			if mode == "session-expired" {
				config, command, attempt, original = nativeSessionFixture(t, 2*time.Hour)
			}
			if mode == "freshness-expired" {
				config.Session.FreshnessLimit = time.Nanosecond
			}
			if mode == "freshness-lock-expiry" {
				config.Session.FreshnessLimit = time.Minute + time.Second
			}
			if mode == "wrong-denial" {
				a, err := config.Codec.restoreAttempt(command, attempt)
				if err != nil {
					t.Fatal(err)
				}
				b, _ := a.Bindings()
				spec, _ := command.Feature()
				originalAuthority, err := config.Codec.restoreAuthority(spec)
				if err != nil {
					t.Fatal(err)
				}
				spec.Fields = []identity.FeatureField{{Name: "feature.flag", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}}}
				issuer, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
				wrong, _ := auth.NewOneTimeCode("654321")
				a, err = issuer.PrepareForCommand(ctx, spec.Binding, spec.Operation, b.Continuation, b.Mode, b.ExpectedVersion, wrong)
				if err != nil {
					t.Fatal(err)
				}
				token, _ := command.SessionToken()
				command, attempt, err = config.Codec.MapSessionWithAuthority(ctx, a, 3, spec, token, originalAuthority)
				if err != nil {
					t.Fatal(err)
				}
			}
			p, err := NewContributorWithSession(config.ContributorConfig, *config.Session)
			if err != nil {
				t.Fatal(err)
			}
			s, _ := original.Bindings()
			remember, _ := s.Remember.Bindings()
			vector, _ := s.Authority.Bindings()
			payload, err := json.Marshal(map[string]any{"Schema": 1, "SessionID": s.SessionID, "FamilyID": s.FamilyID, "TenantID": s.TenantID, "UserID": s.UserID, "Audience": s.Audience, "Version": s.Version, "FamilyVersion": s.FamilyVersion, "Remember": remember, "Authority": vector, "Lookup": s.Lookup, "Authentication": s.Authentication, "IssuedAt": s.IssuedAt, "LastActivityAt": s.LastActivityAt})
			if err != nil {
				t.Fatal(err)
			}
			lifetime, _ := original.Lifetime(s.LastActivityAt)
			const instant = "2006-01-02T15:04:05.000000000Z"
			if _, err := db.Exec(ctx, `INSERT INTO session_store.families VALUES('tenant','family','user',7,'active',$1)`, s.IssuedAt.Format(instant)); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, `INSERT INTO session_store.sessions VALUES('tenant','original-session','user','family',8,7,'active',3,$1,$2,$3::jsonb)`, s.Lookup.Sum[:], lifetime.ExpiresAt.Format(instant), payload); err != nil {
				t.Fatal(err)
			}
			// Scope and digest come from the original attempt, not the new plan.
			a, err := p.codec.restoreAttempt(command, attempt)
			if err != nil {
				t.Fatal(err)
			}
			ab, _ := a.Bindings()
			cb, _ := ab.Continuation.Bindings()
			keyBinding := p.lockout.binding()
			if _, err := db.Exec(ctx, `INSERT INTO otp_store.lockout_key_binding VALUES(true,$1)`, keyBinding[:]); err != nil {
				t.Fatal(err)
			}
			tx := admissionBegin(t, ctx, db)
			if err := p.lockout.initializeLockouts(ctx, sqlChallengeQuery(tx.Tx), sqlChallengeExec(tx.Tx), p.schema, cb.Scope); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			scope, _ := ab.Continuation.DigestScope()
			good, _ := auth.NewOneTimeCode("123456")
			verifier, _ := otp.NewVerifier(3, codecConfig().CodeKeys)
			digest, _ := verifier.Digest(scope, good)
			stored := digest.Storage()
			sd, _ := verifier.ScopeDigest(scope, 3)
			issue := otpCommand(t, ctx, db, "tenant", 77)
			if _, err := db.Exec(ctx, `WITH instant AS MATERIALIZED(SELECT clock_timestamp() AS now) UPDATE identity.commands SET state='committed',generation=1,attempt=1,lease_owner=$2,lease_until=instant.now,heartbeat_at=instant.now,created_at=instant.now,updated_at=instant.now,result_version=1,terminal_class='committed',result=$2,terminal_at=instant.now FROM instant WHERE command_id=$1`, issue, bytes.Repeat([]byte{77}, 16)); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, `INSERT INTO otp_store.challenges(tenant_id,challenge_id,subject_id,purpose,issue_command_id,issue_command_purpose,issue_fingerprint,digest_key_version,code_digest,scope_digest,policy_version,scope_generation,alphabet,code_length,ttl_us,resend_interval_us,maximum_sends,attempt_limit,replacement,checks_enabled,check_limit,lockout_us,issued_at,expires_at,state,version) VALUES('tenant','challenge','user','email-verification',$1,'identity.otp.send',$2,3,$3,$4,11,12,'0123456789',6,60000000,30000000,3,3,'retain',true,2,60000000,statement_timestamp(),statement_timestamp()+interval '60 seconds','issued',1)`, issue, bytes.Repeat([]byte{77}, 32), stored.Value[:], sd.Value[:]); err != nil {
				t.Fatal(err)
			}
			changes := map[string]string{"session-revoked": `UPDATE session_store.sessions SET state='revoked'`, "family-revoked": `UPDATE session_store.families SET state='revoked'`, "user-blocked": `UPDATE identity.users SET status='banned'`, "credential-disabled": `UPDATE identity.credential_references SET enabled=false`, "stale-authorization": `UPDATE authorization_subject_authorities SET version=10`, "stale-directory": `UPDATE identity.tenant_authorities SET version=4`, "user-epoch": `UPDATE identity.users SET authority_version=5`, "identifier-epoch": `UPDATE identity.users SET identifier_version=6`, "credential-epoch": `UPDATE identity.users SET credential_version=7`, "credential-version": `UPDATE identity.credential_references SET version=15`}
			if sql := changes[mode]; sql != "" {
				if _, err := db.Exec(ctx, sql); err != nil {
					t.Fatal(err)
				}
			}
			pool, err := database.New(ctx, database.Config{DSN: os.Getenv("IDENTITY_OTP_POSTGRES_TEST_DSN"), Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = db.Config().Database; return nil }})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := pool.Close(ctx); err != nil {
					t.Error(err)
				}
			})
			repo, _ := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
			spec, _ := command.Feature()
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, &contributorAudit{}, &contributorLifecycle{apply: true}, &contributorFeature{op: spec.Operation, apply: true, fail: mode == "rollback"}, p})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			plan, err := coordinator.PrepareOTPReservationPlan(spec.Binding, command, contributorPlan(t, registry, command, attempt))
			if err != nil {
				t.Fatal(err)
			}
			if mode == "wrong-denial" {
				plan, err = coordinator.PrepareOTPAttemptPlan(spec.Binding, command, contributorPlan(t, registry, command, attempt))
				if err != nil {
					t.Fatal(err)
				}
				result, err := coordinator.RecordOTPAttemptDenial(ctx, spec.Binding, command, plan)
				if err == nil || result.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("wrong session submission not denied", result.Outcome, err)
				}
				if result, err = coordinator.RecordOTPAttemptDenial(ctx, spec.Binding, command, plan); err != nil || result.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("stable session denial replay", result.Outcome, err)
				}
				var used, failed, domains, events, audits int
				if err := db.QueryRow(ctx, `SELECT (SELECT used_attempts FROM otp_store.challenges),(SELECT failed_attempts FROM otp_store.challenges),(SELECT count(*) FROM public.native_otp_domain),(SELECT count(*) FROM public.native_otp_lifecycle),(SELECT count(*) FROM public.native_otp_audits)`).Scan(&used, &failed, &domains, &events, &audits); err != nil {
					t.Fatal(err)
				}
				if used != 1 || failed != 1 || domains != 0 || events != 0 || audits != 1 {
					t.Fatal("session denial double charged or effects escaped", used, failed, domains, events, audits)
				}
				return
			}
			if mode == "freshness-lock-expiry" || mode == "credential-lock-expiry" {
				deadline := s.Authentication.Proof.IssuedAt.Add(config.Session.FreshnessLimit)
				if mode == "credential-lock-expiry" {
					if err := db.QueryRow(ctx, `UPDATE identity.credential_references SET expires_at=clock_timestamp()+interval '1 second' RETURNING expires_at`).Scan(&deadline); err != nil {
						t.Fatal(err)
					}
				}
				blocker, err := peer.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocker.Rollback(context.Background())
				if _, err := blocker.Exec(ctx, `SELECT challenge_id FROM otp_store.challenges FOR UPDATE`); err != nil {
					t.Fatal(err)
				}
				waitConsumingExpiry(t, ctx, db, deadline, func(run context.Context) error {
					_, _, err := coordinator.ReserveOTPCommand(run, spec.Binding, command, plan)
					return err
				}, func() error { return blocker.Rollback(ctx) })
				var state string
				var used, failed int
				if err := db.QueryRow(ctx, `SELECT state,used_attempts,failed_attempts FROM otp_store.challenges`).Scan(&state, &used, &failed); err != nil {
					t.Fatal(err)
				}
				if state != "issued" || used != 0 || failed != 0 {
					t.Fatal("wait renewed original validity", state, used, failed)
				}
				return
			}
			reservation, _, err := coordinator.ReserveOTPCommand(ctx, spec.Binding, command, plan)
			if changes[mode] != "" || mode == "session-expired" || mode == "freshness-expired" {
				if err == nil {
					t.Fatal("stale primary admitted")
				}
				var state string
				var used, failed int
				if err := db.QueryRow(ctx, `SELECT state,used_attempts,failed_attempts FROM otp_store.challenges`).Scan(&state, &used, &failed); err != nil {
					t.Fatal(err)
				}
				if state != "issued" || used != 0 || failed != 0 {
					t.Fatal("denial charged challenge", state, used, failed)
				}
				return
			}
			if err != nil {
				t.Fatal("native session reserve", err)
			}
			if mode == "takeover" {
				id, _ := base64.RawURLEncoding.Strict().DecodeString(string(spec.Binding.CommandID))
				if _, err := db.Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
					t.Fatal(err)
				}
				previous := reservation
				reservation, _, err = coordinator.ReserveOTPCommand(ctx, spec.Binding, command, plan)
				if err != nil {
					t.Fatal("session takeover", err)
				}
				if old, err := coordinator.Begin(ctx, previous); err == nil {
					coordinator.Abort(old, identity.UnavailableError{})
					t.Fatal("stale reservation retained authority")
				}
			}
			if mode == "recovery-revoked" || mode == "recovery-unknown" {
				id, _ := base64.RawURLEncoding.Strict().DecodeString(string(spec.Binding.CommandID))
				if _, err := db.Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1;`, id); err != nil {
					t.Fatal(err)
				}
				if mode == "recovery-revoked" {
					if _, err := db.Exec(ctx, `UPDATE session_store.sessions SET state='revoked'`); err != nil {
						t.Fatal(err)
					}
				}
				cc := codecConfig()
				if mode == "recovery-unknown" {
					cc.WrappingKeys["wrap-1"] = bytes.Repeat([]byte{0x22}, 32)
				}
				freshCodec, err := NewAttemptCodec(cc)
				if err != nil {
					t.Fatal(err)
				}
				config.Codec = freshCodec
				fresh, err := NewContributorWithSession(config.ContributorConfig, *config.Session)
				if err != nil {
					t.Fatal(err)
				}
				r, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, &contributorAudit{}, &contributorLifecycle{apply: true}, &contributorFeature{op: spec.Operation, apply: true}, fresh})
				if err != nil {
					t.Fatal(err)
				}
				restarted, err := kernel.NewCoordinator(pool, r, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &kernel.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: contributorQueryPolicy{}}})
				if err != nil {
					t.Fatal(err)
				}
				b := spec.Binding
				query := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID, LinkMode: b.LinkMode}
				caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Tenant: authorization.TenantID(b.TenantID), Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
				command, reservation = identity.Command{}, kernel.Reservation{}
				result, err := restarted.RecoverFeatureCommand(ctx, query, caller)
				want := identity.CommitOutcomeNotCommitted
				if mode == "recovery-unknown" {
					want = identity.CommitOutcomeInProgress
				}
				if err == nil || result.Outcome != want {
					t.Fatal("session restart recovery", result.Outcome, err)
				}
				var state string
				var used, domains int
				if err := db.QueryRow(ctx, `SELECT (SELECT state FROM otp_store.challenges),(SELECT used_attempts FROM otp_store.challenges),(SELECT count(*) FROM public.native_otp_domain)`).Scan(&state, &used, &domains); err != nil {
					t.Fatal(err)
				}
				wantState := "released"
				if mode == "recovery-unknown" {
					wantState = "reserved"
				}
				if state != wantState || used != 1 || domains != 0 {
					t.Fatal("unknown released or revoked session stranded OTP", state, used, domains)
				}
				return
			}
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer coordinator.Abort(work, identity.UnavailableError{})
			result, err := coordinator.ApplyFeature(ctx, work, command)
			if mode == "rollback" {
				if err == nil {
					t.Fatal("domain failure ignored")
				}
				result, err = coordinator.Abort(work, err)
				if err == nil || result.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("session rollback ambiguous", result.Outcome, err)
				}
				var state, ss string
				var used, domains int
				if err := db.QueryRow(ctx, `SELECT (SELECT state FROM otp_store.challenges),(SELECT state FROM session_store.sessions),(SELECT used_attempts FROM otp_store.challenges),(SELECT count(*) FROM public.native_otp_domain)`).Scan(&state, &ss, &used, &domains); err != nil {
					t.Fatal(err)
				}
				if state != "released" || ss != "active" || used != 1 || domains != 0 {
					t.Fatal("session rollback escaped", state, ss, used, domains)
				}
				return
			}
			if err != nil {
				t.Fatal("native session apply", err)
			}
			if _, err = coordinator.Commit(work, result); err != nil {
				t.Fatal("native session commit", err)
			}
			var otpState, sessionState string
			var used, domains int
			if err := db.QueryRow(ctx, `SELECT (SELECT state FROM otp_store.challenges),(SELECT state FROM session_store.sessions),(SELECT used_attempts FROM otp_store.challenges),(SELECT count(*) FROM public.native_otp_domain)`).Scan(&otpState, &sessionState, &used, &domains); err != nil {
				t.Fatal(err)
			}
			if otpState != "finalized" || sessionState != "active" || used != 1 || domains != 1 {
				t.Fatal("session consumed or effects incomplete", otpState, sessionState, used, domains)
			}
		})
	}
}
