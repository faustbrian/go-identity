//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5/pgconn"
)

// Real coordinator/primary admission, not an OAuth provider or session proof.
// The feature participant below is the existing native test seam; these cases
// cannot establish the unimplemented protected linking or social-signin journey.
func TestProviderAccountAdmissionPrimaryFence(t *testing.T) {
	ctx, pool, repo := newAccountAuthorityStore(t)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Raw().Exec(ctx, sql, args...); err != nil {
			t.Fatal("provider admission fixture", err)
		}
	}
	exec(`CREATE TABLE public.identity_test_feature_audits(event_id text PRIMARY KEY,command_id text NOT NULL,event_index integer NOT NULL,retention_class text NOT NULL,UNIQUE(command_id,event_index));
 CREATE TABLE public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
 CREATE TABLE public.identity_test_feature(tenant_id text,record_id text,command_id text UNIQUE,value text,PRIMARY KEY(tenant_id,record_id));
 INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES('provider-admission','user','active',101,11,13,17);
 INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('provider-admission','user','provider-ref',3,'identity/oauth',7,true);
 WITH metadata AS (SELECT 'oidc-local'::text AS provider,'https://issuer.example'::text AS issuer,'subject-one'::text AS subject)
 INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
 SELECT 'provider-admission','user','account',provider,issuer,subject,sha256(convert_to(octet_length(provider)::text||':'||provider||octet_length(issuer)::text||':'||issuer||octet_length(subject)::text||':'||subject,'UTF8')),5,3,true FROM metadata;
 INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES('provider-admission','user','provider-ref','account')`)
	base := ProviderAccountAdmission{Account: identity.Account{ID: "account", TenantID: "provider-admission", UserID: "user", Provider: "oidc-local", Issuer: "https://issuer.example", Subject: "subject-one", Version: 5}, SocialLinkVersion: 3, Credential: CredentialAdmission{Credential: identity.CredentialRef{ID: "provider-ref", TenantID: "provider-admission", UserID: "user", Kind: identity.CredentialProvider, Owner: "identity/oauth", Version: 7}, UserAuthorityVersion: 11, IdentifierAuthorityVersion: 13, CredentialAuthorityVersion: 17}}
	for _, mode := range []string{"exact", "wrong-account-version", "wrong-social-version", "wrong-provider", "wrong-issuer", "wrong-subject", "missing-association", "unlinked", "disabled", "blocked-user", "stale-credential", "expired", "expired-during-account-lock-wait", "expired-during-association-lock-wait"} {
		t.Run(mode, func(t *testing.T) {
			exec(`UPDATE identity.users SET status='active' WHERE tenant_id='provider-admission';
 UPDATE identity.accounts SET linked=true WHERE tenant_id='provider-admission';
 UPDATE identity.credential_references SET enabled=true,version=7,expires_at=NULL WHERE tenant_id='provider-admission';
 INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES('provider-admission','user','provider-ref','account') ON CONFLICT DO NOTHING`)
			expected := base
			switch mode {
			case "wrong-account-version":
				expected.Account.Version++
			case "wrong-social-version":
				expected.SocialLinkVersion++
			case "wrong-provider":
				expected.Account.Provider = "other-provider"
			case "wrong-issuer":
				expected.Account.Issuer = "https://other.example"
			case "wrong-subject":
				expected.Account.Subject = "other-subject"
			case "missing-association":
				exec(`DELETE FROM identity.account_credentials WHERE tenant_id='provider-admission'`)
			case "unlinked":
				exec(`UPDATE identity.accounts SET linked=false WHERE tenant_id='provider-admission'`)
			case "disabled":
				exec(`UPDATE identity.credential_references SET enabled=false WHERE tenant_id='provider-admission'`)
			case "blocked-user":
				exec(`UPDATE identity.users SET status='banned' WHERE tenant_id='provider-admission'`)
			case "stale-credential":
				exec(`UPDATE identity.credential_references SET version=8 WHERE tenant_id='provider-admission'`)
			case "expired":
				exec(`UPDATE identity.credential_references SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id='provider-admission'`)
			}
			allowed := mode == "exact"
			expiryWait := mode == "expired-during-account-lock-wait" || mode == "expired-during-association-lock-wait"
			phase := &featureExecutionPhase{}
			phase.targetCheck = func(call context.Context, work Work, owner *featureExecutionPhase) error {
				if expiryWait {
					binding, _, _, err := work.FeatureScope(owner)
					if err != nil {
						return err
					}
					if _, err := work.Exec(call, `INSERT INTO public.identity_test_feature(tenant_id,record_id,command_id,value) VALUES($1,$2,$3,'provisional-before-provider-admission')`, string(binding.TenantID), binding.RecordID, string(binding.CommandID)); err != nil {
						return err
					}
				}
				before, _ := work.state.ctx.Deadline()
				now, err := work.RequireActiveProviderAccount(call, owner, expected)
				after, _ := work.state.ctx.Deadline()
				if before != after {
					t.Fatal("link admission renewed original Work lifetime")
				}
				if !allowed {
					var denied identity.ForbiddenError
					if !errors.As(err, &denied) || !now.IsZero() {
						t.Fatal("stale provider account was admitted", err)
					}
					// Ignoring the denial must not let the original feature persist.
					return nil
				}
				if err != nil || now.IsZero() {
					t.Fatal("current provider account denied", err)
				}
				for _, sql := range []string{`SELECT user_id FROM identity.users WHERE tenant_id='provider-admission' FOR UPDATE NOWAIT`, `SELECT credential_id FROM identity.credential_references WHERE tenant_id='provider-admission' FOR UPDATE NOWAIT`, `SELECT account_id FROM identity.accounts WHERE tenant_id='provider-admission' FOR UPDATE NOWAIT`, `SELECT account_id FROM identity.account_credentials WHERE tenant_id='provider-admission' FOR UPDATE NOWAIT`} {
					other, err := pool.Raw().Begin(call)
					if err != nil {
						return err
					}
					_, err = other.Exec(call, sql)
					_ = other.Rollback(call)
					var locked *pgconn.PgError
					if !errors.As(err, &locked) || locked.Code != "55P03" {
						t.Fatal("provider authority lock escaped before commit")
					}
				}
				return nil
			}
			auditing := &featureExecutionAuditPhase{}
			denialAudits := 0
			if expiryWait {
				// Abort records the denial in a separate transaction after rolling
				// back the domain transaction; that audit is not a success effect.
				auditing.afterPersist = func(_ context.Context, terminal Work) error {
					records, err := terminal.StagedAudits()
					if err != nil {
						return err
					}
					if len(records) != 1 || records[0].Record.Outcome() != audit.OutcomeDenied || records[0].Record.ReasonCode() != "not_authorized" || !records[0].Record.Changes().NoChange() {
						return errors.New("provider expiry did not persist an exact no-change denial audit")
					}
					denialAudits++
					return nil
				}
			}
			registry, err := NewContributorRegistry([]Contributor{repo, auditing, &recoveryLifecyclePhase{}, phase})
			if err != nil {
				t.Fatal(err)
			}
			maximumDuration := 2 * time.Second
			if expiryWait {
				maximumDuration = 3 * time.Second
			}
			coordinator, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: maximumDuration, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			spec := featureCodecSpec()
			spec.Binding.TenantID, spec.Binding.UserID, spec.Binding.ActorID = "provider-admission", "user", "user"
			spec.Binding.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			spec.Binding.RecordID = string(spec.Binding.CommandID)
			spec.Fields = []identity.FeatureField{{Name: "value", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "synthetic-provider-fence"}}}
			command := featureCodecCommand(t, spec)
			_, _, plan := featurePlanFixture(t)
			plan.Contributors, plan.Feature, plan.SubjectType = registry.Descriptors(), &FeatureRegistration{Contributor: phase.Descriptor(), Operation: spec.Operation}, "session"
			plan.Audits[0].RetentionClass = "standard"
			seed, err := securityMutationAudit(ctx, spec.Binding, 0, 1, time.Now().UTC().Truncate(time.Microsecond), "committed", "session.issue", "session", spec.Binding.RecordID, "standard", true)
			if err != nil {
				t.Fatal(err)
			}
			plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(spec.Binding, spec.Operation, "session", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err = coordinator.PrepareCommandPlan(spec.Binding, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, spec.Binding, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer coordinator.Abort(work, identity.UnavailableError{})
			var expiryWaitResult <-chan error
			expiryWaitJoined := false
			if expiryWait {
				var expires time.Time
				if err := pool.Raw().QueryRow(ctx, `UPDATE identity.credential_references SET expires_at=clock_timestamp()+interval '1 second' WHERE tenant_id='provider-admission' RETURNING expires_at`).Scan(&expires); err != nil {
					t.Fatal("credential expiry fixture", err)
				}
				blocker, err := pool.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocker.Rollback(ctx)
				table := "identity.accounts"
				if mode == "expired-during-association-lock-wait" {
					table = "identity.account_credentials"
				}
				if _, err := blocker.Exec(ctx, `SELECT account_id FROM `+table+` WHERE tenant_id='provider-admission' AND account_id='account' FOR UPDATE`); err != nil {
					t.Fatal("provider row-lock fixture", err)
				}
				waiting, stopWaiting := context.WithTimeout(ctx, 2*time.Second)
				done := make(chan error, 1)
				expiryWaitResult = done
				defer func() {
					stopWaiting()
					if !expiryWaitJoined {
						<-done
					}
				}()
				go func() {
					done <- func() error {
						defer func() {
							cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
							defer stop()
							_ = blocker.Rollback(cleanup)
						}()
						for {
							if _, err := blocker.Exec(waiting, `SELECT pg_stat_clear_snapshot()`); err != nil {
								return err
							}
							var blocked, stillActive bool
							if err := blocker.QueryRow(waiting, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND pg_backend_pid()=ANY(pg_blocking_pids(pid)) AND query LIKE 'SELECT a.account_id,%'),clock_timestamp()<$1::timestamptz`, expires).Scan(&blocked, &stillActive); err != nil {
								return err
							}
							if !stillActive {
								return errors.New("provider admission did not reach the held row while the credential was active")
							}
							if blocked {
								break
							}
							select {
							case <-waiting.Done():
								return waiting.Err()
							case <-time.After(time.Millisecond):
							}
						}
						// A pre-link-lock credential sample must not survive the
						// unchanged primary expiry crossing during this actual wait.
						_, err := blocker.Exec(waiting, `SELECT pg_sleep_until($1::timestamptz+interval '10 milliseconds')`, expires)
						return err
					}()
				}()
			}
			result, err := coordinator.ApplyFeature(ctx, work, command)
			if expiryWaitResult != nil {
				waitErr := <-expiryWaitResult
				expiryWaitJoined = true
				if waitErr != nil {
					t.Fatal("credential expiry during provider row-lock wait", waitErr)
				}
			}
			if allowed && err != nil {
				t.Fatal("current admission could not apply", err)
			}
			if !allowed {
				var denied identity.ForbiddenError
				if !errors.As(err, &denied) {
					t.Fatal("ignored provider denial did not poison execution", err)
				}
			}
			result, err = coordinator.Commit(work, result)
			want := identity.CommitOutcomeNotCommitted
			if allowed {
				want = identity.CommitOutcomeCommitted
			}
			if result.Outcome != want {
				t.Fatal("provider guard produced incorrect durable outcome", err)
			}
			var effects int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.identity_test_feature WHERE command_id=$1`, string(spec.Binding.CommandID)).Scan(&effects); err != nil || effects != map[bool]int{true: 1, false: 0}[allowed] {
				t.Fatal("provider denial leaked a provisional domain effect", err)
			}
			if expiryWait {
				if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.identity_test_feature_audits WHERE command_id=$1`, string(spec.Binding.CommandID)).Scan(&effects); err != nil || effects != 1 || denialAudits != 1 {
					t.Fatal("expired provider admission lost or duplicated its terminal denial audit", err)
				}
				if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$1`, string(spec.Binding.CommandID)).Scan(&effects); err != nil || effects != 0 {
					t.Fatal("expired provider admission leaked success lifecycle effects", err)
				}
			}
		})
	}
}
