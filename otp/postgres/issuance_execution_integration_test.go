//go:build integration

package postgres

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	authoritypg "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
)

func TestNativeIssuanceCoordinatorAtomicity(t *testing.T) {
	for _, mode := range []string{"committed", "anonymous-committed", "anonymous-delivery-rollback", "audit-rollback", "delivery-rollback", "blocked", "user-epoch", "identifier-epoch", "credential-epoch", "authorization-epoch", "directory-epoch", "missing-flow"} {
		t.Run(mode, func(t *testing.T) {
			committed := mode == "committed" || mode == "anonymous-committed"
			ctx, db, _, preauth := admissionDatabase(t)
			directory := kernel.DirectoryAuthorityMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 12}, Version: 13}, Version: 14, GlobalAuthorityID: "deployment", TenantIDs: []identity.TenantID{"tenant"}}
			for _, source := range []migrations.Source{directory, MigrationSource{Schema: "otp_store", Version: 100}, LockoutMigrationSource{Schema: "otp_store", Version: 101}, SendFamilyMigrationSource{Schema: "otp_store", Version: 102}, IssuanceMigrationSource{Schema: "otp_store", Version: 103}, deliverypg.MigrationSource{Base: kernel.MigrationSource{}, Version: 250}} {
				ms, err := source.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, m := range ms {
					if m.Version() < 12 {
						continue
					}
					if _, err := db.Exec(ctx, m.UpSQL()); err != nil {
						t.Fatal("native issuance migration", err)
					}
				}
			}
			files, err := fs.ReadDir(outboxpg.Migrations(), ".")
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range files {
				wire, err := fs.ReadFile(outboxpg.Migrations(), f.Name())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(ctx, strings.Split(string(wire), "-- +migrations Down")[0]); err != nil {
					t.Fatal("owned outbox migration", err)
				}
			}
			m, err := authoritypg.AuthoritySchemaMigration(300)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, m.Up); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, `UPDATE identity.global_authorities SET version=2; UPDATE identity.tenant_authorities SET version=3;
 INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES('tenant','user','active',101,11,13,17);
 INSERT INTO otp_store.digest_keys VALUES(3,'hmac-sha256-v1');
 CREATE TABLE public.native_otp_audits(event_id text PRIMARY KEY,command_id text UNIQUE NOT NULL,outcome text NOT NULL);
 CREATE TABLE public.native_otp_lifecycle(command_id text PRIMARY KEY,event_id text UNIQUE NOT NULL)`); err != nil {
				t.Fatal(err)
			}
			tx := admissionBegin(t, ctx, db)
			if _, err := authoritypg.InitializeAuthority(ctx, tx.Tx, authoritypg.AuthorityScope{TenantID: "tenant", PolicyNamespace: "users", SubjectID: "user"}, time.Second); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			var now time.Time
			if err := db.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
				t.Fatal(err)
			}
			profileName := "user-valid"
			if strings.HasPrefix(mode, "anonymous-") {
				profileName = "anonymous"
			}
			store, attemptCommand, _, original, attempt := contributorCommand(t, now.Add(-time.Second), "123456", profileName)
			admissionInsert(t, ctx, db, preauth, original)
			binding := store.lockout.binding()
			if _, err := db.Exec(ctx, `INSERT INTO otp_store.lockout_key_binding VALUES(true,$1)`, binding[:]); err != nil {
				t.Fatal(err)
			}
			spec, _ := attemptCommand.Feature()
			authority, err := store.codec.restoreAuthority(spec)
			if err != nil {
				t.Fatal(err)
			}
			ab, _ := attempt.Bindings()
			profile, err := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposeSignin, Alphabet: "0123456789", Length: 6, TTL: time.Minute, ResendInterval: 30 * time.Second, MaximumSends: 3, Attempts: 3, Replacement: otp.ReplacePrevious})
			if err != nil {
				t.Fatal(err)
			}
			policy, _ := otp.NewAttemptPolicy(profile, otp.CheckPolicySpec{Enabled: true, MaximumChecks: 2, LockoutAfter: time.Minute})
			scope, _ := ab.Continuation.DigestScope()
			v, _ := otp.NewVerifier(3, codecConfig().CodeKeys)
			code, _ := auth.NewOneTimeCode("123456")
			digest, err := v.Digest(scope, code)
			if err != nil {
				t.Fatal(err)
			}
			challenge, err := otp.NewChallenge(otp.ChallengeSpec{Continuation: ab.Continuation, Policy: policy, Digest: digest.Storage(), IssuedAt: now, ExpiresAt: now.Add(time.Minute), State: otp.ChallengeIssued, Version: 1})
			if err != nil {
				t.Fatal(err)
			}
			spec.Operation = issuanceOperation(spec.Operation.SubjectRequirement)
			spec.Binding.OperationID, spec.Binding.SchemaID, spec.Binding.SchemaVersion = spec.Operation.OperationID, spec.Operation.SchemaID, 1
			spec.Binding.RecordID, spec.Fields = "challenge", nil
			cookie, _ := attemptCommand.PreAuthCookie()
			command, err := store.codec.MapIssuancePreAuth(ctx, challenge, spec, cookie, authority)
			if err != nil {
				t.Fatal(err)
			}
			delivery, prepared := issuanceDeliveryFixture(t, store.codec, challenge, spec)
			phase, err := newIssuanceContributor(store, delivery, prepared)
			if err != nil {
				t.Fatal(err)
			}
			pool, err := database.New(ctx, database.Config{DSN: os.Getenv("IDENTITY_OTP_POSTGRES_TEST_DSN"), Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = db.Config().Database; return nil }})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				if err := pool.Close(cleanup); err != nil {
					t.Error(err)
				}
			})
			repo, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, &contributorAudit{fail: mode == "audit-rollback"}, &contributorLifecycle{apply: true}, phase, delivery})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: 3 * time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			plan, err := coordinator.PrepareCommandPlan(spec.Binding, command, issuanceExecutionPlan(t, spec, registry, prepared))
			if err != nil {
				t.Fatal("native preparation", err)
			}
			changes := map[string]string{"blocked": `UPDATE identity.users SET status='banned'`, "user-epoch": `UPDATE identity.users SET authority_version=12`, "identifier-epoch": `UPDATE identity.users SET identifier_version=14`, "credential-epoch": `UPDATE identity.users SET credential_version=18`, "directory-epoch": `UPDATE identity.tenant_authorities SET version=4`, "missing-flow": `DELETE FROM session_store.preauth_transactions`, "delivery-rollback": `ALTER TABLE identity.delivery_intents ADD CONSTRAINT native_issue_reject CHECK(false)`}
			changes["anonymous-delivery-rollback"] = changes["delivery-rollback"]
			if sql := changes[mode]; sql != "" {
				if _, err := db.Exec(ctx, sql); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "authorization-epoch" {
				tx := admissionBegin(t, ctx, db)
				if _, err := authoritypg.AdvanceAuthority(ctx, tx.Tx, authoritypg.AuthorityScope{TenantID: "tenant", PolicyNamespace: "users", SubjectID: "user"}, 1, time.Second); err != nil {
					t.Fatal(err)
				}
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, spec.Binding, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			result, err := coordinator.ApplyFeature(ctx, work, command)
			if err == nil {
				result, err = coordinator.Commit(work, result)
			} else {
				_, _ = coordinator.Abort(work, err)
			}
			if committed && (err != nil || result.Outcome != identity.CommitOutcomeCommitted) || !committed && err == nil {
				var invalid identity.InvalidInputError
				if errors.As(err, &invalid) {
					t.Log("invalid input field", invalid.Field)
				}
				t.Fatal("issuance classification", mode, result.Outcome, err)
			}
			var challenges, sends, effects, audits, events int
			if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM otp_store.challenges),(SELECT coalesce(sum(cardinality(sent_at)),0) FROM otp_store.send_families),(SELECT count(*) FROM identity.delivery_intents),(SELECT count(*) FROM public.native_otp_audits),(SELECT count(*) FROM public.native_otp_lifecycle)`).Scan(&challenges, &sends, &effects, &audits, &events); err != nil {
				t.Fatal(err)
			}
			want := 0
			if committed {
				want = 1
			}
			auditWant := 1 // Abort retains one denied audit, not protected effects.
			if mode == "audit-rollback" {
				auditWant = 0
			}
			if challenges != want || sends != want || effects != want || audits != auditWant || events != want {
				t.Fatal("challenge, send, encrypted effect, audit and lifecycle split", challenges, sends, effects, audits, events)
			}
			if committed {
				_, replay, err := coordinator.ReserveCommand(ctx, spec.Binding, command, plan)
				if err != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.AuditEventID != result.AuditEventID {
					t.Fatal("native issuance replay", err)
				}
				tx := admissionBegin(t, ctx, db)
				loaded, err := store.codec.loadChallenge(ctx, sqlChallengeQuery(tx.Tx), store.schema, attempt, 3)
				if err != nil {
					t.Fatal("native issued digest cannot enter existing verification", err)
				}
				if _, err := loaded.challenge.Bindings(); err != nil {
					t.Fatal(err)
				}
				if err := tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				var state string
				if err := db.QueryRow(ctx, `SELECT state FROM session_store.preauth_transactions`).Scan(&state); err != nil || state != "issued" {
					t.Fatal("sending consumed original flow", err)
				}
			}
		})
	}
}

func issuanceExecutionPlan(t *testing.T, spec identity.FeatureCommandSpec, registry *kernel.ContributorRegistry, prepared deliverypg.PreparedDelivery) kernel.CommandPlan {
	t.Helper()
	b := spec.Binding
	kind := audit.ActorService
	if b.ActorKind == authorization.SubjectUser {
		kind = audit.ActorHuman
	}
	builder, _ := audit.NewBuilder(audit.BuilderConfig{})
	record, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: "otp.send", Outcome: audit.OutcomeSucceeded, ReasonCode: "completed", Actor: audit.ActorInput{Kind: kind, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "otp_challenge", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{NoChange: true}, Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(b.CommandID), "aggregate.type": "otp_challenge", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, spec.Operation, "otp_challenge", record)
	if err != nil {
		t.Fatal(err)
	}
	dp, _ := prepared.Plan()
	return kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "otp_challenge", Feature: &kernel.FeatureRegistration{Contributor: (*issuanceContributor)(nil).Descriptor(), Operation: spec.Operation}, Delivery: &dp, Lifecycle: &kernel.LifecyclePlan{EventType: "otp.sent.v1", AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: "otp.send", SchemaVersion: 1, BindingDigest: digest, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected"}}}
}
