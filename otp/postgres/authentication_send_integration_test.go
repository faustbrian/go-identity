//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
)

// PostgreSQL owns actual generation/replay and atomic domain effects here.
// External risk boundaries remain explicit doubles, not durable-counter or
// provider interoperability evidence and not the unfinished public Send API.
func TestAuthenticationSendNativeAtomicity(t *testing.T) {
	for _, mode := range []string{"committed", "restrictive", "final-wait-expired"} {
		t.Run(mode, func(t *testing.T) {
			ctx, db, peer := otpDatabase(t)
			directory := kernel.DirectoryAuthorityMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 12}, Version: 13}, Version: 14, GlobalAuthorityID: "deployment", TenantIDs: []identity.TenantID{"AAAAAAAAAAAAAAAAAAAAAQ"}}
			preparation := kernel.AdmissionPreparationMigrationSource{Base: kernel.PreparationMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}
			for _, source := range []migrations.Source{preparation, directory, MigrationSource{Schema: "otp_store", Version: 100}, LockoutMigrationSource{Schema: "otp_store", Version: 101}, SendFamilyMigrationSource{Schema: "otp_store", Version: 102}, IssuanceMigrationSource{Schema: "otp_store", Version: 103}, sessionpg.MigrationSource{Schema: "session_store", Version: 200}} {
				history, err := source.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, m := range history {
					if m.Version() < 10 {
						continue
					}
					if _, err := db.Exec(ctx, m.UpSQL()); err != nil {
						t.Fatal("native schema", err)
					}
				}
			}
			// Delivery's source includes kernel history; select only its own append.
			history, err := (deliverypg.MigrationSource{Base: kernel.MigrationSource{}, Version: 250}).Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range history {
				if m.Version() >= 250 {
					if _, err := db.Exec(ctx, m.UpSQL()); err != nil {
						t.Fatal(err)
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
					t.Fatal(err)
				}
			}
			m, err := authoritypg.AuthoritySchemaMigration(300)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, m.Up); err != nil {
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
			auditOwner, lifecycleOwner := &contributorAudit{}, &contributorLifecycle{apply: true}
			owner, command, configuration, clock, state, calls := authenticationSendFixture(t, repo.Descriptor(), auditOwner.Descriptor(), lifecycleOwner.Descriptor())
			keyBinding := owner.store.lockout.binding()
			if _, err := db.Exec(ctx, `INSERT INTO otp_store.lockout_key_binding VALUES(true,$1)`, keyBinding[:]); err != nil {
				t.Fatal(err)
			}
			base, _, err := owner.original(ctx, command)
			if err != nil {
				t.Fatal(err)
			}
			r, _, err := owner.store.originalPreparedSend(ctx, base)
			if err != nil {
				t.Fatal(err)
			}
			cb, _ := r.continuation.Bindings()
			original, _ := cb.Authorization.AuthenticatedSession()
			s, _ := original.Bindings()
			if _, err := db.Exec(ctx, `UPDATE identity.global_authorities SET version=2; UPDATE identity.tenant_authorities SET version=3;
INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES('AAAAAAAAAAAAAAAAAAAAAQ','AAAAAAAAAAAAAAAAAAAAAg','active',7,4,5,6);
INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('AAAAAAAAAAAAAAAAAAAAAQ','AAAAAAAAAAAAAAAAAAAAAg','credential',1,'identity/password',14,true);
INSERT INTO authorization_subject_authorities VALUES('AAAAAAAAAAAAAAAAAAAAAQ','users','AAAAAAAAAAAAAAAAAAAAAg',9);
INSERT INTO otp_store.digest_keys VALUES(3,'hmac-sha256-v1'),(4,'hmac-sha256-v1');
CREATE TABLE public.native_otp_audits(event_id text PRIMARY KEY,command_id text UNIQUE NOT NULL,outcome text NOT NULL);
CREATE TABLE public.native_otp_lifecycle(command_id text PRIMARY KEY,event_id text UNIQUE NOT NULL)`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES('AAAAAAAAAAAAAAAAAAAAAQ','AAAAAAAAAAAAAAAAAAAAAg','email','email',$1,true,true,9,2,3,$2)`, cb.Scope.Destination.Value(), r.issuedAt); err != nil {
				t.Fatal(err)
			}
			remember, _ := s.Remember.Bindings()
			vector, _ := s.Authority.Bindings()
			payload, err := json.Marshal(map[string]any{"Schema": 1, "SessionID": s.SessionID, "FamilyID": s.FamilyID, "TenantID": s.TenantID, "UserID": s.UserID, "Audience": s.Audience, "Version": s.Version, "FamilyVersion": s.FamilyVersion, "Remember": remember, "Authority": vector, "Lookup": s.Lookup, "Authentication": s.Authentication, "IssuedAt": s.IssuedAt, "LastActivityAt": s.LastActivityAt})
			if err != nil {
				t.Fatal(err)
			}
			lifetime, _ := original.Lifetime(s.LastActivityAt)
			const instant = "2006-01-02T15:04:05.000000000Z"
			if _, err := db.Exec(ctx, `INSERT INTO session_store.families VALUES($1,$2,$3,$4,'active',$5)`, s.TenantID, s.FamilyID, s.UserID, s.FamilyVersion, s.IssuedAt.Format(instant)); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, `INSERT INTO session_store.sessions VALUES($1,$2,$3,$4,$5,$6,'active',$7,$8,$9,$10::jsonb)`, s.TenantID, s.SessionID, s.UserID, s.FamilyID, s.Version, s.FamilyVersion, s.Lookup.KeyVersion, s.Lookup.Sum[:], lifetime.ExpiresAt.Format(instant), payload); err != nil {
				t.Fatal(err)
			}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, auditOwner, lifecycleOwner, owner, owner.store.send.delivery})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: 4 * time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			declaration, err := owner.store.preparedSendPlan(base, nil)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "restrictive" {
				*state = risk.SignalDeny
			}
			var result identity.CommandResult
			if mode == "final-wait-expired" {
				tx, beginErr := peer.Begin(ctx)
				if beginErr != nil {
					t.Fatal(beginErr)
				}
				defer tx.Rollback(context.Background())
				if _, err := tx.Exec(ctx, `LOCK TABLE otp_store.send_families IN ACCESS EXCLUSIVE MODE`); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				finished := make(chan struct{})
				worker, cancel := context.WithCancel(ctx)
				go func() {
					defer close(finished)
					_, err := coordinator.ExecutePreparedFeature(worker, command, declaration)
					done <- err
				}()
				defer func() { cancel(); <-finished }()
				deadline := time.Now().Add(2 * time.Second)
				for {
					var waiting bool
					if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%send_families%')`).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("native final family wait was not reached")
					}
					time.Sleep(time.Millisecond)
				}
				clock.Advance(30 * time.Second)
				if err := tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				err = <-done
			} else {
				result, err = coordinator.ExecutePreparedFeature(ctx, command, declaration)
			}
			if mode == "committed" {
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Log("external admission calls", *calls)
					t.Fatal("native risk send did not commit", err)
				}
			} else if err == nil {
				t.Fatal("native denial committed")
			}
			var challenges, sends, deliveries, events int
			if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM otp_store.challenges),(SELECT coalesce(sum(cardinality(sent_at)),0) FROM otp_store.send_families),(SELECT count(*) FROM identity.delivery_intents),(SELECT count(*) FROM public.native_otp_lifecycle)`).Scan(&challenges, &sends, &deliveries, &events); err != nil {
				t.Fatal(err)
			}
			want := 0
			if mode == "committed" {
				want = 1
			}
			if challenges != want || sends != want || deliveries != want || events != want {
				t.Fatal("risk admission split atomic effects", challenges, sends, deliveries, events)
			}
			if *calls != 3 {
				t.Fatal("external admission repeated or omitted", *calls)
			}
			if mode == "committed" {
				before := *calls
				freshStore := *owner.store
				freshStore.codec, err = NewAttemptCodec(codecConfig())
				if err != nil {
					t.Fatal(err)
				}
				freshOwner, err := newAuthenticationSendContributor(&freshStore, configuration)
				if err != nil {
					t.Fatal(err)
				}
				spec, _ := command.Feature()
				input, err := freshOwner.restoreInitiationReference(ctx, command, spec.Fields[2].Value.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				remapped, err := freshOwner.mapInitiatedSend(ctx, input)
				if err != nil {
					t.Fatal(err)
				}
				replay, e := coordinator.ExecutePreparedFeature(ctx, remapped, declaration)
				if e != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.AuditEventID != result.AuditEventID || *calls != before {
					t.Fatal("terminal replay repeated risk or changed receipt", e)
				}
			}
		})
	}
}
