//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func otpDatabase(t *testing.T) (context.Context, *pgx.Conn, *pgx.Conn) {
	t.Helper()
	dsn := os.Getenv("IDENTITY_OTP_POSTGRES_TEST_DSN")
	c, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || c.Host != "127.0.0.1" || c.Database != "identity_test" {
		t.Fatal("explicit disposable loopback identity_test required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	admin, err := pgx.ConnectConfig(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := admin.Close(cleanup); err != nil {
			t.Error("admin cleanup", err)
		}
	})
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "otp_native_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("owned database cleanup", err)
		}
	})
	c.Database = name
	connect := func() *pgx.Conn {
		db, err := pgx.ConnectConfig(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if err := db.Close(cleanup); err != nil {
				t.Error("connection cleanup", err)
			}
		})
		return db
	}
	db, peer := connect(), connect()
	kernel, err := (identitypostgres.MigrationSource{}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range kernel {
		if _, err := db.Exec(ctx, m.UpSQL()); err != nil {
			t.Fatal("kernel install", err)
		}
	}
	return ctx, db, peer
}

func TestPreAccountAndRecoveryStorage(t *testing.T) {
	ctx, db, _ := otpDatabase(t)
	h, err := (MigrationSource{Schema: "otp_store", Version: 100}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, h[0].UpSQL()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO otp_store.digest_keys VALUES(1,'hmac-sha256-v1')`); err != nil {
		t.Fatal(err)
	}
	issue := otpCommand(t, ctx, db, "tenant", 30)
	fp := bytes.Repeat([]byte{30}, 32)
	anonymous := strings.Replace(insertChallenge, "'user','email-verification'", "'','email-verification'", 1)
	if _, err := db.Exec(ctx, anonymous, "tenant", "pre-account", issue, fp); err != nil {
		t.Fatal("valid pre-account subject rejected", err)
	}
	var subject string
	if err := db.QueryRow(ctx, `SELECT subject_id FROM otp_store.challenges WHERE challenge_id='pre-account'`).Scan(&subject); err != nil || subject != "" {
		t.Fatal("invented pre-account subject", err)
	}
	consumer := otpCommand(t, ctx, db, "tenant", 31)
	if _, err := db.Exec(ctx, `UPDATE otp_store.challenges SET state='reserved',used_attempts=1,version=2,consumer_command_id=$1,consumer_purpose='identity.otp.send',consumer_fingerprint=$2,consumer_generation=1,consumer_attempt_id='AgICAgICAgICAgICAgICAg',consumer_attempt_fingerprint=$2,consumer_issuer_version=1,reserved_at=issued_at WHERE challenge_id='pre-account'`, consumer, fp); err != nil {
		t.Fatal(err)
	}
	constraintRejected(t, ctx, db, `UPDATE otp_store.challenges SET state='released',consumer_generation=3,terminal_at=expires_at,version=3 WHERE challenge_id='pre-account'`)
	// Coordinator-proven recovery owns the exact successor; it must not need
	// a second interim lifecycle write just to express its terminal projection.
	if _, err := db.Exec(ctx, `UPDATE otp_store.challenges SET state='released',consumer_generation=2,terminal_at=expires_at,version=3 WHERE challenge_id='pre-account'`); err != nil {
		t.Fatal("recovery successor terminal projection rejected", err)
	}
	var gen string
	if err := db.QueryRow(ctx, `SELECT consumer_generation::text FROM otp_store.challenges WHERE challenge_id='pre-account'`).Scan(&gen); err != nil || gen != "2" {
		t.Fatal("successor custody not retained", err)
	}
}

func otpCommand(t *testing.T, ctx context.Context, db *pgx.Conn, tenant string, n byte) []byte {
	t.Helper()
	id, fp := bytes.Repeat([]byte{n}, 16), bytes.Repeat([]byte{n}, 32)
	if _, err := db.Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,'identity.otp.send',$3,1,$4)`, id, tenant, fp, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,'identity.otp.send')`, id, tenant); err != nil {
		t.Fatal(err)
	}
	return id
}

const insertChallenge = `INSERT INTO otp_store.challenges(
 tenant_id,challenge_id,subject_id,purpose,issue_command_id,issue_command_purpose,issue_fingerprint,
 digest_key_version,code_digest,scope_digest,policy_version,scope_generation,
 alphabet,code_length,ttl_us,resend_interval_us,maximum_sends,attempt_limit,replacement,
 checks_enabled,check_limit,lockout_us,issued_at,expires_at,state,version)
 VALUES($1,$2,'user','email-verification',$3,'identity.otp.send',$4,1,$4,$4,1,1,
 '0123456789',6,60000000,30000000,3,3,'replace',true,2,60000000,
 '2026-10-06T12:00:00Z','2026-10-06T12:01:00Z','issued',1)`

func constraintRejected(t *testing.T, ctx context.Context, db *pgx.Conn, sql string, args ...any) {
	t.Helper()
	_, err := db.Exec(ctx, sql, args...)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || (pg.Code != "23514" && pg.Code != "23503" && pg.Code != "23505") {
		t.Fatalf("expected storage constraint rejection, got %T", err)
	}
}

func TestNativeChallengeStorage(t *testing.T) {
	ctx, db, peer := otpDatabase(t)
	issue := otpCommand(t, ctx, db, "tenant", 1)
	var before, after string
	if err := db.QueryRow(ctx, `SELECT row_to_json(c)::text FROM identity.commands c WHERE command_id=$1`, issue).Scan(&before); err != nil {
		t.Fatal(err)
	}
	// A failed install after its first statements cannot retain a partial schema.
	// Only this task-owned disposable database is changed by the rehearsal.
	if _, err := db.Exec(ctx, `ALTER SCHEMA identity RENAME TO identity_saved`); err != nil {
		t.Fatal(err)
	}
	broken, err := (MigrationSource{Schema: "otp_broken", Version: 100}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, broken[0].UpSQL()); err == nil {
		t.Fatal("missing kernel install succeeded")
	}
	var partial *string
	if err := db.QueryRow(ctx, `SELECT to_regnamespace('otp_broken')::text`).Scan(&partial); err != nil || partial != nil {
		t.Fatal("failed install retained partial namespace", err)
	}
	if _, err := db.Exec(ctx, `ALTER SCHEMA identity_saved RENAME TO identity`); err != nil {
		t.Fatal(err)
	}
	h, err := (MigrationSource{Schema: "otp_store", Version: 100}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, h[0].UpSQL()); err != nil {
		t.Fatal("native install", err)
	}
	if err := db.QueryRow(ctx, `SELECT row_to_json(c)::text FROM identity.commands c WHERE command_id=$1`, issue).Scan(&after); err != nil || before != after {
		t.Fatal("install changed populated command", err)
	}
	// Neither repeating the install nor an occupied namespace is adopted.
	if _, err := db.Exec(ctx, h[0].UpSQL()); err == nil {
		t.Fatal("reinstalled unmanaged history")
	}
	if _, err := db.Exec(ctx, `INSERT INTO otp_store.digest_keys VALUES(1,'hmac-sha256-v1')`); err != nil {
		t.Fatal(err)
	}
	fp := bytes.Repeat([]byte{0x31}, 32)
	if _, err := db.Exec(ctx, insertChallenge, "tenant", "challenge", issue, fp); err != nil {
		t.Fatal("issued challenge", err)
	}
	if _, err := db.Exec(ctx, insertChallenge, "other", "challenge", issue, fp); err == nil {
		t.Fatal("foreign tenant issuance adopted")
	}
	for _, sql := range []string{
		`UPDATE otp_store.challenges SET code_digest=decode(repeat('00',32),'hex'),version=2`,
		`UPDATE otp_store.challenges SET digest_key_version=2,version=2`,
		`UPDATE otp_store.challenges SET expires_at=expires_at+interval '1 second',version=2`,
		`UPDATE otp_store.challenges SET attempt_limit=4,version=2`,
		`UPDATE otp_store.challenges SET version=1.5`,
		`UPDATE otp_store.challenges SET version=18446744073709551616`,
		`UPDATE otp_store.challenges SET state='reserved',version=2`,
		`UPDATE otp_store.challenges SET state='exhausted',version=2`,
		`UPDATE otp_store.challenges SET used_attempts=1,failed_attempts=2,version=2`,
		`UPDATE otp_store.challenges SET used_attempts=1,checks=3,version=2`,
		`UPDATE otp_store.challenges SET used_attempts=2,failed_attempts=2,version=2`,
		`DELETE FROM otp_store.digest_keys WHERE key_version=1`,
		`DELETE FROM otp_store.challenges`,
		`DELETE FROM identity.commands WHERE command_id=$1`,
	} {
		args := []any{}
		if sql == `DELETE FROM identity.commands WHERE command_id=$1` {
			args = append(args, issue)
		}
		constraintRejected(t, ctx, db, sql, args...)
	}
	// Two writers using the same expected version cannot both charge one row.
	var wg sync.WaitGroup
	wins := make(chan int64, 2)
	failures := make(chan error, 2)
	for _, conn := range []*pgx.Conn{db, peer} {
		wg.Go(func() {
			tag, err := conn.Exec(ctx, `UPDATE otp_store.challenges SET used_attempts=1,failed_attempts=1,version=2 WHERE tenant_id='tenant' AND challenge_id='challenge' AND state='issued' AND version=1`)
			if err != nil {
				failures <- err
				return
			}
			wins <- tag.RowsAffected()
		})
	}
	wg.Wait()
	close(wins)
	close(failures)
	for err := range failures {
		t.Fatal("concurrent CAS", err)
	}
	var total int64
	for n := range wins {
		total += n
	}
	if total != 1 {
		t.Fatal("two counted winners", total)
	}
	if _, err := db.Exec(ctx, `UPDATE otp_store.challenges SET used_attempts=0,failed_attempts=0,version=3`); err == nil {
		t.Fatal("attempt allowance reset")
	}
	consumer := otpCommand(t, ctx, db, "tenant", 2)
	const reserve = `UPDATE otp_store.challenges SET state='reserved',used_attempts=2,version=3,
 consumer_command_id=$1,consumer_purpose='identity.otp.send',consumer_fingerprint=$2,
 consumer_generation=1,consumer_attempt_id='AQEBAQEBAQEBAQEBAQEBAQ',
 consumer_attempt_fingerprint=$2,consumer_issuer_version=1,
 reserved_at=issued_at WHERE tenant_id='tenant' AND challenge_id='challenge'`
	if _, err := db.Exec(ctx, reserve, consumer, fp); err != nil {
		t.Fatal("reservation storage", err)
	}
	if _, err := db.Exec(ctx, `UPDATE otp_store.challenges SET state='expired',version=4`); err == nil {
		t.Fatal("expiry released unresolved reservation")
	}
	if _, err := db.Exec(ctx, `UPDATE otp_store.challenges SET consumer_generation=0,version=4`); err == nil {
		t.Fatal("generation rewind")
	}
	if _, err := db.Exec(ctx, `UPDATE otp_store.challenges SET consumer_generation=18446744073709551615,version=4`); err != nil {
		t.Fatal("full-width generation rebind", err)
	}
	if _, err := db.Exec(ctx, `UPDATE otp_store.challenges SET state='finalized',terminal_at=expires_at,version=5`); err == nil {
		t.Fatal("finalized at exclusive expiry")
	}
	if _, err := db.Exec(ctx, `UPDATE otp_store.challenges SET state='released',terminal_at=expires_at+interval '1 day',version=5`); err != nil {
		t.Fatal("late proven release storage", err)
	}
	if _, err := db.Exec(ctx, `UPDATE otp_store.challenges SET state='issued',version=6`); err == nil {
		t.Fatal("terminal resurrection")
	}
	var state, version, generation string
	var used, failed int
	if err := db.QueryRow(ctx, `SELECT state,version::text,consumer_generation::text,used_attempts,failed_attempts FROM otp_store.challenges`).Scan(&state, &version, &generation, &used, &failed); err != nil || state != "released" || version != "5" || generation != "18446744073709551615" || used != 2 || failed != 1 {
		t.Fatal("original custody changed", err)
	}
	if _, err := db.Exec(ctx, `DELETE FROM identity.commands WHERE command_id=$1`, consumer); err == nil {
		t.Fatal("consumer journal erased")
	}
}

func TestNativeChallengeTerminalTransitions(t *testing.T) {
	ctx, db, _ := otpDatabase(t)
	h, err := (MigrationSource{Schema: "otp_store", Version: 100}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, h[0].UpSQL()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO otp_store.digest_keys VALUES(1,'hmac-sha256-v1')`); err != nil {
		t.Fatal(err)
	}
	for i, kind := range []string{"expired", "revoked", "exhausted", "finalized"} {
		issue := otpCommand(t, ctx, db, "tenant", byte(10+i))
		fp := bytes.Repeat([]byte{byte(10 + i)}, 32)
		if _, err := db.Exec(ctx, insertChallenge, "tenant", kind, issue, fp); err != nil {
			t.Fatal(err)
		}
		// Initial inserts cannot invent counters or already-terminal custody.
		invalid := strings.Replace(insertChallenge, "'issued',1)", "'expired',1)", 1)
		constraintRejected(t, ctx, db, invalid, "tenant", "invalid", issue, fp)
		switch kind {
		case "expired":
			constraintRejected(t, ctx, db, `UPDATE otp_store.challenges SET state='expired',terminal_at=expires_at-interval '1 microsecond',version=2 WHERE challenge_id=$1`, kind)
			if _, err := db.Exec(ctx, `UPDATE otp_store.challenges SET state='expired',terminal_at=expires_at,version=2 WHERE challenge_id=$1`, kind); err != nil {
				t.Fatal(err)
			}
		case "revoked":
			if _, err := db.Exec(ctx, `UPDATE otp_store.challenges SET state='revoked',terminal_at=issued_at,version=2 WHERE challenge_id=$1`, kind); err != nil {
				t.Fatal(err)
			}
		case "exhausted":
			for n := 1; n <= 2; n++ {
				if _, err := db.Exec(ctx, `UPDATE otp_store.challenges SET used_attempts=$2,failed_attempts=$2,version=$2+1 WHERE challenge_id=$1`, kind, n); err != nil {
					t.Fatal(err)
				}
			}
			constraintRejected(t, ctx, db, `UPDATE otp_store.challenges SET state='exhausted',used_attempts=3,terminal_at=issued_at,version=4 WHERE challenge_id=$1`, kind)
			if _, err := db.Exec(ctx, `UPDATE otp_store.challenges SET state='exhausted',used_attempts=3,failed_attempts=3,terminal_at=issued_at,version=4 WHERE challenge_id=$1`, kind); err != nil {
				t.Fatal(err)
			}
		case "finalized":
			consumer := otpCommand(t, ctx, db, "tenant", 20)
			if _, err := db.Exec(ctx, `UPDATE otp_store.challenges SET state='reserved',used_attempts=1,version=2,consumer_command_id=$2,consumer_purpose='identity.otp.send',consumer_fingerprint=$3,consumer_generation=1,consumer_attempt_id='AgICAgICAgICAgICAgICAg',consumer_attempt_fingerprint=$3,consumer_issuer_version=4294967295,reserved_at=issued_at WHERE challenge_id=$1`, kind, consumer, fp); err != nil {
				t.Fatal(err)
			}
			constraintRejected(t, ctx, db, `UPDATE otp_store.challenges SET consumer_attempt_id='AQEBAQEBAQEBAQEBAQEBAQ',consumer_generation=2,version=3 WHERE challenge_id=$1`, kind)
			if _, err := db.Exec(ctx, `UPDATE otp_store.challenges SET state='finalized',terminal_at=reserved_at,version=3 WHERE challenge_id=$1`, kind); err != nil {
				t.Fatal(err)
			}
		}
		constraintRejected(t, ctx, db, `UPDATE otp_store.challenges SET version=version+1,state='issued',terminal_at=NULL WHERE challenge_id=$1`, kind)
		constraintRejected(t, ctx, db, `DELETE FROM otp_store.challenges WHERE challenge_id=$1`, kind)
	}
	// Failed writes within a caller-owned transaction roll back both counters
	// and any companion effect; installing the schema creates no private UoW.
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE otp_store.rollback_marker(id integer)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE otp_store.challenges SET state='issued',version=version+1 WHERE challenge_id='finalized'`); err == nil {
		t.Fatal("terminal edit accepted in transaction")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var marker *string
	if err := db.QueryRow(ctx, `SELECT to_regclass('otp_store.rollback_marker')::text`).Scan(&marker); err != nil || marker != nil {
		t.Fatal("partial companion effect survived", err)
	}
}
