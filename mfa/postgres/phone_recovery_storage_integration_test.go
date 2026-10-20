//go:build integration

package mfapostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// This exercises the actual owned SQL/crypto/replay implementation against an
// encrypted confirmed-factor fixture. Explicit transactions are a storage oracle,
// NOT fabricated Work, reset authorization, native enrollment or a complete phone
// recovery consumer. The parent separately owns genuine live-Work composition.
func TestPhoneRecoveryTOTPStoragePostgres(t *testing.T) {
	dsn := os.Getenv("IDENTITY_MFA_TEST_DSN")
	config, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" {
		t.Fatal("explicit disposable loopback identity_test cluster required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("owned cluster unavailable")
	}
	defer admin.Close(context.Background())
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	name := "phone_recovery_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("owned database cleanup failed")
		}
	}()
	config.Database = name
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(kernel.MigrationSource{}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("kernel install failed", err)
	}
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 4, Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = name; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := pool.Close(cleanup); err != nil {
			t.Error("owned pool cleanup failed")
		}
	}()
	if _, err := pool.Raw().Exec(ctx, authoritySQL+totpFactorSQL+recoverySetSQL); err != nil {
		t.Fatal("MFA install failed", err)
	}
	v, fixture := phoneRecoveryFixture(t)
	f := fixture.custody()
	m := f.metadata
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','mfa-user','active',1);
INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES(decode(repeat('01',16),'hex'),'tenant-a','identity.password.signup',decode(repeat('01',32),'hex'),1,decode('01','hex')),(decode(repeat('02',16),'hex'),'tenant-a','identity.mfa.enable',decode(repeat('02',32),'hex'),1,decode('01','hex'));
INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES(decode(repeat('01',16),'hex'),'tenant-a','identity.password.signup'),(decode(repeat('02',16),'hex'),'tenant-a','identity.mfa.enable');
INSERT INTO identity_mfa.factor_authorities VALUES('tenant-a','mfa-user',1,1,decode(repeat('01',16),'hex'),'identity.password.signup')`); err != nil {
		t.Fatal("authority fixture failed", err)
	}
	_, err = pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.totp_factors(tenant_id,user_id,factor_id,state,enrollment_version,row_version,algorithm,digits,period_seconds,skew_steps,issuer,encrypted_secret,created_command_id,created_purpose,created_at,enrollment_expires_at,confirmed_at) VALUES($1,$2,$3,2,1,1,'SHA1',8,30,1,'Example',$4,decode(repeat('02',16),'hex'),'identity.mfa.enable',clock_timestamp()-interval '1 minute',clock_timestamp()+interval '4 minutes',clock_timestamp())`, string(m.TenantID), string(m.UserID), m.FactorID, f.wire)
	if err != nil {
		t.Fatal("encrypted factor fixture failed", err)
	}
	reader, err := NewTOTPFactorReader(pool, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, stopSelection := context.WithCancel(ctx)
	stopSelection()
	if _, err := reader.SelectForPhoneRecovery(cancelled, m.TenantID, m.UserID); !errors.Is(err, context.Canceled) {
		t.Fatal("factor selection lost caller cancellation", err)
	}
	selected, err := reader.SelectForPhoneRecovery(ctx, m.TenantID, m.UserID)
	selectedMetadata, selectedErr := selected.Metadata()
	if err != nil || selectedErr != nil || selectedMetadata.FactorID != m.FactorID {
		t.Fatal("native request cannot select its actual independent factor", err)
	}
	if _, err := reader.SelectForPhoneRecovery(ctx, "tenant-b", m.UserID); err == nil {
		t.Fatal("factor selection escaped tenant scope")
	}
	if _, err := reader.SelectForPhoneRecovery(ctx, m.TenantID, "other-user"); err == nil {
		t.Fatal("factor selection escaped subject scope")
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended' WHERE tenant_id=$1 AND user_id=$2`, string(m.TenantID), string(m.UserID)); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.SelectForPhoneRecovery(ctx, m.TenantID, m.UserID); err == nil {
		t.Fatal("selected factor bypassed current account status")
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active' WHERE tenant_id=$1 AND user_id=$2`, string(m.TenantID), string(m.UserID)); err != nil {
		t.Fatal(err)
	}
	snapshot, err := reader.ReadForPhoneRecovery(ctx, m.TenantID, m.UserID, m.FactorID)
	if err != nil {
		t.Fatal("confirmed original read failed", err)
	}
	for _, scope := range [][3]string{{"tenant-b", string(m.UserID), m.FactorID}, {string(m.TenantID), "other-user", m.FactorID}, {string(m.TenantID), string(m.UserID), "AAAAAAAAAAAAAAAAAAAAAg"}} {
		if _, err := reader.ReadForPhoneRecovery(ctx, identity.TenantID(scope[0]), identity.UserID(scope[1]), scope[2]); err == nil {
			t.Fatal("foreign factor read succeeded")
		}
	}
	until := time.Now().UTC().Truncate(time.Microsecond).Add(time.Minute)
	readReplay := func() (*string, string, uint64) {
		t.Helper()
		var last *string
		var row string
		var version string
		if err := pool.Raw().QueryRow(ctx, `SELECT t.last_step::text,t.row_version::text,u.version::text FROM identity_mfa.totp_factors t JOIN identity.users u USING(tenant_id,user_id) WHERE t.tenant_id=$1 AND t.factor_id=$2`, string(m.TenantID), m.FactorID).Scan(&last, &row, &version); err != nil {
			t.Fatal(err)
		}
		n, _ := strconv.ParseUint(version, 10, 64)
		return last, row, n
	}
	for _, mode := range []string{"correct-denial-phase", "wrong-code", "wrong-enrollment", "wrong-row", "changed-replay", "withdrawn-aggregate", "withdrawn-factor", "disabled-user", "changed-ciphertext", "changed-profile", "expired-before-lock", "expired-after-verification", "rollback-parent-effect"} {
		t.Run(mode, func(t *testing.T) {
			code := phoneRecoveryCurrentCode(t, ctx, pool)
			if mode == "wrong-code" {
				code = "123456"
			} // profile is eight digits, so mismatch is deterministic.
			command := phoneRecoveryTestCommand(t, m, mode == "correct-denial-phase" || mode == "wrong-code", code, nil)
			prepared, err := v.Prepare(ctx, snapshot, command, until)
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.Destroy()
			use, err := prepared.borrow()
			if err != nil {
				t.Fatal(err)
			}
			defer use.finish()
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			sql := phoneRecoveryTestSQL(tx)
			var mutate string
			switch mode {
			case "wrong-enrollment":
				mutate = `UPDATE identity_mfa.totp_factors SET enrollment_version=2`
			case "wrong-row":
				mutate = `UPDATE identity_mfa.totp_factors SET row_version=2`
			case "changed-replay":
				mutate = `UPDATE identity_mfa.totp_factors SET last_step=0`
			case "withdrawn-aggregate":
				mutate = `UPDATE identity_mfa.factor_authorities SET version=2,active_factors=0`
			case "withdrawn-factor":
				mutate = `UPDATE identity_mfa.totp_factors SET state=3,encrypted_secret=NULL,last_step=NULL`
			case "disabled-user":
				mutate = `UPDATE identity.users SET status='suspended'`
			case "changed-ciphertext":
				mutate = `UPDATE identity_mfa.totp_factors SET encrypted_secret=encrypted_secret||decode('01','hex')`
			case "changed-profile":
				mutate = `UPDATE identity_mfa.totp_factors SET issuer='Changed'`
			case "expired-before-lock":
				use.until = time.Now().Add(-time.Second)
			}
			if mutate != "" {
				if _, err := tx.Exec(ctx, mutate); err != nil {
					t.Fatal("fixture mutation failed", err)
				}
			}
			b := phoneRecoveryTestBinding(command, use.input)
			step, accepted, err := verifyPhoneRecoveryTOTPCode(ctx, use, sql, b, [32]byte{1}, 1)
			switch mode {
			case "wrong-code":
				if err != nil || accepted {
					t.Fatal("actual wrong-code classification failed", err)
				}
			case "correct-denial-phase":
				if err != nil || !accepted {
					t.Fatal("actual original code did not verify", err)
				}
			case "expired-after-verification":
				if err != nil || !accepted {
					t.Fatal("original verification failed", err)
				}
				if err := recordPhoneRecoveryTOTPStep(ctx, sql, snapshot, time.Now().UTC().Truncate(time.Microsecond).Add(-time.Second), step); err == nil {
					t.Fatal("late expiry advanced replay")
				}
			case "rollback-parent-effect":
				if err != nil || !accepted {
					t.Fatal("original verification failed", err)
				}
				if err := recordPhoneRecoveryTOTPStep(ctx, sql, snapshot, until, step); err != nil {
					t.Fatal("verified replay CAS failed", err)
				}
				if _, err := tx.Exec(ctx, `UPDATE identity.users SET version=2 WHERE tenant_id='tenant-a' AND user_id='mfa-user'`); err != nil {
					t.Fatal(err)
				}
			default:
				if err == nil {
					t.Fatal("stale/withdrawn authority was classified as a mere code denial")
				}
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			last, row, version := readReplay()
			if last != nil || row != "1" || version != 1 {
				t.Fatal("denial/rollback altered replay or parent effect")
			}
		})
	}
	t.Run("concurrent-one-winner-and-replay", func(t *testing.T) {
		code := phoneRecoveryCurrentCode(t, ctx, pool)
		var ready sync.WaitGroup
		ready.Add(2)
		start := make(chan struct{})
		results := make(chan error, 2)
		for range 2 {
			command := phoneRecoveryTestCommand(t, m, false, code, nil)
			prepared, err := v.Prepare(ctx, snapshot, command, until)
			if err != nil {
				t.Fatal(err)
			}
			use, err := prepared.borrow()
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				defer use.finish()
				ready.Done()
				<-start
				tx, err := pool.Raw().Begin(ctx)
				if err != nil {
					results <- err
					return
				}
				defer tx.Rollback(context.Background())
				sql := phoneRecoveryTestSQL(tx)
				step, accepted, err := verifyPhoneRecoveryTOTPCode(ctx, use, sql, phoneRecoveryTestBinding(command, false), [32]byte{1}, 1)
				if err == nil && !accepted {
					err = identity.ForbiddenError{}
				}
				if err == nil {
					err = recordPhoneRecoveryTOTPStep(ctx, sql, snapshot, until, step)
				}
				if err == nil {
					_, err = tx.Exec(ctx, `UPDATE identity.users SET version=2 WHERE tenant_id='tenant-a' AND user_id='mfa-user'`)
				}
				if err == nil {
					err = tx.Commit(ctx)
				}
				results <- err
			}()
		}
		ready.Wait()
		close(start)
		wins := 0
		for range 2 {
			if err := <-results; err == nil {
				wins++
			} else {
				var denied identity.ForbiddenError
				if !errors.As(err, &denied) {
					t.Fatal("losing replay contender failed for an unrelated reason", err)
				}
			}
		}
		if wins != 1 {
			t.Fatal("replay CAS did not have exactly one winner", wins)
		}
		last, row, version := readReplay()
		if last == nil || row != "2" || version != 2 {
			t.Fatal("winner did not commit replay and parent effect together")
		}
		current, err := reader.ReadForPhoneRecovery(ctx, m.TenantID, m.UserID, m.FactorID)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := v.Prepare(ctx, current, phoneRecoveryTestCommand(t, m, false, code, nil), until)
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.Destroy()
		use, err := prepared.borrow()
		if err != nil {
			t.Fatal(err)
		}
		defer use.finish()
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		_, accepted, err := verifyPhoneRecoveryTOTPCode(ctx, use, phoneRecoveryTestSQL(tx), phoneRecoveryTestBinding(use.command, false), [32]byte{1}, 1)
		if err != nil || accepted {
			t.Fatal("already accepted original TOTP step replayed", err)
		}
	})
}

func phoneRecoveryTestSQL(tx pgx.Tx) totpAttemptSQL {
	return totpAttemptSQL{query: func(ctx context.Context, q string, args []any, dest ...any) error {
		return tx.QueryRow(ctx, q, args...).Scan(dest...)
	}, exec: func(ctx context.Context, q string, args ...any) (int64, error) {
		tag, err := tx.Exec(ctx, q, args...)
		return tag.RowsAffected(), err
	}}
}

func phoneRecoveryTestBinding(command identity.Command, input bool) identity.CommandBinding {
	f, _ := command.PhonePasswordResetFeature()
	if input {
		f, _ = command.PhonePasswordResetInputFeature()
	}
	return f.Binding
}

// RFC 6238 public SHA1 key, independent HMAC/truncation oracle at actual DB time.
func phoneRecoveryCurrentCode(t testing.TB, ctx context.Context, pool *database.Pool) string {
	t.Helper()
	var now time.Time
	if err := pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	var moving [8]byte
	binary.BigEndian.PutUint64(moving[:], uint64(now.Unix()/30))
	mac := hmac.New(sha1.New, []byte("12345678901234567890"))
	_, _ = mac.Write(moving[:])
	sum := mac.Sum(nil)
	defer clear(sum)
	offset := sum[len(sum)-1] & 15
	return fmt.Sprintf("%08d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%100000000)
}
