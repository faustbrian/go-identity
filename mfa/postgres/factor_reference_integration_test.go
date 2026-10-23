//go:build integration

package mfapostgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

// This tests actual migration/storage integrity and old-writer compatibility.
// Journal and encrypted-factor values are structural fixtures, not a public
// enrollment, authentication or recovery-code service acceptance journey.
func TestMFAFactorReferencesPostgres(t *testing.T) {
	dsn := os.Getenv("IDENTITY_MFA_TEST_DSN")
	config, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" {
		t.Fatal("explicit disposable loopback identity_test cluster required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("owned fixture cluster unavailable")
	}
	defer admin.Close(context.Background())
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	name := "mfa_reference_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
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
	root, err := migrations.NewRunner(kernel.MigrationSource{}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.Up(ctx); err != nil {
		t.Fatal("kernel install", err)
	}
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	base := RecoveryMigrationSource{Base: TOTPFactorMigrationSource{Base: ContinuationMigrationSource{Base: MigrationSource{Version: 1}, Version: 2}, Version: 3}, Version: 4}
	prior, err := base.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range prior {
		if _, err := conn.Exec(ctx, m.UpSQL()); err != nil {
			t.Fatal("prior MFA install", err)
		}
	}
	seed := func() (string, []byte) {
		t.Helper()
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		wire := mustContinuationCommandBytes(string(id))
		if _, err := conn.Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'tenant-a','identity.mfa.enable',$2,1,decode('01','hex'));`, wire, make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'tenant-a','identity.mfa.enable')`, wire); err != nil {
			t.Fatal(err)
		}
		return string(id), wire
	}
	if _, err := conn.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','factor-owner','active',1),('tenant-a','other-owner','active',1);
INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES(decode(repeat('01',16),'hex'),'tenant-a','identity.password.signup',decode(repeat('01',32),'hex'),1,decode('01','hex')),(decode(repeat('02',16),'hex'),'tenant-a','identity.password.signup',decode(repeat('02',32),'hex'),1,decode('01','hex'));
INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES(decode(repeat('01',16),'hex'),'tenant-a','identity.password.signup'),(decode(repeat('02',16),'hex'),'tenant-a','identity.password.signup');
INSERT INTO identity_mfa.factor_authorities VALUES('tenant-a','factor-owner',1,0,decode(repeat('01',16),'hex'),'identity.password.signup'),('tenant-a','other-owner',1,0,decode(repeat('02',16),'hex'),'identity.password.signup')`); err != nil {
		t.Fatal("factor authority fixtures", err)
	}
	insertTOTP := func(factor string, wire []byte) error {
		_, err := conn.Exec(ctx, `INSERT INTO identity_mfa.totp_factors(tenant_id,user_id,factor_id,state,enrollment_version,row_version,algorithm,digits,period_seconds,skew_steps,issuer,encrypted_secret,created_command_id,created_purpose,created_at,enrollment_expires_at) VALUES('tenant-a','factor-owner',$1,1,1,1,'SHA1',8,30,0,'Fixture',decode('01','hex'),$2,'identity.mfa.enable',clock_timestamp(),clock_timestamp()+interval '5 minutes')`, factor, wire)
		return err
	}
	legacyFactor, legacyCommand := seed()
	if err := insertTOTP(legacyFactor, legacyCommand); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO identity_mfa.recovery_sets(tenant_id,user_id,set_id,factor_id,set_version,row_version,state,code_count,key_version,created_command_id,created_purpose,created_at) VALUES('tenant-a','factor-owner',$1,$1,1,1,1,1,1,$2,'identity.mfa.enable',clock_timestamp())`, legacyFactor, legacyCommand); err != nil {
		t.Fatal("populated recovery seed", err)
	}
	source := FactorReferenceMigrationSource{Base: base, Version: 13}
	history, err := source.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i, old := range prior {
		if old.UpSQL() != history[i].UpSQL() || old.Version() != history[i].Version() {
			t.Fatal("published migration bytes changed")
		}
	}
	migration := history[len(history)-1]
	apply, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer apply.Rollback(ctx)
	if _, err := apply.Exec(ctx, migration.UpSQL()); err != nil {
		t.Fatal("shared factor-reference migration", err)
	}
	if err := apply.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var method string
	if err := conn.QueryRow(ctx, `SELECT method FROM identity_mfa.factor_references WHERE tenant_id='tenant-a' AND user_id='factor-owner' AND factor_id=$1`, legacyFactor).Scan(&method); err != nil || method != "totp" {
		t.Fatal("populated TOTP reference lost", err)
	}
	var count int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM identity_mfa.recovery_sets WHERE tenant_id='tenant-a' AND factor_id=$1 AND state=1`, legacyFactor).Scan(&count); err != nil || count != 1 {
		t.Fatal("populated recovery state changed", err)
	}
	// The old binary still executes exactly its original INSERT column list.
	newFactor, newCommand := seed()
	if err := insertTOTP(newFactor, newCommand); err != nil {
		t.Fatal("legacy TOTP writer rejected", err)
	}
	if err := conn.QueryRow(ctx, `SELECT method FROM identity_mfa.factor_references WHERE tenant_id='tenant-a' AND factor_id=$1`, newFactor).Scan(&method); err != nil || method != "totp" {
		t.Fatal("legacy writer omitted shared reference", err)
	}
	// A registry row is identity metadata, not confirmed factor authority. Other
	// method details and eligibility remain mandatory native-owner checks.
	otpFactor, otpCommand := seed()
	if _, err := conn.Exec(ctx, `INSERT INTO identity_mfa.factor_references(tenant_id,user_id,factor_id,method) VALUES('tenant-a','factor-owner',$1,'otp')`, otpFactor); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO identity_mfa.recovery_sets(tenant_id,user_id,set_id,factor_id,factor_method,set_version,row_version,state,code_count,key_version,created_command_id,created_purpose,created_at) VALUES('tenant-a','factor-owner',$1,$1,'otp',1,1,1,1,1,$2,'identity.mfa.enable',clock_timestamp())`, otpFactor, otpCommand); err != nil {
		t.Fatal("OTP reference rejected by shared recovery owner", err)
	}
	if err := insertTOTP(otpFactor, otpCommand); err == nil {
		t.Fatal("OTP identity retargeted into TOTP")
	}
	for _, statement := range []string{
		`DELETE FROM identity_mfa.totp_factors WHERE tenant_id='tenant-a' AND factor_id=$1`,
		`UPDATE identity_mfa.factor_references SET method='otp' WHERE tenant_id='tenant-a' AND factor_id=$1`,
		`UPDATE identity_mfa.factor_references SET user_id='other-owner' WHERE tenant_id='tenant-a' AND factor_id=$1`,
		`DELETE FROM identity_mfa.factor_references WHERE tenant_id='tenant-a' AND factor_id=$1`,
	} {
		_, err := conn.Exec(ctx, statement, legacyFactor)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || (pg.Code != "23514" && pg.Code != "23503") {
			t.Fatal("factor identity mutation or orphaning admitted")
		}
	}
	// Actual OTP-factor storage participates in that same identity namespace,
	// without a second recovery-code store or plaintext destination/code columns.
	// Before the OTP owner is installed, its identity-only reference is not a
	// usable enrollment. Remove that structural seam before validating actual
	// per-method referential integrity; no real service has been exercised here.
	if _, err := conn.Exec(ctx, `DELETE FROM identity_mfa.recovery_sets WHERE tenant_id='tenant-a' AND factor_id=$1`, otpFactor); err != nil {
		t.Fatal(err)
	}
	opts, err := (OTPFactorMigrationSource{Base: source, Version: 14}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, opts[len(opts)-1].UpSQL()); err != nil {
		t.Fatal("OTP factor install", err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES('tenant-a','factor-owner','email-factor','email','factor@example.invalid',true,true,1,2,1,clock_timestamp()),('tenant-a','other-owner','email-other','email','other@example.invalid',true,true,1,2,1,clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
	confirmedFactor, confirmedCommand := seed()
	if _, err := conn.Exec(ctx, `INSERT INTO identity_mfa.otp_factors(tenant_id,user_id,factor_id,state,enrollment_version,row_version,channel,identifier_id,identifier_version,verification_version,created_command_id,created_purpose,created_at,enrollment_expires_at) VALUES('tenant-a','factor-owner',$1,1,1,1,'email','email-factor',1,1,$2,'identity.mfa.enable',clock_timestamp(),clock_timestamp()+interval '5 minutes')`, confirmedFactor, confirmedCommand); err != nil {
		t.Fatal("pending OTP factor", err)
	}
	if err := conn.QueryRow(ctx, `SELECT method FROM identity_mfa.factor_references WHERE tenant_id='tenant-a' AND factor_id=$1`, confirmedFactor).Scan(&method); err != nil || method != "otp" {
		t.Fatal("OTP identity registered as another method", err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO identity_mfa.recovery_sets(tenant_id,user_id,set_id,factor_id,factor_method,set_version,row_version,state,code_count,key_version,created_command_id,created_purpose,created_at) VALUES('tenant-a','factor-owner',$1,$1,'otp',1,1,1,1,1,$2,'identity.mfa.enable',clock_timestamp())`, confirmedFactor, confirmedCommand); err != nil {
		t.Fatal("OTP recovery reference did not bind actual factor", err)
	}
	if _, err := conn.Exec(ctx, `DELETE FROM identity_mfa.otp_factors WHERE tenant_id='tenant-a' AND factor_id=$1`, confirmedFactor); err == nil {
		t.Fatal("OTP deletion orphaned recovery owner")
	}
	if _, err := conn.Exec(ctx, `UPDATE identity_mfa.otp_factors SET state=2 WHERE tenant_id='tenant-a' AND factor_id=$1`, confirmedFactor); err == nil {
		t.Fatal("unconfirmed OTP became active")
	}
	if _, err := conn.Exec(ctx, `UPDATE identity_mfa.otp_factors SET identifier_id='email-other' WHERE tenant_id='tenant-a' AND factor_id=$1`, confirmedFactor); err == nil {
		t.Fatal("OTP factor borrowed another user's recipient")
	}
	if _, err := conn.Exec(ctx, `UPDATE identity_mfa.otp_factors SET state=3 WHERE tenant_id='tenant-a' AND factor_id=$1`, confirmedFactor); err == nil {
		t.Fatal("revoked OTP retained recipient custody")
	}
	if _, err := conn.Exec(ctx, `UPDATE identity_mfa.otp_factors SET state=3,identifier_id=NULL,identifier_version=NULL,verification_version=NULL WHERE tenant_id='tenant-a' AND factor_id=$1`, confirmedFactor); err != nil {
		t.Fatal("OTP revocation erasure", err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO identity_mfa.otp_factors(tenant_id,user_id,factor_id,state,enrollment_version,row_version,channel,identifier_id,identifier_version,verification_version,created_command_id,created_purpose,created_at,enrollment_expires_at) VALUES('tenant-a','factor-owner',$1,1,1,1,'email','email-factor',1,1,$2,'identity.mfa.enable',clock_timestamp(),clock_timestamp()+interval '5 minutes')`, legacyFactor, legacyCommand); err == nil {
		t.Fatal("TOTP identity retargeted into OTP")
	}
	t.Run("OTP action history preserves populated factors", func(t *testing.T) {
		totpProofs := FactorVerificationMigrationSource{Base: OTPFactorMigrationSource{Base: source, Version: 14}, Version: 15}
		proofs := OTPFactorVerificationMigrationSource{Base: totpProofs, Version: 16}
		history, err := (OTPFactorManagementMigrationSource{Base: proofs, Version: 17}).Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range history[len(history)-3:] {
			if _, err := conn.Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("OTP action history install", err)
			}
		}
		var label string
		var state, version int
		if err := conn.QueryRow(ctx, `SELECT label,state,row_version FROM identity_mfa.otp_factors WHERE tenant_id='tenant-a' AND factor_id=$1`, confirmedFactor).Scan(&label, &state, &version); err != nil || label != "" || state != 3 || version != 1 {
			t.Fatal("additive management history changed retained factor state", err)
		}
		// The old INSERT shape still works; a label is not required for an
		// enrollment writer that does not select active factor management.
		oldWriterFactor, oldWriterCommand := seed()
		if _, err := conn.Exec(ctx, `INSERT INTO identity_mfa.otp_factors(tenant_id,user_id,factor_id,state,enrollment_version,row_version,channel,identifier_id,identifier_version,verification_version,created_command_id,created_purpose,created_at,enrollment_expires_at) VALUES('tenant-a','factor-owner',$1,1,1,1,'email','email-factor',1,1,$2,'identity.mfa.enable',clock_timestamp(),clock_timestamp()+interval '5 minutes')`, oldWriterFactor, oldWriterCommand); err != nil {
			t.Fatal("unselected legacy enrollment writer rejected", err)
		}
		proofID, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		proofCommand := mustContinuationCommandBytes(string(proofID))
		if _, err := conn.Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'tenant-a','identity.mfa.otp-verify',$2,1,decode('01','hex'))`, proofCommand, make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'tenant-a','identity.mfa.otp-verify')`, proofCommand); err != nil {
			t.Fatal(err)
		}
		insertProof := func(factor, user, purpose string) error {
			_, err := conn.Exec(ctx, `INSERT INTO identity_mfa.otp_factor_verifications(proof_id,tenant_id,user_id,factor_id,enrollment_version,factor_authority_version,command_id,purpose,record) VALUES($1,'tenant-a',$2,$3,1,1,$4,$5,decode('01','hex'))`, string(proofID), user, factor, proofCommand, purpose)
			return err
		}
		if err := insertProof(legacyFactor, "factor-owner", "identity.mfa.otp-verify"); err == nil {
			t.Fatal("OTP proof accepted a TOTP predecessor")
		}
		if err := insertProof(oldWriterFactor, "other-owner", "identity.mfa.otp-verify"); err == nil {
			t.Fatal("OTP proof crossed factor owner")
		}
		if err := insertProof(oldWriterFactor, "factor-owner", "identity.mfa.totp-verify"); err == nil {
			t.Fatal("OTP proof accepted a TOTP command")
		}
		if err := insertProof(oldWriterFactor, "factor-owner", "identity.mfa.otp-verify"); err != nil {
			t.Fatal("actual OTP predecessor rejected", err)
		}
		if _, err := conn.Exec(ctx, `UPDATE identity_mfa.otp_factor_verifications SET used_at=clock_timestamp() WHERE proof_id=$1`, string(proofID)); err == nil {
			t.Fatal("partial proof-use marker accepted")
		}
		if _, err := conn.Exec(ctx, `UPDATE identity_mfa.otp_factors SET label=E'line\nbreak' WHERE tenant_id='tenant-a' AND factor_id=$1`, oldWriterFactor); err == nil {
			t.Fatal("control characters persisted in public factor label")
		}
		testOTPFactorVerificationSourcePostgres(t, ctx, conn, dsn, name, string(proofID), oldWriterFactor)
		var populated string
		if err := conn.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(f) ORDER BY factor_id)::text FROM identity_mfa.otp_factors f`).Scan(&populated); err != nil {
			t.Fatal("populated OTP removal predecessor unavailable", err)
		}
		removed, err := (OTPFactorRemovalMigrationSource{Base: OTPFactorManagementMigrationSource{Base: proofs, Version: 17}, Version: 18}).Load(ctx)
		if err != nil || len(removed) != len(history)+1 {
			t.Fatal("OTP removal suffix did not append", err)
		}
		for i := range history {
			if removed[i] != history[i] {
				t.Fatal("OTP removal changed installed migration bytes")
			}
		}
		if _, err := conn.Exec(ctx, removed[len(removed)-1].UpSQL()); err != nil {
			t.Fatal("populated OTP removal suffix failed", err)
		}
		var after string
		if err := conn.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(f) ORDER BY factor_id)::text FROM identity_mfa.otp_factors f`).Scan(&after); err != nil || after != populated {
			t.Fatal("OTP removal migration changed populated factor/recipient metadata", err)
		}
		disabled, err := (OTPDisableMigrationSource{Base: OTPFactorRemovalMigrationSource{Base: OTPFactorManagementMigrationSource{Base: proofs, Version: 17}, Version: 18}, Version: 19}).Load(ctx)
		if err != nil || len(disabled) != len(removed)+1 {
			t.Fatal("OTP disable suffix did not append", err)
		}
		for i := range removed {
			if disabled[i] != removed[i] {
				t.Fatal("OTP disable changed installed migration bytes")
			}
		}
		if _, err := conn.Exec(ctx, disabled[len(disabled)-1].UpSQL()); err != nil {
			t.Fatal("populated OTP disable suffix failed", err)
		}
		if err := conn.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(f) ORDER BY factor_id)::text FROM identity_mfa.otp_factors f`).Scan(&after); err != nil || after != populated {
			t.Fatal("OTP disable changed installed factor metadata", err)
		}
	})
}
