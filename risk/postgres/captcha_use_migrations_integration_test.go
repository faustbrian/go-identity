//go:build integration

package postgres

import (
	"bytes"
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Real populated forward upgrade and storage invariants, not execution or
// permission. Native coordinator reservation/finalization follows this schema.
func testCaptchaUseMigrationSQL(t *testing.T, ctx context.Context, db *pgx.Conn, issuance, digest []byte) {
	t.Helper()
	const original = `SELECT row_to_json(e)::text FROM (SELECT tenant_id,command_id,command_purpose,user_id,anonymous_flow_id,binding_digest,intent_digest,proof_digest,evidence_digest,key_version,hostname,issued_at,expires_at,state,response_envelope FROM risk_store.captcha_issued_evidence WHERE command_id=$1) e`
	var before, after string
	if err := db.QueryRow(ctx, original, issuance).Scan(&before); err != nil {
		t.Fatal(err)
	}
	h, err := (CaptchaUseMigrationSource{Schema: "risk_store", Version: 42}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Existing reserved history without authenticated ownership cannot be
	// guessed or reset. The complete upgrade must roll back in this case.
	if _, err := db.Exec(ctx, `UPDATE risk_store.captcha_issued_evidence SET state='reserved' WHERE command_id=$1`, issuance); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, h[0].UpSQL()); err == nil {
		t.Fatal("upgrade invented consuming custody for unknown reservation")
	}
	var columns int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema='risk_store' AND table_name='captcha_issued_evidence' AND column_name='consumer_command_id'`).Scan(&columns); err != nil || columns != 0 {
		t.Fatal("rejected upgrade left partial custody", err)
	}
	if _, err := db.Exec(ctx, `UPDATE risk_store.captcha_issued_evidence SET state='issued' WHERE command_id=$1`, issuance); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, h[0].UpSQL()); err != nil {
		t.Fatal("populated consuming upgrade", err)
	}
	if err := db.QueryRow(ctx, original, issuance).Scan(&after); err != nil || before != after {
		t.Fatal("upgrade changed original evidence or encrypted response", err)
	}
	consumer := bytes.Repeat([]byte{8}, 16)
	const purpose = "identity.password.signin"
	if _, err := db.Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'tenant',$2,$3,1,$4)`, consumer, purpose, digest, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'tenant',$2)`, consumer, purpose); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		`UPDATE risk_store.captcha_issued_evidence SET state='reserved' WHERE command_id=$1`,
		`UPDATE risk_store.captcha_issued_evidence SET consumer_command_id=$2 WHERE command_id=$1`,
	} {
		args := []any{issuance}
		if bytes.Contains([]byte(sql), []byte("$2")) {
			args = append(args, consumer)
		}
		if _, err := db.Exec(ctx, sql, args...); err == nil {
			t.Fatal("partial consuming ownership accepted")
		}
	}
	const reserve = `UPDATE risk_store.captcha_issued_evidence SET state='reserved',consumer_command_id=$2,consumer_purpose=$3,consumer_fingerprint=$4,consumer_generation=$5,consumer_binding_digest=$4,consumer_signature=$4,reserved_at=issued_at WHERE command_id=$1`
	for _, bad := range []struct {
		id                  []byte
		purpose, generation string
	}{
		{issuance, "identity.risk.captcha-issue", "1"},
		{consumer, "wrong-purpose", "1"},
		{consumer, purpose, "0"}, {consumer, purpose, "1.5"}, {consumer, purpose, "18446744073709551616"},
	} {
		if _, err := db.Exec(ctx, reserve, issuance, bad.id, bad.purpose, digest, bad.generation); err == nil {
			t.Fatal("invalid consuming lineage accepted")
		}
	}
	if _, err := db.Exec(ctx, reserve, issuance, consumer, purpose, digest, "18446744073709551615"); err != nil {
		t.Fatal("full-width ownership rejected", err)
	}
	for _, sql := range []string{
		`UPDATE risk_store.captcha_issued_evidence SET terminal_at=reserved_at WHERE command_id=$1`,
		`UPDATE risk_store.captcha_issued_evidence SET reserved_at=expires_at WHERE command_id=$1`,
		`UPDATE risk_store.captcha_issued_evidence SET state='finalized' WHERE command_id=$1`,
		`UPDATE risk_store.captcha_issued_evidence SET state='finalized',terminal_at=expires_at WHERE command_id=$1`,
		`UPDATE risk_store.captcha_issued_evidence SET state='released',terminal_at=reserved_at-interval '1 microsecond' WHERE command_id=$1`,
	} {
		if _, err := db.Exec(ctx, sql, issuance); err == nil {
			t.Fatal("invalid consuming temporal state accepted")
		}
	}
	if _, err := db.Exec(ctx, `UPDATE risk_store.captcha_issued_evidence SET state='finalized',terminal_at=reserved_at,response_envelope=NULL WHERE command_id=$1`, issuance); err != nil {
		t.Fatal("terminal tombstone with erased payload rejected", err)
	}
	var generation, state string
	var fingerprint []byte
	if err := db.QueryRow(ctx, `SELECT consumer_generation::text,state,consumer_fingerprint FROM risk_store.captcha_issued_evidence WHERE command_id=$1`, issuance).Scan(&generation, &state, &fingerprint); err != nil || generation != "18446744073709551615" || state != "finalized" || !bytes.Equal(fingerprint, digest) {
		t.Fatal("terminal ownership was not conserved", err)
	}
	if _, err := db.Exec(ctx, `DELETE FROM identity.commands WHERE command_id=$1`, consumer); err == nil {
		t.Fatal("referenced consuming journal removed")
	}
}
