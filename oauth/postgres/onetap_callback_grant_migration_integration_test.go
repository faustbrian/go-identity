//go:build integration

package postgres

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestOneTapCallbackGrantForwardSchema(t *testing.T) {
	ctx, db := rpMigrationDatabase(t)
	const schema = "oauth_rp"
	prior, err := (MigrationSource{Schema: schema, Version: 100}).Load(ctx)
	if err != nil {
		t.Fatal("load original RP schema", err)
	}
	if _, err := db.Exec(ctx, prior[0].UpSQL()); err != nil {
		t.Fatal("install original RP schema", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','existing-owner','active',7)`); err != nil {
		t.Fatal("seed populated predecessor", err)
	}
	seed := func(tenant, purpose string, mark byte) []byte {
		t.Helper()
		id, fingerprint := bytes.Repeat([]byte{mark}, 16), bytes.Repeat([]byte{mark}, 32)
		if _, err := db.Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,$3,$4,1,$5)`, id, tenant, purpose, fingerprint, []byte{1}); err != nil {
			t.Fatal("seed original identity claim", err)
		}
		if _, err := db.Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,$3)`, id, tenant, purpose); err != nil {
			t.Fatal("seed original identity command", err)
		}
		return id
	}
	first := seed("tenant-a", "identity.oauth.onetap-start", 1)
	other := seed("tenant-a", "identity.oauth.onetap-start", 2)
	unrelated := seed("tenant-a", "identity.oauth.signin-start", 3)
	foreign := seed("tenant-b", "identity.oauth.onetap-start", 4)

	history, err := (OneTapCallbackGrantMigrationSource{Schema: schema, Version: 101}).Load(ctx)
	if err != nil || len(history) != 1 {
		t.Fatal("load additive One Tap callback-grant migration", err)
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal("begin forward One Tap apply", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, history[0].UpSQL()); err != nil {
		t.Fatal("apply additive One Tap migration", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("commit additive One Tap migration", err)
	}
	var preserved bool
	if err := db.QueryRow(ctx, `SELECT to_regclass('oauth_rp.transactions') IS NOT NULL AND EXISTS
		(SELECT 1 FROM identity.users WHERE tenant_id='tenant-a' AND user_id='existing-owner' AND version=7)`).Scan(&preserved); err != nil || !preserved {
		t.Fatal("One Tap installation changed the RP or identity predecessor", err)
	}

	const insert = `INSERT INTO oauth_rp.onetap_callback_grants
	 (tenant_id,flow_id,origin_command_id,origin_operation,issued_at,expires_at,proof_ciphertext)
	 VALUES($1,$2,$3,$4,$5,$6,$7)`
	issued := time.Now().UTC().Truncate(time.Second)
	expires := issued.Add(5 * time.Minute)
	ciphertextFixture := []byte("opaque-envelope-fixture")
	flow := func(mark byte) []byte { return bytes.Repeat([]byte{mark}, 16) }
	insertGrant := func(tenant string, id, command []byte, purpose string, expiry time.Time, ciphertext []byte) error {
		_, err := db.Exec(ctx, insert, tenant, id, command, purpose, issued, expiry, ciphertext)
		return err
	}
	wantState := func(t *testing.T, err error, state string) {
		t.Helper()
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != state {
			t.Fatalf("wrong SQL state: got %v, wanted %s", err, state)
		}
	}
	const purpose = "identity.oauth.onetap-start"
	if err := insertGrant("tenant-a", flow(10), first, purpose, expires, ciphertextFixture); err != nil {
		t.Fatal("insert exact original callback grant", err)
	}
	t.Run("foreign tenant and unrelated journal command", func(t *testing.T) {
		wantState(t, insertGrant("tenant-a", flow(11), foreign, purpose, expires, ciphertextFixture), "23503")
		wantState(t, insertGrant("tenant-a", flow(11), unrelated, "identity.oauth.signin-start", expires, ciphertextFixture), "23514")
	})
	t.Run("original flow and original command each unique", func(t *testing.T) {
		wantState(t, insertGrant("tenant-a", flow(10), other, purpose, expires, ciphertextFixture), "23505")
		wantState(t, insertGrant("tenant-a", flow(11), first, purpose, expires, ciphertextFixture), "23505")
	})
	t.Run("lifetime and custody shape", func(t *testing.T) {
		wantState(t, insertGrant("tenant-a", flow(11), other, purpose, expires.Add(time.Second), ciphertextFixture), "23514")
		wantState(t, insertGrant("tenant-a", flow(11), other, purpose, expires, nil), "23514")
		wantState(t, insertGrant("tenant-a", flow(0), other, purpose, expires, ciphertextFixture), "23514")
	})
	if _, err := db.Exec(ctx, `UPDATE oauth_rp.onetap_callback_grants
	 SET proof_ciphertext=NULL, erased_at=$1 WHERE tenant_id=$2 AND flow_id=$3`, issued.Add(time.Second), "tenant-a", flow(10)); err != nil {
		t.Fatal("erase known terminal custody without discarding provenance", err)
	}
	var retained bool
	if err := db.QueryRow(ctx, `SELECT proof_ciphertext IS NULL AND erased_at IS NOT NULL AND origin_command_id=$3
	 FROM oauth_rp.onetap_callback_grants WHERE tenant_id=$1 AND flow_id=$2`, "tenant-a", flow(10), first).Scan(&retained); err != nil || !retained {
		t.Fatal("historical exact ownership was not retained after erasure", err)
	}
}
