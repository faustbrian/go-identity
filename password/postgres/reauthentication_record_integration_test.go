//go:build integration

package passwordpostgres_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	passworddb "github.com/faustbrian/go-identity/password/postgres"
	database "github.com/faustbrian/go-postgres"
)

// Historical SQL fixtures exercise the actual primary source and installed
// constraints, not credential verification, native issuance or consumption.
func testNativeReauthenticationRead(t *testing.T, ctx context.Context, pool *database.Pool, repo *passworddb.Repository) {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	command, _ := base64.RawURLEncoding.DecodeString(string(id))
	now := time.Date(2026, 10, 9, 0, 0, 0, 123456789, time.UTC)
	original := auth.SignedReauthenticationRecord{Issuer: "issuer", Environment: "test", ProofVersion: ^uint64(0), CredentialID: "password-a", CredentialVersion: ^uint64(0), KeyID: "evidence-1", Proof: auth.ReauthenticationProof{Proof: auth.Proof{ID: auth.ProofID(id), Tenant: "tenant-a", Subject: "user-a", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "identity.password.change", Audience: "backend", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, SessionID: "session-a", SessionVersion: ^uint64(0), Action: "identity.password.change"}}
	frame, err := original.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	original.Signature = ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{19}, ed25519.SeedSize)), frame)
	payload, _ := json.Marshal(original)
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'tenant-a','identity.password.verify',$2,1,$3)`, command, bytes.Repeat([]byte{1}, 32), []byte{1}); err != nil {
		t.Fatal("proof command fixture unavailable")
	}
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'tenant-a','identity.password.verify')`, command); err != nil {
		t.Fatal("proof journal fixture unavailable")
	}
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity_password.reauthentication_records(proof_id,tenant_id,user_id,command_id,purpose,record) VALUES($1,'tenant-a','user-a',$2,'identity.password.verify',$3)`, string(id), command, payload); err != nil {
		t.Fatal("proof record fixture unavailable")
	}
	var source auth.ReauthenticationSource = repo
	for _, label := range []string{"uncommitted", "pending", "aborted"} {
		if label != "uncommitted" {
			state, terminalClass, resultVersion, result, terminalAt := "pending", any(nil), any(nil), any(nil), any(nil)
			if label == "aborted" {
				state, terminalClass, resultVersion, result, terminalAt = "aborted", "denied", 1, []byte{1}, now
			}
			if _, err = pool.Raw().Exec(ctx, `UPDATE identity.commands SET state=$2,generation=1,attempt=1,lease_owner=$3,lease_until=$4,heartbeat_at=$4,created_at=$4,updated_at=$4,terminal_class=$5,result_version=$6,result=$7,terminal_at=$8 WHERE command_id=$1`, command, state, bytes.Repeat([]byte{2}, 16), now, terminalClass, resultVersion, result, terminalAt); err != nil {
				t.Fatal("journal state fixture unavailable")
			}
		}
		got, err := source.Reauthentication(ctx, auth.ProofID(id))
		if !errors.Is(err, auth.ErrInvalidProof) || got.Proof.Proof.ID != "" || len(got.Signature) != 0 {
			t.Fatal(label, "original exposed without commit", err)
		}
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE identity.commands SET state='committed',terminal_class='committed' WHERE command_id=$1`, command); err != nil {
		t.Fatal("commit fixture unavailable")
	}
	got, err := source.Reauthentication(ctx, auth.ProofID(id))
	gotFrame, frameErr := got.SigningBytes()
	if err != nil || frameErr != nil || !bytes.Equal(frame, gotFrame) || !bytes.Equal(got.Signature, original.Signature) {
		t.Fatal("native original frame or signature changed", err)
	}
	got.Signature[0] ^= 1
	got, err = source.Reauthentication(ctx, auth.ProofID(id))
	if err != nil || !bytes.Equal(got.Signature, original.Signature) {
		t.Fatal("reader retained caller mutation")
	}
	if _, err = source.Reauthentication(ctx, "bbbbbbbbbbbbbbbbbbbbbb"); !errors.Is(err, auth.ErrInvalidProof) {
		t.Fatal("absent original classification changed")
	}
	for _, bad := range [][]byte{[]byte(`{}`), bytes.Repeat([]byte{'x'}, 32768), bytes.Replace(payload, []byte(`"Tenant":"tenant-a"`), []byte(`"Tenant":"tenant-b"`), 1)} {
		if _, err = pool.Raw().Exec(ctx, `UPDATE identity_password.reauthentication_records SET record=$2 WHERE proof_id=$1`, string(id), bad); err != nil {
			t.Fatal("corruption fixture unavailable")
		}
		got, err = source.Reauthentication(ctx, auth.ProofID(id))
		if !errors.Is(err, password.ErrPasswordWork) || got.Proof.Proof.ID != "" || len(got.Signature) != 0 {
			t.Fatal("corrupt storage returned partial original")
		}
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE identity_password.reauthentication_records SET record=$2 WHERE proof_id=$1`, string(id), payload); err != nil {
		t.Fatal("original restoration unavailable")
	}
	stopped, stop := context.WithCancel(ctx)
	stop()
	if _, err = source.Reauthentication(stopped, auth.ProofID(id)); !errors.Is(err, context.Canceled) {
		t.Fatal("source cancellation lost")
	}
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity_password.reauthentication_records SELECT * FROM identity_password.reauthentication_records WHERE proof_id=$1`, string(id)); err == nil {
		t.Fatal("duplicate original accepted")
	}
	locked, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal("source lock unavailable")
	}
	defer locked.Rollback(ctx)
	if _, err = locked.Exec(ctx, `LOCK TABLE identity_password.reauthentication_records IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal("source lock unavailable")
	}
	limited, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	_, readErr := source.Reauthentication(limited, auth.ProofID(id))
	cancel()
	if !errors.Is(readErr, context.DeadlineExceeded) {
		t.Fatal("blocked original read escaped caller deadline")
	}
	if err = locked.Rollback(ctx); err != nil {
		t.Fatal("source lock cleanup failed")
	}
	if _, err = pool.Raw().Exec(ctx, `ALTER TABLE identity_password.reauthentication_records RENAME TO fixture_reauthentication_records`); err != nil {
		t.Fatal("source loss fixture unavailable")
	}
	_, readErr = source.Reauthentication(ctx, auth.ProofID(id))
	if _, err = pool.Raw().Exec(ctx, `ALTER TABLE identity_password.fixture_reauthentication_records RENAME TO reauthentication_records`); err != nil {
		t.Fatal("source restoration failed")
	}
	if !errors.Is(readErr, password.ErrPasswordWork) {
		t.Fatal("missing original schema accepted")
	}
}
