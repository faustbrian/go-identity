//go:build integration

package passwordintegration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	passworddb "github.com/faustbrian/go-identity/password/postgres"
	database "github.com/faustbrian/go-postgres"
)

// Original-record storage is a prerequisite, not an authentication workflow.
// These historical fixtures grant no password match, policy or session authority.
func testNativeSigninRead(t *testing.T, ctx context.Context, pool *database.Pool, repo *passworddb.Repository) {
	t.Helper()
	source, ok := any(repo).(auth.SignInSource)
	if !ok {
		t.Fatal("owned committed password signin source unavailable")
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	command, _ := base64.RawURLEncoding.DecodeString(string(id))
	now := time.Date(2026, 10, 10, 0, 0, 0, 123456789, time.UTC)
	original := auth.SignedSignInRecord{Issuer: "issuer", Environment: "test", State: auth.SignInStateAuthenticated, ProofVersion: ^uint64(0), CredentialID: "password-a", CredentialVersion: ^uint64(0), KeyID: "evidence-1", Proof: auth.Proof{ID: auth.ProofID(id), Tenant: "tenant-a", Subject: "user-a", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: "backend", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}}
	frame, err := original.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	original.Signature = ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{20}, ed25519.SeedSize)), frame)
	payload, _ := json.Marshal(original)
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'tenant-a','identity.password.signin',$2,1,$3)`, command, bytes.Repeat([]byte{1}, 32), []byte{1}); err != nil {
		t.Fatal("signin command fixture unavailable")
	}
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'tenant-a','identity.password.signin')`, command); err != nil {
		t.Fatal("signin journal fixture unavailable")
	}
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity_password.signin_records(proof_id,tenant_id,user_id,command_id,purpose,record) VALUES($1,'tenant-a','user-a',$2,'identity.password.signin',$3)`, string(id), command, payload); err != nil {
		t.Fatal("signin record fixture unavailable")
	}
	for _, label := range []string{"uncommitted", "pending", "aborted"} {
		if label != "uncommitted" {
			state, terminalClass, resultVersion, result, terminalAt := "pending", any(nil), any(nil), any(nil), any(nil)
			if label == "aborted" {
				state, terminalClass, resultVersion, result, terminalAt = "aborted", "denied", 1, []byte{1}, now
			}
			if _, err = pool.Raw().Exec(ctx, `UPDATE identity.commands SET state=$2,generation=1,attempt=1,lease_owner=$3,lease_until=$4,heartbeat_at=$4,created_at=$4,updated_at=$4,terminal_class=$5,result_version=$6,result=$7,terminal_at=$8 WHERE command_id=$1`, command, state, bytes.Repeat([]byte{2}, 16), now, terminalClass, resultVersion, result, terminalAt); err != nil {
				t.Fatal("signin state fixture unavailable")
			}
		}
		got, err := source.SignInAuthentication(ctx, auth.ProofID(id))
		if !errors.Is(err, auth.ErrInvalidProof) || got.Proof.ID != "" || len(got.Signature) != 0 {
			t.Fatal(label, "original exposed without commit")
		}
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE identity.commands SET state='committed',terminal_class='committed' WHERE command_id=$1`, command); err != nil {
		t.Fatal("signin commit fixture unavailable")
	}
	got, err := source.SignInAuthentication(ctx, auth.ProofID(id))
	gotFrame, frameErr := got.SigningBytes()
	if err != nil || frameErr != nil || !bytes.Equal(frame, gotFrame) || !bytes.Equal(got.Signature, original.Signature) {
		t.Fatal("signin original frame or signature changed")
	}
	got.Signature[0] ^= 1
	got, err = source.SignInAuthentication(ctx, auth.ProofID(id))
	if err != nil || !bytes.Equal(got.Signature, original.Signature) {
		t.Fatal("signin reader retained caller mutation")
	}
	if _, err = source.SignInAuthentication(ctx, "bbbbbbbbbbbbbbbbbbbbbb"); !errors.Is(err, auth.ErrInvalidProof) {
		t.Fatal("absent signin original classification changed")
	}
	for _, bad := range [][]byte{[]byte(`{}`), bytes.Repeat([]byte{'x'}, 32768), bytes.Replace(payload, []byte(`"Tenant":"tenant-a"`), []byte(`"Tenant":"tenant-b"`), 1)} {
		if _, err = pool.Raw().Exec(ctx, `UPDATE identity_password.signin_records SET record=$2 WHERE proof_id=$1`, string(id), bad); err != nil {
			t.Fatal("signin corruption fixture unavailable")
		}
		got, err = source.SignInAuthentication(ctx, auth.ProofID(id))
		if !errors.Is(err, password.ErrPasswordWork) || got.Proof.ID != "" || len(got.Signature) != 0 {
			t.Fatal("corrupt signin storage returned partial original")
		}
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE identity_password.signin_records SET record=$2 WHERE proof_id=$1`, string(id), payload); err != nil {
		t.Fatal("signin restoration unavailable")
	}
	stopped, stop := context.WithCancel(ctx)
	stop()
	if _, err = source.SignInAuthentication(stopped, auth.ProofID(id)); !errors.Is(err, context.Canceled) {
		t.Fatal("signin cancellation lost")
	}
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity_password.signin_records SELECT * FROM identity_password.signin_records WHERE proof_id=$1`, string(id)); err == nil {
		t.Fatal("duplicate signin original accepted")
	}
	locked, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal("signin source lock unavailable")
	}
	defer locked.Rollback(ctx)
	if _, err = locked.Exec(ctx, `LOCK TABLE identity_password.signin_records IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal("signin source lock unavailable")
	}
	limited, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	_, readErr := source.SignInAuthentication(limited, auth.ProofID(id))
	cancel()
	if !errors.Is(readErr, context.DeadlineExceeded) {
		t.Fatal("blocked signin read escaped deadline")
	}
	if err = locked.Rollback(ctx); err != nil {
		t.Fatal("signin lock cleanup failed")
	}
	if _, err = pool.Raw().Exec(ctx, `ALTER TABLE identity_password.signin_records RENAME TO fixture_signin_records`); err != nil {
		t.Fatal("signin source loss fixture unavailable")
	}
	_, readErr = source.SignInAuthentication(ctx, auth.ProofID(id))
	if _, err = pool.Raw().Exec(ctx, `ALTER TABLE identity_password.fixture_signin_records RENAME TO signin_records`); err != nil {
		t.Fatal("signin source restoration failed")
	}
	if !errors.Is(readErr, password.ErrPasswordWork) {
		t.Fatal("missing signin schema accepted")
	}
}
