//go:build integration

package mfapostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// Journal/factor bootstrap and direct evidence insertion are storage-oracle
// seams, not active-factor authentication. This proves actual migration,
// committed-only lookup, exact tuple/canonical-record checks and redaction;
// genuine verification and atomic issuance remain a separate public journey.
func testFactorVerificationStorage(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	if _, err := pool.Raw().Exec(ctx, factorVerificationSQL); err != nil {
		t.Fatal("factor verification storage install failed")
	}
	tenant, user, factor := "AAAAAAAAAAAAAAAAAAAAAQ", "AAAAAAAAAAAAAAAAAAAAAg", "AAAAAAAAAAAAAAAAAAAABA"
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	raw := mustContinuationCommandBytes(string(id))
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,'identity.mfa.totp-verify',$3,1,decode('01','hex'))`, raw, tenant, make([]byte, 32)); err != nil {
		t.Fatal("fixture proof command claim failed")
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,'identity.mfa.totp-verify')`, raw, tenant); err != nil {
		t.Fatal("fixture proof journal failed")
	}
	r := factorVerificationFixture(t)
	r.Original.Proof.Proof.ID, r.Original.Proof.Proof.Tenant, r.Original.Proof.Proof.Subject = auth.ProofID(id), tenant, user
	r.Original.CredentialID, r.Original.CredentialVersion, r.FactorAuthorityVersion = factor, 1, 7
	frame, err := r.Original.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	defer clear(key)
	r.Original.Signature = ed25519.Sign(key, frame)
	clear(frame)
	wire, err := encodeFactorVerificationRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.factor_verifications(proof_id,tenant_id,user_id,factor_id,enrollment_version,factor_authority_version,command_id,purpose,record) VALUES($1,$2,$3,$4,1,7,$5,'identity.mfa.totp-verify',$6)`, string(id), tenant, user, factor, raw, wire); err != nil {
		t.Fatal("fixture factor evidence failed")
	}
	source, err := NewFactorVerificationSource(pool, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := source.Reauthentication(ctx, auth.ProofID(id)); !errors.Is(err, auth.ErrInvalidProof) || got.Proof != (auth.ReauthenticationProof{}) || len(got.Signature) != 0 {
		t.Fatal("uncommitted factor evidence was visible")
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET state='committed',generation=1,attempt=1,lease_owner=decode(repeat('01',16),'hex'),lease_until=now(),heartbeat_at=now(),created_at=now(),updated_at=now(),result_version=1,terminal_class='committed',result=decode('01','hex'),terminal_at=now() WHERE command_id=$1`, raw); err != nil {
		t.Fatal("fixture commit state failed")
	}
	got, err := source.Reauthentication(ctx, auth.ProofID(id))
	if err != nil || got.Proof != r.Original.Proof || got.CredentialID != factor || got.CredentialVersion != 1 || !bytes.Equal(got.Signature, r.Original.Signature) {
		t.Fatal("committed original evidence changed on read")
	}
	frame, err = got.SigningBytes()
	if err != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), frame, got.Signature) {
		t.Fatal("source changed authentication's original signature frame")
	}
	clear(frame)
	for _, mutation := range []string{
		`UPDATE identity_mfa.factor_verifications SET enrollment_version=2 WHERE command_id=$1`,
		`UPDATE identity_mfa.factor_verifications SET factor_authority_version=8 WHERE command_id=$1`,
		`UPDATE identity_mfa.factor_verifications SET record=decode('01','hex') WHERE command_id=$1`,
	} {
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal("fixture mutation transaction failed")
		}
		if _, err := tx.Exec(ctx, mutation, raw); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal("fixture mutation failed")
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal("fixture mutation commit failed")
		}
		observed, err := source.Reauthentication(ctx, auth.ProofID(id))
		var unavailable identity.UnavailableError
		if !errors.As(err, &unavailable) || observed.Proof != (auth.ReauthenticationProof{}) || len(observed.Signature) != 0 {
			t.Fatal("corrupt binding/evidence escaped the native source")
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_verifications SET enrollment_version=1,factor_authority_version=7,record=$2 WHERE command_id=$1`, raw, wire); err != nil {
			t.Fatal("fixture evidence restoration failed")
		}
	}
	retirement, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal("fixture retirement transaction failed")
	}
	defer retirement.Rollback(ctx)
	// Canonical retirement erases the scoped payload before clearing its live
	// claim bindings. A boolean-only update is intentionally rejected by kernel
	// storage; do not weaken that constraint to construct an impossible state.
	for _, statement := range []string{
		`DELETE FROM identity_mfa.factor_verifications WHERE command_id=$1`,
		`DELETE FROM identity.commands WHERE command_id=$1`,
		`UPDATE identity.identity_command_id_claims SET retired=true,tenant_id=NULL,purpose=NULL,fingerprint=NULL,fingerprint_key_version=NULL,safe_fields=NULL WHERE command_id=$1`,
	} {
		if _, err := retirement.Exec(ctx, statement, raw); err != nil {
			t.Fatal("fixture canonical retirement failed")
		}
	}
	if err := retirement.Commit(ctx); err != nil {
		t.Fatal("fixture retirement commit failed")
	}
	if got, err := source.Reauthentication(ctx, auth.ProofID(id)); !errors.Is(err, auth.ErrInvalidProof) || got.Proof != (auth.ReauthenticationProof{}) {
		t.Fatal("retired original proof became visible")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := source.Reauthentication(canceled, auth.ProofID(id)); !errors.Is(err, context.Canceled) || got.Proof != (auth.ReauthenticationProof{}) {
		t.Fatal("proof source ignored cancellation or disclosed data")
	}
}
