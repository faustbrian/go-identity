//go:build integration

package mfapostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// The signed record and command are structural storage fixtures, not a claim
// that the active OTP verification workflow has authenticated this subject.
func testOTPFactorVerificationSourcePostgres(t *testing.T, ctx context.Context, conn *pgx.Conn, dsn, databaseName, proofID, factorID string) {
	t.Helper()
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = databaseName
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := pool.Close(cleanup); err != nil {
			t.Error("OTP source fixture pool cleanup failed")
		}
	}()
	source, err := NewOTPFactorVerificationSource(pool, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r := otpFactorVerificationFixture(t)
	r.Original.Proof.Proof.ID = auth.ProofID(proofID)
	r.Original.Proof.Proof.Subject = "factor-owner"
	r.Original.CredentialID, r.Original.CredentialVersion = factorID, 1
	r.FactorAuthorityVersion = 1
	frame, err := r.Original.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	r.Original.Signature = ed25519.Sign(key, frame)
	clear(key)
	clear(frame)
	wire, err := encodeOTPFactorVerificationRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `UPDATE identity_mfa.otp_factor_verifications SET record=$2 WHERE proof_id=$1`, proofID, wire); err != nil {
		t.Fatal(err)
	}
	if got, err := source.Reauthentication(ctx, auth.ProofID(proofID)); !errors.Is(err, auth.ErrInvalidProof) || got.Proof.Proof.ID != "" {
		t.Fatal("uncommitted OTP evidence became visible", err)
	}
	raw := mustContinuationCommandBytes(proofID)
	if _, err := conn.Exec(ctx, `UPDATE identity.commands SET state='committed',generation=1,attempt=1,lease_owner=decode(repeat('01',16),'hex'),lease_until=now(),heartbeat_at=now(),created_at=now(),updated_at=now(),result_version=1,terminal_class='committed',result=decode('01','hex'),terminal_at=now() WHERE command_id=$1`, raw); err != nil {
		t.Fatal(err)
	}
	got, err := source.Reauthentication(ctx, auth.ProofID(proofID))
	if err != nil || got.Proof != r.Original.Proof || got.CredentialID != factorID || got.CredentialVersion != 1 || !bytes.Equal(got.Signature, r.Original.Signature) {
		t.Fatal("source changed original committed OTP evidence", err)
	}
	// The ordinary TOTP source cannot accidentally interpret this distinct
	// method table as TOTP evidence, even with the same globally unique proof ID.
	totp, err := NewFactorVerificationSource(pool, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := totp.Reauthentication(ctx, auth.ProofID(proofID)); !errors.Is(err, auth.ErrInvalidProof) || got.Proof.Proof.ID != "" {
		t.Fatal("OTP record crossed into the TOTP source", err)
	}
	if _, err := conn.Exec(ctx, `UPDATE identity_mfa.otp_factor_verifications SET factor_authority_version=2 WHERE proof_id=$1`, proofID); err != nil {
		t.Fatal(err)
	}
	var unavailable identity.UnavailableError
	if got, err := source.Reauthentication(ctx, auth.ProofID(proofID)); !errors.As(err, &unavailable) || got.Proof.Proof.ID != "" {
		t.Fatal("contradictory OTP factor epoch yielded partial evidence", err)
	}
	if _, err := conn.Exec(ctx, `UPDATE identity_mfa.otp_factor_verifications SET factor_authority_version=1,record=decode('01','hex') WHERE proof_id=$1`, proofID); err != nil {
		t.Fatal(err)
	}
	if got, err := source.Reauthentication(ctx, auth.ProofID(proofID)); !errors.As(err, &unavailable) || got.Proof.Proof.ID != "" {
		t.Fatal("corrupt OTP record yielded partial evidence", err)
	}
	if _, err := conn.Exec(ctx, `UPDATE identity_mfa.otp_factor_verifications SET record=$2 WHERE proof_id=$1`, proofID, wire); err != nil {
		t.Fatal(err)
	}
	retirement, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer retirement.Rollback(ctx)
	// Exercise canonical owner retirement, not an impossible boolean-only
	// update that leaves the live claim's scoped payload behind.
	for _, statement := range []string{
		`DELETE FROM identity_mfa.otp_factor_verifications WHERE command_id=$1`,
		`DELETE FROM identity.commands WHERE command_id=$1`,
		`UPDATE identity.identity_command_id_claims SET retired=true,tenant_id=NULL,purpose=NULL,fingerprint=NULL,fingerprint_key_version=NULL,safe_fields=NULL WHERE command_id=$1`,
	} {
		if _, err := retirement.Exec(ctx, statement, raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := retirement.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := source.Reauthentication(ctx, auth.ProofID(proofID)); !errors.Is(err, auth.ErrInvalidProof) || got.Proof.Proof.ID != "" {
		t.Fatal("retired OTP command yielded evidence", err)
	}
}
