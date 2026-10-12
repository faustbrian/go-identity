//go:build integration

package mfapostgres

import (
	"context"
	"crypto/rand"
	"strconv"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	password "github.com/faustbrian/go-password"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

// Enrollment command/account authority are fixtures. This tests real storage
// installation and encrypted-custody/state constraints, not an enrollment API
// or protected native session completion.
func testTOTPStorage(t *testing.T, ctx context.Context, pool *database.Pool) (*envelope.Service, string) {
	t.Helper()
	history, err := (TOTPFactorMigrationSource{Base: ContinuationMigrationSource{Base: MigrationSource{Version: 1}, Version: 2}, Version: 3}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, history[2].UpSQL()); err != nil {
		t.Fatal("TOTP install", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal("fixture entropy unavailable")
	}
	defer clear(key)
	provider, err := keyring.New(map[string][]byte{"totp-test-v1": key})
	if err != nil {
		t.Fatal("fixture wrapping key rejected")
	}
	crypto, err := envelope.NewService(provider)
	if err != nil {
		t.Fatal(err)
	}
	var activeID string
	for i, mode := range []string{"pending", "active-unconfirmed", "active", "revoked-retained", "revoked", "bad-profile"} {
		t.Run(mode, func(t *testing.T) {
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			command := mustContinuationCommandBytes(string(id))
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'tenant-a','identity.mfa.enable',$2,1,decode('01','hex'))`, command, make([]byte, 32)); err != nil {
				t.Fatal("fixture enrollment command", err)
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'tenant-a','identity.mfa.enable')`, command); err != nil {
				t.Fatal("fixture enrollment journal", err)
			}
			profile := mfa.TOTPProfile{Algorithm: "SHA1", Digits: 8, Period: 30 * time.Second, Issuer: "Example"}
			binding, err := totpEncryptionContext("tenant-a", "mfa-user", string(id), 1, profile)
			if err != nil {
				t.Fatal(err)
			}
			sealed, err := crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: []byte("12345678901234567890"), KeyReference: "totp-test-v1", Context: binding})
			if err != nil {
				t.Fatal("factor encryption unavailable")
			}
			wire, err := sealed.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			defer clear(wire)
			now := time.Now().UTC()
			state := 1
			var confirmed any
			var stored any = wire
			digits := 8
			switch mode {
			case "active-unconfirmed":
				state = 2
			case "active":
				state = 2
				confirmed = now
			case "revoked-retained":
				state = 3
			case "revoked":
				state = 3
				stored = nil
			case "bad-profile":
				digits = 11
			}
			_, err = pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.totp_factors(tenant_id,user_id,factor_id,state,enrollment_version,row_version,algorithm,digits,period_seconds,skew_steps,issuer,encrypted_secret,created_command_id,created_purpose,created_at,enrollment_expires_at,confirmed_at) VALUES('tenant-a','mfa-user',$1,$2,1,1,'SHA1',$3,30,0,'Example',$4,$5,'identity.mfa.enable',$6,$7,$8)`, string(id), state, digits, stored, command, now, now.Add(5*time.Minute), confirmed)
			denied := mode == "active-unconfirmed" || mode == "revoked-retained" || mode == "bad-profile"
			if denied {
				if err == nil {
					t.Fatal("invalid factor state persisted", strconv.Itoa(i))
				}
				return
			}
			if err != nil {
				t.Fatal("valid encrypted factor rejected", err)
			}
			if mode == "active" {
				activeID = string(id)
			}
			if mode == "revoked" {
				return
			}
			var actual []byte
			if err := pool.Raw().QueryRow(ctx, `SELECT encrypted_secret FROM identity_mfa.totp_factors WHERE tenant_id='tenant-a' AND factor_id=$1`, string(id)).Scan(&actual); err != nil {
				t.Fatal(err)
			}
			defer clear(actual)
			persisted, err := envelope.ParseEnvelope(actual)
			if err != nil {
				t.Fatal("stored custody malformed")
			}
			plain, err := crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: persisted, Context: binding})
			defer clear(plain)
			if err != nil || string(plain) != "12345678901234567890" {
				t.Fatal("stored encrypted custody changed")
			}
			foreign, err := totpEncryptionContext("tenant-a", "foreign-user", string(id), 1, profile)
			if err != nil {
				t.Fatal(err)
			}
			other, err := crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: persisted, Context: foreign})
			clear(other)
			if err == nil {
				t.Fatal("cross-user factor secret decrypted")
			}
		})
	}
	if activeID == "" {
		t.Fatal("confirmed fixture factor unavailable")
	}
	return crypto, activeID
}

func testTOTPFactorRead(t *testing.T, ctx context.Context, pool *database.Pool, grant capability.Grant, issuer, factorID string, crypto *envelope.Service) {
	t.Helper()
	reader, err := NewTOTPFactorReader(pool, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := reader.Read(ctx, grant, issuer, factorID)
	if err != nil {
		t.Fatal("native confirmed factor read failed", err)
	}
	metadata, err := snapshot.Metadata()
	if err != nil || metadata.FactorID != factorID || metadata.Replay.Used || metadata.EnrollmentVersion != 1 || metadata.RowVersion != 1 {
		t.Fatal("factor snapshot replaced original metadata")
	}
	testTOTPAttemptStorage(t, ctx, pool, snapshot)
	sealed, err := snapshot.Envelope()
	if err != nil {
		t.Fatal(err)
	}
	binding, err := snapshot.EncryptionContext()
	if err != nil {
		t.Fatal(err)
	}
	plain, err := crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: binding})
	defer clear(plain)
	if err != nil {
		t.Fatal("native factor profile/custody binding unavailable")
	}
	secret, err := password.NewSecret(plain)
	clear(plain)
	if err != nil {
		t.Fatal("owned factor secret unavailable")
	}
	defer secret.Destroy()
	verifier, err := mfa.NewTOTPVerifier([32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	code, err := auth.NewOneTimeCode("94287082")
	if err != nil {
		t.Fatal("public vector unavailable")
	}
	step, err := verifier.Verify(ctx, secret, code, metadata.Profile, []byte("fixture/factor/challenge/key-version-1"), time.Unix(59, 0), metadata.Replay)
	if err != nil || step != 1 {
		t.Fatal("stored encrypted factor did not compose with native verifier")
	}
	if _, err := reader.Read(ctx, capability.Grant{}, issuer, factorID); err == nil {
		t.Fatal("zero grant read factor")
	}
	var pending string
	if err := pool.Raw().QueryRow(ctx, `SELECT factor_id FROM identity_mfa.totp_factors WHERE state=1 LIMIT 1`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(ctx, grant, issuer, pending); err == nil {
		t.Fatal("pending enrollment became usable factor")
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.totp_factors SET issuer='Changed' WHERE tenant_id='tenant-a' AND factor_id=$1`, factorID); err != nil {
		t.Fatal(err)
	}
	changed, err := reader.Read(ctx, grant, issuer, factorID)
	if err != nil {
		t.Fatal("tampered profile fixture unavailable")
	}
	changedEnvelope, err := changed.Envelope()
	if err != nil {
		t.Fatal(err)
	}
	changedBinding, err := changed.EncryptionContext()
	if err != nil {
		t.Fatal(err)
	}
	invalidPlain, err := crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: changedEnvelope, Context: changedBinding})
	clear(invalidPlain)
	if err == nil {
		t.Fatal("stored profile substitution decrypted original factor secret")
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.totp_factors SET issuer='Example' WHERE tenant_id='tenant-a' AND factor_id=$1`, factorID); err != nil {
		t.Fatal(err)
	}
}
