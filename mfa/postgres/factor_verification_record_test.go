package mfapostgres

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
)

func factorVerificationFixture(t testing.TB) factorVerificationRecord {
	t.Helper()
	at := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	r := factorVerificationRecord{Schema: 1, FactorAuthorityVersion: 3, Original: auth.SignedReauthenticationRecord{Issuer: "https://issuer.example", Environment: "test", Proof: auth.ReauthenticationProof{Proof: auth.Proof{ID: "AAAAAAAAAAAAAAAAAAAAAQ", Tenant: "tenant-a", Subject: "user-a", Method: "totp", Assurance: auth.AssuranceMultiFactor, Purpose: "identity.mfa.recovery-regenerate", Audience: "backend", IssuedAt: at, ExpiresAt: at.Add(time.Minute)}, SessionID: "source-session", SessionVersion: 1, Action: "identity.mfa.recovery-regenerate"}, ProofVersion: 1, CredentialID: "AAAAAAAAAAAAAAAAAAAAAg", CredentialVersion: 2, KeyID: "evidence-v1"}}
	frame, err := r.Original.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	defer clear(key)
	r.Original.Signature = ed25519.Sign(key, frame)
	clear(frame)
	return r
}

func FuzzFactorVerificationRecord(f *testing.F) {
	r := factorVerificationFixture(f)
	wire, err := encodeFactorVerificationRecord(r)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"Schema":1,"Schema":2}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := decodeFactorVerificationRecord(r.Original.Proof.Proof.ID, "tenant-a", "user-a", data)
		if err != nil {
			return
		}
		canonical, err := encodeFactorVerificationRecord(got)
		if err != nil || !bytes.Equal(canonical, data) || got.Original.Proof.Proof.ID != r.Original.Proof.Proof.ID || got.Original.Proof.Proof.Tenant != "tenant-a" || got.Original.Proof.Proof.Subject != "user-a" || len(data) > maximumFactorVerificationRecordBytes {
			t.Fatal("decoder admitted noncanonical or foreign evidence")
		}
	})
}

func TestFactorVerificationRecordPreservesSignedOriginalAndOwnerEpoch(t *testing.T) {
	r := factorVerificationFixture(t)
	wire, err := encodeFactorVerificationRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeFactorVerificationRecord(r.Original.Proof.Proof.ID, "tenant-a", "user-a", wire)
	if err != nil || got.FactorAuthorityVersion != r.FactorAuthorityVersion || got.Original.Proof != r.Original.Proof || got.Original.CredentialID != r.Original.CredentialID || got.Original.CredentialVersion != r.Original.CredentialVersion || !bytes.Equal(got.Original.Signature, r.Original.Signature) {
		t.Fatal("signed original or factor epoch changed on storage round trip")
	}
	for _, mutate := range []func(*factorVerificationRecord){
		func(r *factorVerificationRecord) { r.Schema = 2 },
		func(r *factorVerificationRecord) { r.FactorAuthorityVersion = 0 },
		func(r *factorVerificationRecord) { r.Original.Proof.Proof.Method = "password" },
		func(r *factorVerificationRecord) { r.Original.Proof.Proof.Assurance = auth.AssuranceSingleFactor },
		func(r *factorVerificationRecord) { r.Original.Proof.Action = "identity.mfa.enable" },
		func(r *factorVerificationRecord) {
			r.Original.Proof.Proof.ExpiresAt = r.Original.Proof.Proof.IssuedAt.Add(6 * time.Minute)
		},
		func(r *factorVerificationRecord) { r.Original.CredentialID = "not-a-factor" },
		func(r *factorVerificationRecord) { r.Original.Signature = nil },
	} {
		bad := r
		mutate(&bad)
		if _, err := encodeFactorVerificationRecord(bad); err == nil {
			t.Fatal("invalid factor verification encoded")
		}
	}
	for _, payload := range [][]byte{nil, []byte(`{}`), append(bytes.Clone(wire), []byte(`{}`)...), bytes.Replace(wire, []byte(`"Schema":1`), []byte(`"Schema":1,"Schema":1`), 1), bytes.Repeat([]byte("x"), maximumFactorVerificationRecordBytes+1)} {
		if _, err := decodeFactorVerificationRecord(r.Original.Proof.Proof.ID, "tenant-a", "user-a", payload); err == nil {
			t.Fatal("noncanonical or unbounded evidence decoded")
		}
	}
	if _, err := decodeFactorVerificationRecord(r.Original.Proof.Proof.ID, "other-tenant", "user-a", wire); err == nil {
		t.Fatal("foreign evidence crossed tenant scope")
	}
}
