package mfapostgres

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
)

func otpFactorVerificationFixture(t testing.TB) factorVerificationRecord {
	t.Helper()
	r := factorVerificationFixture(t)
	r.Schema = 2
	r.Original.Proof.Proof.Method = "otp"
	r.Original.Proof.Proof.Purpose = "identity.mfa.factor-update"
	r.Original.Proof.Action = string(r.Original.Proof.Proof.Purpose)
	frame, err := r.Original.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	r.Original.Signature = ed25519.Sign(key, frame)
	clear(key)
	clear(frame)
	return r
}

func TestOTPFactorVerificationKeepsOriginalSignedActionAndDistinctProfile(t *testing.T) {
	r := otpFactorVerificationFixture(t)
	wire, err := encodeOTPFactorVerificationRecord(r)
	if err != nil {
		t.Fatal("native OTP action evidence cannot be retained", err)
	}
	got, err := decodeOTPFactorVerificationRecord(r.Original.Proof.Proof.ID, "tenant-a", "user-a", wire)
	if err != nil || got.Original.Proof != r.Original.Proof || got.FactorAuthorityVersion != r.FactorAuthorityVersion || got.Original.CredentialID != r.Original.CredentialID || got.Original.CredentialVersion != r.Original.CredentialVersion || !bytes.Equal(got.Original.Signature, r.Original.Signature) {
		t.Fatal("OTP evidence changed original authentication or factor authority", err)
	}
	frame, err := got.Original.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), frame, got.Original.Signature) {
		t.Fatal("retention changed original signed evidence")
	}
	clear(frame)
	clear(key)
	if _, err := decodeFactorVerificationRecord(r.Original.Proof.Proof.ID, "tenant-a", "user-a", wire); err == nil {
		t.Fatal("OTP evidence silently reinterpreted as the existing TOTP profile")
	}
	if _, err := decodeOTPFactorVerificationRecord(r.Original.Proof.Proof.ID, "foreign", "user-a", wire); err == nil {
		t.Fatal("OTP evidence crossed tenant scope")
	}
	for _, change := range []func(*factorVerificationRecord){
		func(r *factorVerificationRecord) { r.Schema = 1 },
		func(r *factorVerificationRecord) { r.FactorAuthorityVersion = 0 },
		func(r *factorVerificationRecord) { r.Original.Proof.Proof.Method = "totp" },
		func(r *factorVerificationRecord) { r.Original.Proof.Proof.Method = "password" },
		func(r *factorVerificationRecord) { r.Original.Proof.Proof.Assurance = auth.AssuranceSingleFactor },
		func(r *factorVerificationRecord) {
			r.Original.Proof.Proof.Purpose = "identity.mfa.disable"
			r.Original.Proof.Action = "identity.mfa.disable"
		},
	} {
		bad := r
		change(&bad)
		if _, err := encodeOTPFactorVerificationRecord(bad); err == nil {
			t.Fatal("unselected action/method/authority encoded as OTP rename evidence")
		}
	}
}

func FuzzOTPFactorVerificationRecord(f *testing.F) {
	r := otpFactorVerificationFixture(f)
	wire, err := encodeOTPFactorVerificationRecord(r)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"Schema":2,"Schema":2}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := decodeOTPFactorVerificationRecord(r.Original.Proof.Proof.ID, "tenant-a", "user-a", data)
		if err != nil {
			return
		}
		canonical, err := encodeOTPFactorVerificationRecord(got)
		if err != nil || !bytes.Equal(canonical, data) || got.Schema != 2 || got.Original.Proof.Proof.Method != "otp" || got.Original.Proof.Action != "identity.mfa.factor-update" || len(data) > maximumFactorVerificationRecordBytes {
			t.Fatal("OTP decoder accepted noncanonical or foreign-profile evidence")
		}
	})
}
