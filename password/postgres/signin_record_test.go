package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	password "github.com/faustbrian/go-identity/password"
)

func originalSigninFixture(t testing.TB) auth.SignedSignInRecord {
	t.Helper()
	now := time.Date(2026, 10, 10, 0, 0, 0, 123456789, time.FixedZone("offset", 3600))
	r := auth.SignedSignInRecord{Issuer: "issuer", Environment: "test", State: auth.SignInStateAuthenticated, ProofVersion: ^uint64(0), CredentialID: "password", CredentialVersion: ^uint64(0), KeyID: "evidence-1", Proof: auth.Proof{ID: "aaaaaaaaaaaaaaaaaaaaaa", Tenant: "tenant", Subject: "user", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: "backend", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}}
	frame, err := r.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{20}, ed25519.SeedSize)), frame)
	return r
}

func TestSigninRecordPreservesSignedOriginal(t *testing.T) {
	original := originalSigninFixture(t)
	payload, err := encodeSigninRecord(original)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeSigninRecord(original.Proof.ID, "tenant", "user", payload)
	wantFrame, _ := original.SigningBytes()
	gotFrame, frameErr := got.SigningBytes()
	if err != nil || frameErr != nil || !bytes.Equal(gotFrame, wantFrame) || !bytes.Equal(got.Signature, original.Signature) || !got.Proof.IssuedAt.Equal(original.Proof.IssuedAt) || !got.Proof.ExpiresAt.Equal(original.Proof.ExpiresAt) {
		t.Fatal("original signature, versions or exact timestamps changed")
	}
	got.Signature[0] ^= 1
	if got.Signature[0] == original.Signature[0] {
		t.Fatal("decoder borrowed signature custody")
	}
	// Signature verification deliberately belongs to the configured upstream
	// authenticator. The storage codec must neither mint nor authenticate a proof.
	tampered, _ := encodeSigninRecord(got)
	if _, err := decodeSigninRecord(got.Proof.ID, "tenant", "user", tampered); err != nil {
		t.Fatal("storage codec became a competing signature validator")
	}
}

func TestSigninRecordRejectsMalformedAndForeignStorage(t *testing.T) {
	original := originalSigninFixture(t)
	payload, _ := encodeSigninRecord(original)
	for _, tc := range []struct {
		name, tenant, user string
		id                 auth.ProofID
		payload            []byte
	}{
		{"foreign tenant", "foreign", "user", original.Proof.ID, payload},
		{"foreign user", "tenant", "foreign", original.Proof.ID, payload},
		{"foreign proof", "tenant", "user", "bbbbbbbbbbbbbbbbbbbbbb", payload},
		{"empty", "tenant", "user", original.Proof.ID, nil},
		{"oversize", "tenant", "user", original.Proof.ID, bytes.Repeat([]byte{'x'}, maximumSigninRecordBytes+1)},
		{"unknown", "tenant", "user", original.Proof.ID, append(append([]byte{}, payload[:len(payload)-1]...), []byte(`,"Extra":true}`)...)},
		{"duplicate", "tenant", "user", original.Proof.ID, append(append([]byte{}, payload[:len(payload)-1]...), []byte(`,"Issuer":"issuer"}`)...)},
		{"case alias", "tenant", "user", original.Proof.ID, bytes.Replace(payload, []byte(`"Issuer"`), []byte(`"issuer"`), 1)},
		{"trailing", "tenant", "user", original.Proof.ID, append(append([]byte{}, payload...), []byte(`{}`)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeSigninRecord(tc.id, tc.tenant, tc.user, tc.payload)
			if !errors.Is(err, password.ErrPasswordWork) || got.Proof.ID != "" || len(got.Signature) != 0 {
				t.Fatal("malformed storage returned a partial signin original")
			}
		})
	}
	for _, mutate := range []func(*auth.SignedSignInRecord){
		func(r *auth.SignedSignInRecord) { r.State = auth.SignInStateChallengeRequired },
		func(r *auth.SignedSignInRecord) { r.Proof.Method = "otp" },
		func(r *auth.SignedSignInRecord) { r.Proof.Assurance = auth.AssuranceMultiFactor },
		func(r *auth.SignedSignInRecord) { r.Proof.Purpose = "identity.password.change" },
		func(r *auth.SignedSignInRecord) { r.ProofVersion = 0 },
		func(r *auth.SignedSignInRecord) { r.CredentialVersion = 0 },
		func(r *auth.SignedSignInRecord) { r.CredentialID = "" },
		func(r *auth.SignedSignInRecord) { r.Signature = nil },
	} {
		r := original
		mutate(&r)
		raw, _ := json.Marshal(r)
		got, err := decodeSigninRecord(original.Proof.ID, "tenant", "user", raw)
		if !errors.Is(err, password.ErrPasswordWork) || got.Proof.ID != "" {
			t.Fatal("incomplete or unsupported signin original accepted")
		}
	}
	for _, r := range []*Repository{nil, {}} {
		got, err := r.SignInAuthentication(context.Background(), original.Proof.ID)
		if !errors.Is(err, password.ErrPasswordWork) || got.Proof.ID != "" {
			t.Fatal("zero reader yielded authority data")
		}
	}
}

func FuzzOriginalSigninRecord(f *testing.F) {
	r := originalSigninFixture(f)
	payload, err := encodeSigninRecord(r)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(payload)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"Issuer":"issuer","Issuer":"other"}`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		got, err := decodeSigninRecord(r.Proof.ID, "tenant", "user", payload)
		if err != nil {
			if got.Proof.ID != "" || len(got.Signature) != 0 {
				t.Fatal("denial returned partial original")
			}
			return
		}
		canonical, err := encodeSigninRecord(got)
		if err != nil || !bytes.Equal(canonical, payload) {
			t.Fatal("accepted noncanonical original")
		}
	})
}
