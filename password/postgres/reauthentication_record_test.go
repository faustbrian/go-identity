package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	password "github.com/faustbrian/go-identity/password"
)

func originalReauthenticationFixture(t testing.TB) auth.SignedReauthenticationRecord {
	t.Helper()
	now := time.Date(2026, 10, 9, 19, 0, 0, 123456789, time.UTC)
	r := auth.SignedReauthenticationRecord{Issuer: "issuer", Environment: "test", ProofVersion: ^uint64(0), CredentialID: "password", CredentialVersion: ^uint64(0), KeyID: "evidence-1", Proof: auth.ReauthenticationProof{Proof: auth.Proof{ID: "aaaaaaaaaaaaaaaaaaaaaa", Tenant: "tenant", Subject: "user", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "identity.password.change", Audience: "backend", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}, SessionID: "source-session", SessionVersion: ^uint64(0), Action: "identity.password.change"}}
	frame, err := r.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, ed25519.SeedSize)), frame)
	return r
}

func TestReauthenticationRecordRetainsExactSignedOriginal(t *testing.T) {
	original := originalReauthenticationFixture(t)
	payload, err := encodeReauthenticationRecord(original)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := decodeReauthenticationRecord(original.Proof.Proof.ID, original.Proof.Proof.Tenant, original.Proof.Proof.Subject, payload)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := original.SigningBytes()
	got, _ := restored.SigningBytes()
	if !bytes.Equal(got, want) || !bytes.Equal(restored.Signature, original.Signature) {
		t.Fatal("original signing frame, full-width versions or nanosecond times changed")
	}
	restored.Signature[0] ^= 1
	if restored.Signature[0] == original.Signature[0] {
		t.Fatal("decoder borrowed input signature")
	}
}

func TestReauthenticationRecordRejectsCorruptOrForeignStorage(t *testing.T) {
	r := originalReauthenticationFixture(t)
	payload, _ := json.Marshal(r)
	for _, tc := range []struct {
		name, tenant, user string
		id                 auth.ProofID
		payload            []byte
	}{
		{"foreign tenant", "foreign", "user", r.Proof.Proof.ID, payload},
		{"foreign user", "tenant", "foreign", r.Proof.Proof.ID, payload},
		{"foreign id", "tenant", "user", "bbbbbbbbbbbbbbbbbbbbbb", payload},
		{"unknown field", "tenant", "user", r.Proof.Proof.ID, append(append([]byte{}, payload[:len(payload)-1]...), []byte(",\"Extra\":true}")...)},
		{"duplicate", "tenant", "user", r.Proof.Proof.ID, append(append([]byte{}, payload[:len(payload)-1]...), []byte(",\"Issuer\":\"issuer\"}")...)},
		{"oversize", "tenant", "user", r.Proof.Proof.ID, bytes.Repeat([]byte{'x'}, 32769)},
		{"empty", "tenant", "user", r.Proof.Proof.ID, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeReauthenticationRecord(tc.id, tc.tenant, tc.user, tc.payload)
			if !errors.Is(err, password.ErrPasswordWork) || got.Proof.Proof.ID != "" || len(got.Signature) != 0 {
				t.Fatal("corrupt/foreign storage yielded a partial original", err)
			}
		})
	}
	for _, change := range []func(*auth.SignedReauthenticationRecord){
		func(r *auth.SignedReauthenticationRecord) { r.Signature = nil },
		func(r *auth.SignedReauthenticationRecord) { r.ProofVersion = 0 },
		func(r *auth.SignedReauthenticationRecord) { r.CredentialVersion = 0 },
		func(r *auth.SignedReauthenticationRecord) { r.Proof.SessionVersion = 0 },
		func(r *auth.SignedReauthenticationRecord) { r.Proof.Proof.Method = "oauth" },
	} {
		copy := r
		change(&copy)
		if _, err := encodeReauthenticationRecord(copy); !errors.Is(err, password.ErrPasswordWork) {
			t.Fatal("incomplete or foreign-method original accepted")
		}
	}
}

func TestReauthenticationSourceZeroAndInputBounds(t *testing.T) {
	var r *Repository
	for _, id := range []auth.ProofID{"", "short", auth.ProofID(bytes.Repeat([]byte{'x'}, 129)), "aaaaaaaaaaaaaaaaaaaaa "} {
		if validReauthenticationID(id) {
			t.Fatal("invalid proof identifier accepted")
		}
		got, err := r.Reauthentication(context.Background(), id)
		if !errors.Is(err, password.ErrPasswordWork) || got.Proof.Proof.ID != "" {
			t.Fatal("zero source yielded partial data")
		}
	}
}

func FuzzOriginalReauthenticationRecord(f *testing.F) {
	original := originalReauthenticationFixture(f)
	payload, err := encodeReauthenticationRecord(original)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(payload)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"Issuer":"issuer","Issuer":"other"}`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		got, err := decodeReauthenticationRecord("aaaaaaaaaaaaaaaaaaaaaa", "tenant", "user", payload)
		if err != nil {
			if got.Proof.Proof.ID != "" || len(got.Signature) != 0 {
				t.Fatal("denial returned partial original")
			}
			return
		}
		canonical, err := encodeReauthenticationRecord(got)
		if err != nil || !bytes.Equal(canonical, payload) {
			t.Fatal("accepted record lacks complete canonical representation")
		}
	})
}
