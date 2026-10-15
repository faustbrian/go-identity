package mfapostgres

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func TestPendingTOTPPreparationBindsEncryptedFactorAndReturnsNoPlaintext(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal("fixture entropy unavailable")
	}
	defer clear(key)
	keys, err := keyring.New(map[string][]byte{"wrap-v1": key})
	if err != nil {
		t.Fatal("fixture key rejected")
	}
	preparer, err := NewTOTPEnrollmentPreparer(keys, "wrap-v1")
	if err != nil {
		t.Fatal("native encryption composition rejected")
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	r := TOTPEnrollmentPreparation{TenantID: "tenant-a", UserID: "user-a", FactorID: "AAAAAAAAAAAAAAAAAAAAAQ", AuthorityVersion: 1, CreatedAt: now, TTL: 5 * time.Minute, Profile: mfa.TOTPProfile{Algorithm: "SHA1", Digits: 6, Period: 30 * time.Second, Issuer: "Example"}}
	prepared, err := preparer.Prepare(context.Background(), r)
	if err != nil {
		t.Fatal("pending factor preparation failed")
	}
	metadata, err := prepared.Metadata()
	if err != nil || metadata.TenantID != r.TenantID || metadata.UserID != r.UserID || metadata.FactorID != r.FactorID || metadata.Profile != r.Profile || !metadata.CreatedAt.Equal(now) || !metadata.ExpiresAt.Equal(now.Add(r.TTL)) {
		t.Fatal("original enrollment metadata changed")
	}
	sealed, err := prepared.Envelope()
	if err != nil {
		t.Fatal("encrypted factor unavailable")
	}
	binding, err := prepared.EncryptionContext()
	if err != nil {
		t.Fatal("original factor context unavailable")
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal("native decryptor unavailable")
	}
	plain, err := crypto.Decrypt(context.Background(), envelope.DecryptRequest{Envelope: sealed, Context: binding})
	defer clear(plain)
	if err != nil || len(plain) != 32 {
		t.Fatal("owned factor entropy not retained by envelope")
	}
	wrong, err := totpEncryptionContext(r.TenantID, r.UserID, "AAAAAAAAAAAAAAAAAAAAAg", 1, r.Profile)
	if err != nil {
		t.Fatal("fixture context rejected")
	}
	foreign, err := crypto.Decrypt(context.Background(), envelope.DecryptRequest{Envelope: sealed, Context: wrong})
	clear(foreign)
	if err == nil {
		t.Fatal("cross-factor envelope accepted")
	}
	for _, value := range []any{prepared, preparer} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			if !strings.Contains(fmt.Sprintf(verb, value), "redacted") {
				t.Fatal("diagnostic traversal of enrollment custody")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("implicit enrollment custody export accepted")
		}
	}
	fields, err := prepared.Fields()
	if err != nil {
		t.Fatal("non-secret enrollment fields unavailable")
	}
	for _, field := range fields {
		if field.Value.Kind == identity.FeatureBytes {
			t.Fatal("secret/encrypted material entered scalar command fields")
		}
	}
}

func TestPendingTOTPPreparationRejectsInvalidAndUnownedInputs(t *testing.T) {
	keys, _ := keyring.New(map[string][]byte{"wrap-v1": make([]byte, 32)})
	preparer, err := NewTOTPEnrollmentPreparer(keys, "wrap-v1")
	if err != nil {
		t.Fatal("fixture composition unavailable")
	}
	r := TOTPEnrollmentPreparation{TenantID: "tenant-a", UserID: "user-a", FactorID: "AAAAAAAAAAAAAAAAAAAAAQ", AuthorityVersion: 1, CreatedAt: time.Now().UTC().Truncate(time.Microsecond), TTL: 5 * time.Minute, Profile: mfa.TOTPProfile{Algorithm: "SHA1", Digits: 6, Period: 30 * time.Second, Issuer: "Example"}}
	for _, change := range []func(*TOTPEnrollmentPreparation){func(r *TOTPEnrollmentPreparation) { r.TenantID = "" }, func(r *TOTPEnrollmentPreparation) { r.UserID = "" }, func(r *TOTPEnrollmentPreparation) { r.FactorID = "bad" }, func(r *TOTPEnrollmentPreparation) { r.AuthorityVersion = 0 }, func(r *TOTPEnrollmentPreparation) { r.TTL = 0 }, func(r *TOTPEnrollmentPreparation) { r.TTL = 16 * time.Minute }, func(r *TOTPEnrollmentPreparation) { r.CreatedAt = time.Time{} }, func(r *TOTPEnrollmentPreparation) { r.CreatedAt = r.CreatedAt.Add(time.Nanosecond) }, func(r *TOTPEnrollmentPreparation) { r.Profile.Digits = 7 }} {
		bad := r
		change(&bad)
		prepared, err := preparer.Prepare(context.Background(), bad)
		if err == nil || prepared.custody != nil {
			t.Fatal("invalid scope produced pending factor custody")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if prepared, err := preparer.Prepare(ctx, r); !errors.Is(err, context.Canceled) || prepared.custody != nil {
		t.Fatal("cancelled preparation produced material")
	}
	var prepared PreparedTOTPEnrollment
	if _, err := prepared.Metadata(); err == nil {
		t.Fatal("zero pending factor produced metadata")
	}
	if _, err := prepared.Envelope(); err == nil {
		t.Fatal("zero pending factor produced encrypted material")
	}
	if _, err := prepared.Fields(); err == nil {
		t.Fatal("zero pending factor produced command fields")
	}
	if err := prepared.Persist(context.Background(), kernel.Work{}, nil, identity.Command{}, nil); err == nil {
		t.Fatal("unowned transaction created enrollment")
	}
}
