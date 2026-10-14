package postgres

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/faustbrian/go-identity/delivery"
)

func TestReconciliationCursorRestartScopeAndRotation(t *testing.T) {
	codec, _, _ := custodyFixture(t)
	scope := reconciliationCursorScope{Deployment: "test", Tenant: "tenant", Subject: "user", Effect: "synthetic-effect-0001", Provider: "provider", ProviderVersion: 1, Generation: 1, Step: 1}
	namespace := [32]byte{9}
	secret := "synthetic-provider-private-cursor"
	scope.Digest = reconciliationCursorDigest(namespace, scope, secret)
	sealed, err := sealReconciliationCursor(context.Background(), codec, scope, secret, "envelope-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed.Wire, []byte(secret)) {
		t.Fatal("plaintext cursor persisted")
	}
	// A fresh codec with a newer active key must still open retained old custody.
	restarted, err := newPayloadCodec(codec.service, map[uint32][32]byte{1: {3}, 2: {4}}, codec.timeout)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := openReconciliationCursor(context.Background(), restarted, scope, sealed); err != nil || got != secret {
		t.Fatal("restart lost original cursor", err)
	}
	for _, change := range []func(*reconciliationCursorScope){
		func(s *reconciliationCursorScope) { s.Deployment = "other" },
		func(s *reconciliationCursorScope) { s.Tenant = "other" },
		func(s *reconciliationCursorScope) { s.Subject = "other" },
		func(s *reconciliationCursorScope) { s.Effect = "other" },
		func(s *reconciliationCursorScope) { s.Provider = "other" },
		func(s *reconciliationCursorScope) { s.ProviderVersion++ },
		func(s *reconciliationCursorScope) { s.Generation++ },
		func(s *reconciliationCursorScope) { s.Step++ },
		func(s *reconciliationCursorScope) { s.Digest[0]++ },
	} {
		altered := scope
		change(&altered)
		if _, err := openReconciliationCursor(context.Background(), restarted, altered, sealed); err == nil {
			t.Fatal("cursor transplanted across scope")
		}
	}
	token := reconciliationCursorToken(namespace, scope)
	changed := scope
	changed.Generation++
	if token == "" || token == secret || token == reconciliationCursorToken(namespace, changed) {
		t.Fatal("cursor token not opaque and scoped")
	}
	sealed.Wire[len(sealed.Wire)-1] ^= 1
	if _, err := openReconciliationCursor(context.Background(), restarted, scope, sealed); !errors.Is(err, delivery.ErrForbidden) {
		t.Fatal("tampered cursor accepted", err)
	}
}

func TestReconciliationCursorUsesProviderBounds(t *testing.T) {
	for _, value := range []string{"x", strings.Repeat("x", 512)} {
		if !validReconciliationCursor(value) {
			t.Fatal("valid bounded cursor rejected")
		}
	}
	for _, value := range []string{"", " ", strings.Repeat("x", 513), "\x00", "\n", "é"} {
		if validReconciliationCursor(value) {
			t.Fatal("invalid provider cursor accepted")
		}
	}
}

func FuzzReconciliationCursorCustody(f *testing.F) {
	codec, _, _ := custodyFixture(f)
	scope := reconciliationCursorScope{Deployment: "test", Tenant: "tenant", Subject: "user", Effect: "synthetic-effect-0001", Provider: "provider", ProviderVersion: 1, Generation: 1, Step: 1}
	secret := "synthetic-fuzz-cursor"
	scope.Digest = reconciliationCursorDigest([32]byte{9}, scope, secret)
	sealed, err := sealReconciliationCursor(context.Background(), codec, scope, secret, "envelope-a", 1)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{})
	f.Add([]byte("malformed"))
	f.Add(sealed.Wire)
	f.Add(bytes.Repeat([]byte{'x'}, 8193))
	f.Fuzz(func(t *testing.T, wire []byte) {
		candidate := reconciliationCursorEnvelope{KeyID: sealed.KeyID, KeyVersion: sealed.KeyVersion, Wire: wire}
		if err := verifyReconciliationCursor(codec, scope, candidate); err == nil {
			got, err := openReconciliationCursor(context.Background(), codec, scope, candidate)
			if err != nil || got != secret {
				t.Fatal("authenticated cursor changed plaintext", err)
			}
		} else if len(wire) > 8192 && !errors.Is(err, delivery.ErrInvalidInput) {
			t.Fatal("oversized cursor reached parser")
		}
	})
}
