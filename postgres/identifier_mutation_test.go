package postgres

import (
	"context"
	"fmt"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestIdentifierMutationPolicyAndReuseDomain(t *testing.T) {
	p := identifierMutationPolicy{currentKeyVersion: 1, keys: map[uint32][32]byte{1: {1}}, reuseCooldown: time.Hour}
	if !p.valid() {
		t.Fatal("valid policy")
	}
	for _, bad := range []identifierMutationPolicy{{}, {currentKeyVersion: 2, keys: p.keys}, {currentKeyVersion: 1, keys: map[uint32][32]byte{1: {}}}, {currentKeyVersion: 1, keys: p.keys, reuseCooldown: -1}, {currentKeyVersion: 1, keys: p.keys, reuseCooldown: time.Nanosecond}, {currentKeyVersion: 1, keys: p.keys, reuseCooldown: 366 * 24 * time.Hour}} {
		if bad.valid() {
			t.Fatal("invalid policy")
		}
	}
	digest := identifierReuseDigest([32]byte{1}, "tenant", identity.IdentifierEmail, "synthetic@example.test")
	for _, other := range [][32]byte{identifierReuseDigest([32]byte{2}, "tenant", identity.IdentifierEmail, "synthetic@example.test"), identifierReuseDigest([32]byte{1}, "other", identity.IdentifierEmail, "synthetic@example.test"), identifierReuseDigest([32]byte{1}, "tenant", identity.IdentifierUsername, "synthetic@example.test"), identifierReuseDigest([32]byte{1}, "tenant", identity.IdentifierEmail, "other@example.test")} {
		if digest == other {
			t.Fatal("reuse scope/key/value collision")
		}
	}
	if fmt.Sprintf("%#v", p) != "postgres.identifierMutationPolicy(redacted)" {
		t.Fatal("key disclosed")
	}
}

func TestIdentifierMutationMigrationPreservesHistory(t *testing.T) {
	history, err := (MigrationSource{}).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, err := (IdentifierMutationMigrationSource{Base: MigrationSource{}, Version: 10}).Load(context.Background())
	if err != nil || len(got) != len(history)+1 {
		t.Fatal(err)
	}
	for i, m := range history {
		if m.Checksum() != got[i].Checksum() {
			t.Fatal("historical bytes changed")
		}
	}
	for _, bad := range []IdentifierMutationMigrationSource{{}, {Base: MigrationSource{}, Version: 9}} {
		if rows, err := bad.Load(context.Background()); err == nil || rows != nil {
			t.Fatal("invalid version/source")
		}
	}
	if _, err := (IdentifierMutationMigrationSource{Base: MigrationSource{}, Version: 10}).Load(nil); err == nil {
		t.Fatal("nil context")
	}
	// Native storage remains inaccessible through a zero Work/repository.
	if _, err := (*Repository)(nil).applyIdentifierMutation(context.Background(), Work{}, identity.Command{}, identifierMutationPolicy{}); err == nil {
		t.Fatal("zero storage authority")
	}
}
