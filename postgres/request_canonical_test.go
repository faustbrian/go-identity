package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestCanonicalRequestKeyOwnsBoundedRedactedSelector(t *testing.T) {
	raw := []byte("delete/user-original/version-original")
	key, err := NewCanonicalRequestKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	first, err := key.digest([32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 1
	again, err := key.digest([32]byte{1})
	if err != nil || first != again {
		t.Fatal("caller mutation changed canonical correlation")
	}
	other, err := key.digest([32]byte{2})
	if err != nil || other == first {
		t.Fatal("canonical lookup did not bind authority key")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
		if strings.Contains(fmt.Sprintf(format, key), "user-original") {
			t.Fatal("canonical selector leaked through diagnostics")
		}
	}
	if _, err := json.Marshal(key); err == nil {
		t.Fatal("canonical selector allowed implicit persistence")
	}
	for _, raw := range [][]byte{nil, {}, bytes.Repeat([]byte{'a'}, 65537)} {
		if _, err := NewCanonicalRequestKey(raw); err == nil {
			t.Fatal("invalid canonical selector admitted")
		}
	}
	if _, err := key.digest([32]byte{}); err == nil {
		t.Fatal("zero authority key admitted")
	}
	if _, err := (CanonicalRequestKey{}).digest([32]byte{1}); err == nil {
		t.Fatal("zero canonical key admitted")
	}
}

func TestCanonicalRequestMigrationPreservesExistingHistory(t *testing.T) {
	base := RequestKeyPreparationMigrationSource{Base: RequestKeyMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}
	original, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	source := CanonicalRequestMigrationSource{Base: base, Version: 12}
	history, err := source.Load(context.Background())
	if err != nil || len(history) != len(original)+1 || history[len(original)].DownSQL() != "" {
		t.Fatal("canonical forward migration invalid", err)
	}
	for index := range original {
		if history[index] != original[index] {
			t.Fatal("existing installed history changed")
		}
	}
	for _, bad := range []CanonicalRequestMigrationSource{{}, {Base: base, Version: migrations.Version(11)}} {
		if history, err := bad.Load(context.Background()); err == nil || history != nil {
			t.Fatal("invalid canonical migration returned history")
		}
	}
	if history, err := source.Load(nil); err == nil || history != nil {
		t.Fatal("nil context returned migration")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if history, err := source.Load(ctx); err != context.Canceled || history != nil {
		t.Fatal("cancelled migration returned history")
	}
}
