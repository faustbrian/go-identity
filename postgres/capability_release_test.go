package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

func TestCapabilityReleaseAuthorityCannotBeConstructed(t *testing.T) {
	var w CapabilityReleaseWork
	if _, err := w.Binding(nil); err == nil {
		t.Fatal("zero release binding admitted")
	}
	if _, err := w.Exec(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("zero release SQL admitted")
	}
	if rows, err := w.Query(context.Background(), "SELECT 1"); err == nil || rows != nil {
		t.Fatal("zero release rows admitted")
	}
	if _, err := w.DatabaseTime(context.Background()); err == nil {
		t.Fatal("zero release clock admitted")
	}
	var evidence RecoveryWork
	if _, err := evidence.CapabilityBinding(nil); err == nil {
		t.Fatal("zero recovery binding admitted")
	}
	if fmt.Sprintf("%+v", w) != "postgres.CapabilityReleaseWork(redacted)" {
		t.Fatal("release metadata leaked")
	}
	if _, err := json.Marshal(w); err == nil {
		t.Fatal("release authority serialized")
	}
}
