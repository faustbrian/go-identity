package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

func TestRiskReleaseZeroAndRedaction(t *testing.T) {
	var w RiskReleaseWork
	if _, err := w.Binding(nil); err == nil {
		t.Fatal("zero release binding")
	}
	if _, err := w.Exec(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("zero release SQL")
	}
	if _, err := w.Query(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("zero release query")
	}
	if _, err := w.DatabaseTime(context.Background()); err == nil {
		t.Fatal("zero release clock")
	}
	if _, err := json.Marshal(w); err == nil {
		t.Fatal("release serialized")
	}
	if _, err := w.MarshalText(); err == nil {
		t.Fatal("release serialized as text")
	}
	if fmt.Sprint(w) != "postgres.RiskReleaseWork(redacted)" {
		t.Fatal("release diagnostics")
	}
	if _, err := (RecoveryWork{}).RiskBinding(nil); err == nil {
		t.Fatal("zero recovery binding")
	}
}
