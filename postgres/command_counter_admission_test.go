package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestCommandCounterAdmissionWorkRejectsZero(t *testing.T) {
	w := CommandCounterAdmissionWork{}
	if _, e := w.Binding(&commandCounterProbe{}); e == nil {
		t.Fatal("zero admitted command scope")
	}
	if _, e := w.NativeCommand(&commandCounterProbe{}); e == nil {
		t.Fatal("zero exposed native input")
	}
	if _, e := w.Query(context.Background(), "SELECT 1"); e == nil {
		t.Fatal("zero admitted SQL")
	}
	if _, e := w.DatabaseTime(context.Background()); e == nil {
		t.Fatal("zero refreshed time")
	}
	if _, e := json.Marshal(w); e == nil {
		t.Fatal("serialized admission authority")
	}
	if !strings.Contains(fmt.Sprintf("%+v", w), "redacted") {
		t.Fatal("unredacted admission authority")
	}
}
