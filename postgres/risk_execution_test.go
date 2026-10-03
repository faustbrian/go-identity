package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestRiskDomainWorkRejectsZero(t *testing.T) {
	p := &riskReservationProbe{}
	read := RiskApplyWork{}
	if _, e := read.Binding(p); e == nil {
		t.Fatal("zero exposed binding")
	}
	if _, e := read.NativeCommand(p); e == nil {
		t.Fatal("zero exposed command")
	}
	if _, e := read.Query(context.Background(), "SELECT 1"); e == nil {
		t.Fatal("zero allowed read")
	}
	if _, e := read.DatabaseTime(context.Background()); e == nil {
		t.Fatal("zero refreshed time")
	}
	write := RiskFinalizeWork{}
	if _, e := write.Binding(p); e == nil {
		t.Fatal("zero exposed finalize binding")
	}
	if _, e := write.NativeCommand(p); e == nil {
		t.Fatal("zero exposed finalize command")
	}
	if _, e := write.Query(context.Background(), "SELECT 1"); e == nil {
		t.Fatal("zero allowed finalize read")
	}
	if _, e := write.Exec(context.Background(), "SELECT 1"); e == nil {
		t.Fatal("zero allowed finalize mutation")
	}
	if _, e := write.DatabaseTime(context.Background()); e == nil {
		t.Fatal("zero refreshed finalize time")
	}
	for _, value := range []any{read, write} {
		if _, e := json.Marshal(value); e == nil {
			t.Fatal("serialized authority")
		}
		if !strings.Contains(fmt.Sprintf("%+v", value), "redacted") {
			t.Fatal("exposed custody")
		}
	}
}
