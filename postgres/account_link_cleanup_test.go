package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

func TestZeroAccountLinkCleanupHandleCannotExposeCustodyOrExecute(t *testing.T) {
	var work AccountLinkCleanupWork
	if _, _, err := work.Scope(nil); err == nil {
		t.Fatal("zero cleanup handle exposed original custody")
	}
	if _, err := work.Exec(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("zero cleanup handle executed SQL")
	}
	if _, err := json.Marshal(work); err == nil {
		t.Fatal("terminal cleanup authority was serializable")
	}
	if _, err := work.MarshalText(); err == nil {
		t.Fatal("terminal cleanup authority was text serializable")
	}
	if got := fmt.Sprintf("%+v", work); got != "postgres.AccountLinkCleanupWork(redacted)" {
		t.Fatal("cleanup formatting exposed internal custody")
	}
}
