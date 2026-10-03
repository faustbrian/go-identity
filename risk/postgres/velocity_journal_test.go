package postgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/risk"
)

func TestVelocityJournalRejectsZeroBeforeIO(t *testing.T) {
	if _, err := NewVelocityJournal(VelocityJournalConfig{}); err == nil {
		t.Fatal("zero configuration admitted")
	}
	var journal VelocityJournal
	if _, err := journal.RecordAttempt(context.Background(), risk.CounterCommand{}); err == nil {
		t.Fatal("zero journal admitted")
	}
	if err := journal.RecordResult(context.Background(), VelocityAttempt{}, risk.CounterUnknown, nil); err == nil {
		t.Fatal("zero receipt admitted")
	}
}
