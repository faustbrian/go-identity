package postgres

import (
	"context"
	"testing"
	"time"
)

func TestJournalInvalidInputs(t *testing.T) {
	q := claimRequest{commandID: "AAAAAAAAAAAAAAAAAAAAAQ", tenant: "tenant-a", purpose: "identity.user.create"}
	if _, e := reserveJournal(nil, nil, q, claimNew, [16]byte{1}, time.Minute); e == nil {
		t.Fatal("nil journal admitted")
	}
	if e := heartbeatJournal(context.Background(), nil, q, journalReservation{}, [16]byte{1}, time.Minute); e == nil {
		t.Fatal("nil heartbeat admitted")
	}
}
