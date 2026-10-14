//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	database "github.com/faustbrian/go-postgres"
)

func testJournalLeases(t *testing.T, ctx context.Context, pool *database.Pool) {
	keys := claimKeys{current: 1, retained: map[uint32][32]byte{1: {1}}}
	q := claimRequest{commandID: "AAAAAAAAAAAAAAAAAAAACA", tenant: "tenant-a", purpose: "identity.user.create", canonical: []byte{0xa0}, safeFields: []byte{0xa0}}
	owner := [16]byte{1}
	reserve := func(who [16]byte, commit bool) journalReservation {
		t.Helper()
		tx, e := pool.Raw().Begin(ctx)
		if e != nil {
			t.Fatal("journal transaction")
		}
		defer tx.Rollback(ctx)
		d, e := lockCommandClaim(ctx, tx, q, keys)
		if e != nil {
			t.Fatal("journal claim")
		}
		r, e := reserveJournal(ctx, tx, q, d, who, time.Minute)
		if e != nil {
			t.Fatal("journal reservation")
		}
		if commit && tx.Commit(ctx) != nil {
			t.Fatal("journal commit")
		}
		return r
	}
	first := reserve(owner, false)
	if first.disposition != journalOwned || first.generation != 1 || first.attempt != 1 {
		t.Fatal("initial ownership")
	}
	first = reserve(owner, true)
	if first.generation != 1 {
		t.Fatal("rollback retained ownership")
	}
	busy := reserve([16]byte{2}, true)
	if busy.disposition != journalBusy || busy.retryAfter <= 0 || busy.retryAfter > time.Minute {
		t.Fatal("live lease permitted work")
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
	// Heartbeat is generation-bound and never resurrects an expired lease.
	tx, e := pool.Raw().Begin(ctx)
	if e != nil {
		t.Fatal("heartbeat transaction")
	}
	defer tx.Rollback(ctx)
	if e = heartbeatJournal(ctx, tx, q, first, owner, time.Minute); e != nil {
		t.Fatal("live heartbeat")
	}
	if e = heartbeatJournal(ctx, tx, q, first, [16]byte{2}, time.Minute); e == nil {
		t.Fatal("foreign heartbeat")
	}
	if tx.Commit(ctx) != nil {
		t.Fatal("heartbeat commit")
	}
	if _, e = pool.Raw().Exec(ctx, `UPDATE identity.commands SET created_at=clock_timestamp()-interval '3 seconds',heartbeat_at=clock_timestamp()-interval '2 seconds',updated_at=clock_timestamp()-interval '2 seconds',lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); e != nil {
		t.Fatal("expire lease")
	}
	expired, e := pool.Raw().Begin(ctx)
	if e != nil {
		t.Fatal("expired heartbeat transaction")
	}
	defer expired.Rollback(ctx)
	if e = heartbeatJournal(ctx, expired, q, first, owner, time.Minute); e == nil {
		t.Fatal("expired owner resurrected lease")
	}
	if expired.Rollback(ctx) != nil {
		t.Fatal("expired heartbeat cleanup")
	}
	takeover := reserve([16]byte{2}, false)
	if takeover.disposition != journalOwned || takeover.previousGeneration != 1 || takeover.generation != 2 || takeover.attempt != 2 {
		t.Fatal("takeover did not fence prior generation")
	}
	// A failed participant rebind can roll back the whole takeover.
	takeover = reserve([16]byte{2}, true)
	if takeover.generation != 2 || takeover.previousGeneration != 1 {
		t.Fatal("rolled-back takeover survived")
	}
	tx, e = pool.Raw().Begin(ctx)
	if e != nil {
		t.Fatal("stale heartbeat transaction")
	}
	defer tx.Rollback(ctx)
	if e = heartbeatJournal(ctx, tx, q, first, owner, time.Minute); e == nil {
		t.Fatal("stale generation heartbeat")
	}
	if e = heartbeatJournal(ctx, tx, q, takeover, [16]byte{2}, time.Minute); e != nil {
		t.Fatal("takeover heartbeat")
	}
	if tx.Commit(ctx) != nil {
		t.Fatal("takeover heartbeat commit")
	}
	// Foundation-only rows have no provable ownership; never invent it.
	legacy := q
	legacy.commandID = "AAAAAAAAAAAAAAAAAAAACQ"
	tx, e = pool.Raw().Begin(ctx)
	if e != nil {
		t.Fatal("legacy transaction")
	}
	defer tx.Rollback(ctx)
	if d, e := lockCommandClaim(ctx, tx, legacy, keys); e != nil || d != claimNew {
		t.Fatal("legacy claim")
	}
	lid, _ := base64.RawURLEncoding.DecodeString(string(legacy.commandID))
	if _, e = tx.Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,$3)`, lid, string(legacy.tenant), legacy.purpose); e != nil {
		t.Fatal("legacy row")
	}
	if _, e = reserveJournal(ctx, tx, legacy, claimReplay, owner, time.Minute); e == nil {
		t.Fatal("legacy absence fabricated ownership")
	}
	if _, e = tx.Exec(ctx, `UPDATE identity.commands SET state='unknown' WHERE command_id=$1`, id); e == nil {
		t.Fatal("unknown observation persisted as state")
	}
}
