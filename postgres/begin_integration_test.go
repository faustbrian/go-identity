//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

func testBeginJournal(t *testing.T, ctx context.Context, pool *database.Pool) {
	keys := claimKeys{current: 1, retained: map[uint32][32]byte{1: {1}}}
	q := claimRequest{commandID: "AAAAAAAAAAAAAAAAAAAARA", tenant: "tenant-a", purpose: "identity.user.create", canonical: []byte{0xa0}, safeFields: []byte{0xa0}}
	owner := [16]byte{4}
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal("begin reservation transaction")
	}
	defer tx.Rollback(ctx)
	d, err := lockCommandClaim(ctx, tx, q, keys)
	if err != nil {
		t.Fatal(err)
	}
	r, err := reserveJournal(ctx, tx, q, d, owner, time.Minute)
	if err != nil || tx.Commit(ctx) != nil {
		t.Fatal("begin reservation")
	}
	for _, test := range []struct {
		name        string
		request     claimRequest
		reservation journalReservation
		who         [16]byte
		denied      bool
	}{
		{"live", q, r, owner, false},
		{"foreign", q, r, [16]byte{5}, true},
		{"stale", q, journalReservation{disposition: journalOwned, generation: 2}, owner, true},
		{"changed intent", claimRequest{commandID: q.commandID, tenant: q.tenant, purpose: q.purpose, canonical: []byte{0xa1}, safeFields: q.safeFields}, r, owner, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			domain, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal("domain transaction")
			}
			defer domain.Rollback(ctx)
			fence, err := beginJournal(ctx, domain, test.request, keys, test.reservation, test.who)
			if test.denied {
				var conflict identity.ConflictError
				if !errors.As(err, &conflict) || fence != (journalWorkFence{}) {
					t.Fatalf("unsafe begin admitted: %v", err)
				}
				return
			}
			if err != nil || fence.generation != 1 || !fence.until.After(fence.now) || !postgresExactTime(fence.now) || fence.now.Location() != time.UTC {
				t.Fatalf("live begin failed: %v", err)
			}
			if _, err = domain.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','begin-owned','active',1)`); err != nil {
				t.Fatal("same transaction write")
			}
			if domain.Rollback(ctx) != nil {
				t.Fatal("begin rollback")
			}
			var exists bool
			if pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity.users WHERE user_id='begin-owned')`).Scan(&exists) != nil || exists {
				t.Fatal("domain rollback lost ownership")
			}
		})
	}
	t.Run("retained key", func(t *testing.T) {
		domain, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer domain.Rollback(ctx)
		rotated := claimKeys{current: 2, retained: map[uint32][32]byte{1: {1}, 2: {2}}}
		if _, err := beginJournal(ctx, domain, q, rotated, r, owner); err != nil {
			t.Fatal("rotation changed begin authority")
		}
	})
	t.Run("missing retained key", func(t *testing.T) {
		domain, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer domain.Rollback(ctx)
		rotated := claimKeys{current: 2, retained: map[uint32][32]byte{2: {2}}}
		_, err = beginJournal(ctx, domain, q, rotated, r, owner)
		var unavailable identity.UnavailableError
		if !errors.As(err, &unavailable) {
			t.Fatal("missing key fabricated begin authority")
		}
	})
	t.Run("missing reservation rollback", func(t *testing.T) {
		missing := q
		missing.commandID = "AAAAAAAAAAAAAAAAAAAARQ"
		domain, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer domain.Rollback(ctx)
		_, err = beginJournal(ctx, domain, missing, keys, r, owner)
		var unavailable identity.UnavailableError
		if !errors.As(err, &unavailable) {
			t.Fatal("missing reservation repaired")
		}
		if domain.Rollback(ctx) != nil {
			t.Fatal("failed begin rollback")
		}
		mid, _ := base64.RawURLEncoding.DecodeString(string(missing.commandID))
		var exists bool
		if pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity.identity_command_id_claims WHERE command_id=$1)`, mid).Scan(&exists) != nil || exists {
			t.Fatal("failed begin left new authority")
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		domain, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer domain.Rollback(ctx)
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		fence, err := beginJournal(cancelled, domain, q, keys, r, owner)
		var stopped identity.CancelledError
		if !errors.As(err, &stopped) || fence != (journalWorkFence{}) {
			t.Fatal("cancelled begin admitted")
		}
	})
	id, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
	t.Run("expired after lock wait", func(t *testing.T) {
		blocker, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Rollback(ctx)
		if _, err = lockCommandClaim(ctx, blocker, q, keys); err != nil {
			t.Fatal(err)
		}
		if _, err = blocker.Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()+interval '150 milliseconds' WHERE command_id=$1`, id); err != nil {
			t.Fatal("bound test lease")
		}
		domain, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		pid := domain.Conn().PgConn().PID()
		done := make(chan error, 1)
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			defer domain.Rollback(ctx)
			_, err := beginJournal(ctx, domain, q, keys, r, owner)
			done <- err
		}()
		defer func() {
			blocker.Rollback(ctx)
			select {
			case <-finished:
			case <-ctx.Done():
				t.Error("begin contender did not stop")
			}
		}()
		var waiting bool
		for !waiting && ctx.Err() == nil {
			if _, err = blocker.Exec(ctx, `SELECT pg_stat_clear_snapshot()`); err != nil {
				t.Fatal("refresh lock observation")
			}
			if blocker.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')`, pid).Scan(&waiting) != nil {
				t.Fatal("observe bounded lock wait")
			}
		}
		if !waiting {
			t.Fatal("contender not waiting")
		}
		if _, err = blocker.Exec(ctx, `SELECT pg_sleep(0.2)`); err != nil {
			t.Fatal("test clock wait")
		}
		if blocker.Commit(ctx) != nil {
			t.Fatal("release test lock")
		}
		select {
		case err := <-done:
			var conflict identity.ConflictError
			if !errors.As(err, &conflict) {
				t.Fatalf("expired lock wait admitted work: %v", err)
			}
		case <-ctx.Done():
			t.Fatal("bounded contender timeout")
		}
	})
	t.Run("terminal", func(t *testing.T) {
		domain, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer domain.Rollback(ctx)
		// Even a terminal row with an unreadable receipt must never be apply
		// authority. Recovery owns receipt validation, not Begin.
		if _, err := domain.Exec(ctx, `WITH instant AS (SELECT clock_timestamp() AS now)
UPDATE identity.commands SET state='committed',result_version=1,terminal_class='committed',result=$2,
terminal_at=instant.now,updated_at=instant.now,lease_until=instant.now+interval '1 minute'
FROM instant WHERE command_id=$1`, id, []byte{1}); err != nil {
			t.Fatal("terminal test state")
		}
		_, err = beginJournal(ctx, domain, q, keys, r, owner)
		var conflict identity.ConflictError
		if !errors.As(err, &conflict) {
			t.Fatal("terminal row reentered domain work")
		}
	})
}
