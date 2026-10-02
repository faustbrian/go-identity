//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

func testJournalTerminal(t *testing.T, ctx context.Context, pool *database.Pool) {
	keys := claimKeys{current: 1, retained: map[uint32][32]byte{1: {1}}}
	owner := [16]byte{3}
	q, r := terminalCreation(t)
	s, _ := q.source.CreateUser()
	s.Binding.CommandID = "AAAAAAAAAAAAAAAAAAAADg"
	s.Binding.UserID = "terminal-user"
	c, e := identity.NewUserCreationCommand(s)
	if e != nil {
		t.Fatal("terminal input")
	}
	q, e = prepareClaim(c, [32]byte{1})
	if e != nil {
		t.Fatal("terminal preparation")
	}
	r.Binding = s.Binding
	r.User.ID = s.Binding.UserID
	reserve := func() journalReservation {
		t.Helper()
		tx, e := pool.Raw().Begin(ctx)
		if e != nil {
			t.Fatal("terminal reserve transaction")
		}
		defer tx.Rollback(ctx)
		d, e := lockCommandClaim(ctx, tx, q, keys)
		if e != nil {
			t.Fatal("terminal claim")
		}
		got, e := reserveJournal(ctx, tx, q, d, owner, time.Minute)
		if e != nil {
			t.Fatal("terminal reservation")
		}
		if tx.Commit(ctx) != nil {
			t.Fatal("terminal reserve commit")
		}
		return got
	}
	initial := reserve()
	fence, e := pool.Raw().Begin(ctx)
	if e != nil {
		t.Fatal("terminal fence transaction")
	}
	defer fence.Rollback(ctx)
	stale := initial
	stale.generation++
	if e = terminalizeJournal(ctx, fence, q, stale, owner, r, "committed"); e == nil {
		t.Fatal("foreign generation terminalized")
	}
	if e = terminalizeJournal(ctx, fence, q, initial, [16]byte{4}, r, "committed"); e == nil {
		t.Fatal("foreign owner terminalized")
	}
	if fence.Rollback(ctx) != nil {
		t.Fatal("terminal fence cleanup")
	}
	write := func(commit bool) {
		t.Helper()
		tx, e := pool.Raw().Begin(ctx)
		if e != nil {
			t.Fatal("terminal domain transaction")
		}
		defer tx.Rollback(ctx)
		if _, e = tx.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1)`, string(r.Binding.TenantID), string(r.User.ID)); e != nil {
			t.Fatal("terminal domain insert")
		}
		if e = terminalizeJournal(ctx, tx, q, initial, owner, r, "committed"); e != nil {
			t.Fatal("terminal receipt write")
		}
		if commit && tx.Commit(ctx) != nil {
			t.Fatal("terminal domain commit")
		}
	}
	write(false)
	if reserve().disposition != journalBusy {
		t.Fatal("rollback left terminal result")
	}
	write(true)
	replay := reserve()
	if replay.disposition != journalTerminal || replay.result == nil || replay.result.User != r.User || replay.result.AuditEventID != r.AuditEventID {
		t.Fatal("committed result not replayed")
	}
	if _, e = pool.Raw().Exec(ctx, `UPDATE identity.users SET status='banned',version=2 WHERE tenant_id=$1 AND user_id=$2`, string(r.Binding.TenantID), string(r.User.ID)); e != nil {
		t.Fatal("historical projection update")
	}
	if reserve().result.User != r.User {
		t.Fatal("current authority replaced immutable receipt")
	}
	tx, e := pool.Raw().Begin(ctx)
	if e != nil {
		t.Fatal("terminal rewrite transaction")
	}
	defer tx.Rollback(ctx)
	if e = terminalizeJournal(ctx, tx, q, initial, owner, r, "committed"); e == nil {
		t.Fatal("terminal row rewritten")
	}
	if tx.Rollback(ctx) != nil {
		t.Fatal("terminal rewrite cleanup")
	}
	// Abort stores no fabricated user/audit success and stays terminal on retry.
	s.Binding.CommandID = "AAAAAAAAAAAAAAAAAAAADw"
	c, e = identity.NewUserCreationCommand(s)
	if e != nil {
		t.Fatal("abort input")
	}
	q, e = prepareClaim(c, [32]byte{1})
	if e != nil {
		t.Fatal("abort preparation")
	}
	initial = reserve()
	r = identity.CommandResult{Binding: s.Binding, Outcome: identity.CommitOutcomeNotCommitted}
	tx, e = pool.Raw().Begin(ctx)
	if e != nil {
		t.Fatal("abort transaction")
	}
	defer tx.Rollback(ctx)
	if e = terminalizeJournal(ctx, tx, q, initial, owner, r, "dependency-failure"); e != nil {
		t.Fatal("abort receipt")
	}
	if tx.Commit(ctx) != nil {
		t.Fatal("abort commit")
	}
	replay = reserve()
	if replay.disposition != journalTerminal || replay.result == nil || replay.result.Outcome != identity.CommitOutcomeNotCommitted || replay.result.User != (identity.User{}) {
		t.Fatal("abort replay fabricated result")
	}
	s.Binding.CommandID = "AAAAAAAAAAAAAAAAAAAAEA"
	c, e = identity.NewUserCreationCommand(s)
	if e != nil {
		t.Fatal("expired terminal input")
	}
	q, e = prepareClaim(c, [32]byte{1})
	if e != nil {
		t.Fatal("expired terminal preparation")
	}
	initial = reserve()
	r = identity.CommandResult{Binding: s.Binding, Outcome: identity.CommitOutcomeNotCommitted}
	if _, e = pool.Raw().Exec(ctx, `UPDATE identity.commands SET created_at=clock_timestamp()-interval '3 seconds',heartbeat_at=clock_timestamp()-interval '2 seconds',updated_at=clock_timestamp()-interval '2 seconds',lease_until=clock_timestamp()-interval '1 second' WHERE command_id=decode('00000000000000000000000000000010','hex')`); e != nil {
		t.Fatal("expired terminal fixture")
	}
	expired, e := pool.Raw().Begin(ctx)
	if e != nil {
		t.Fatal("expired terminal transaction")
	}
	defer expired.Rollback(ctx)
	if e = terminalizeJournal(ctx, expired, q, initial, owner, r, "dependency-failure"); e == nil {
		t.Fatal("expired owner terminalized")
	}
}
