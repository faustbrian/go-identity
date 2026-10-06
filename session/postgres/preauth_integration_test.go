//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// This test-only adapter preserves borrowed pgx transaction ownership while
// matching the existing coordinator's affected-row write contract.
type preAuthTestTx struct{ pgx.Tx }

func (q preAuthTestTx) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	result, err := q.Tx.Exec(ctx, sql, args...)
	return result.RowsAffected(), err
}

func testNativePreAuth(t *testing.T, ctx context.Context, pool *database.Pool) {
	config := Config{Schema: "session_store", MaximumDuration: time.Second}
	begin := func(t *testing.T) preAuthTestTx {
		t.Helper()
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			_ = tx.Rollback(cleanup)
		})
		return preAuthTestTx{tx}
	}
	fixture := func(t *testing.T, issued time.Time) (session.PreAuthTransaction, PreAuthUse) {
		t.Helper()
		r := testPreAuth(t, issued)
		s, _ := r.Bindings()
		id, err := identity.NewPreAuthTransactionID()
		if err != nil {
			t.Fatal(err)
		}
		s.Binding.ID = id
		// Random safe ID also supplies unique non-bearer fixture index bytes.
		copy(s.Cookie.Sum[:], []byte(id))
		r, err = session.NewPreAuthTransaction(s)
		if err != nil {
			t.Fatal(err)
		}
		b := revokeBinding()
		b.OperationID = s.Binding.Intent.Action
		b.PolicyID = s.Binding.Intent.PolicyID
		b.PolicyVersion = s.Binding.Intent.PolicyVersion
		return r, PreAuthUse{Command: b, Fingerprint: [32]byte{7}, Generation: 1}
	}
	insert := func(t *testing.T, r session.PreAuthTransaction) {
		t.Helper()
		q := begin(t)
		if err := InsertPreAuth(ctx, q, config, r); err != nil {
			t.Fatal("flow insert", err)
		}
		if err := q.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	denied := func(t *testing.T, err error) {
		t.Helper()
		var forbidden identity.ForbiddenError
		if !errors.As(err, &forbidden) {
			t.Fatal("expected uniform denial", err)
		}
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE session_store.preauth_effects(flow_id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	t.Run("exact original and rollback", func(t *testing.T) {
		begin := func() preAuthTestTx { return begin(t) }
		fixture := func(at time.Time) (session.PreAuthTransaction, PreAuthUse) { return fixture(t, at) }
		insert := func(r session.PreAuthTransaction) { insert(t, r) }
		denied := func(err error) { denied(t, err) }
		r, use := fixture(time.Now().UTC())
		insert(r)
		q := begin()
		if err := RequirePreAuth(ctx, q, config, r); err != nil {
			t.Fatal(err)
		}
		denied(InsertPreAuth(ctx, q, config, r))
		s, _ := r.Bindings()
		for _, change := range []func(*session.PreAuthTransactionSpec){
			func(s *session.PreAuthTransactionSpec) { s.Binding.Intent.TenantID = "tenant-b" },
			func(s *session.PreAuthTransactionSpec) { s.Binding.Intent.Origin = "https://other.test" },
			func(s *session.PreAuthTransactionSpec) { s.Binding.Intent.PolicyVersion-- },
			func(s *session.PreAuthTransactionSpec) { s.Binding.Intent.Nonce[0]++ },
			func(s *session.PreAuthTransactionSpec) { s.Cookie.KeyVersion-- },
			func(s *session.PreAuthTransactionSpec) { s.Version++ },
		} {
			changed := s
			change(&changed)
			other, err := session.NewPreAuthTransaction(changed)
			if err != nil {
				t.Fatal(err)
			}
			denied(RequirePreAuth(ctx, q, config, other))
		}
		if err := ReservePreAuth(ctx, q, config, r, use); err != nil {
			t.Fatal(err)
		}
		if err := q.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		after := begin()
		if err := RequirePreAuth(ctx, after, config, r); err != nil {
			t.Fatal("rollback consumed flow", err)
		}
	})
	t.Run("same commit and exact terminal custody", func(t *testing.T) {
		begin := func() preAuthTestTx { return begin(t) }
		fixture := func(at time.Time) (session.PreAuthTransaction, PreAuthUse) { return fixture(t, at) }
		insert := func(r session.PreAuthTransaction) { insert(t, r) }
		denied := func(err error) { denied(t, err) }
		r, use := fixture(time.Now().UTC())
		insert(r)
		q := begin()
		if err := ReservePreAuth(ctx, q, config, r, use); err != nil {
			t.Fatal(err)
		}
		if err := q.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		q = begin()
		denied(RequirePreAuth(ctx, q, config, r))
		denied(ReservePreAuth(ctx, q, config, r, use))
		for _, change := range []func(*PreAuthUse){
			func(u *PreAuthUse) { u.Fingerprint[0]++ },
			func(u *PreAuthUse) { u.Generation++ },
			func(u *PreAuthUse) { u.Command.CommandID = "AgICAgICAgICAgICAgICAg" },
		} {
			other := use
			change(&other)
			denied(FinalizePreAuth(ctx, q, config, r, other))
		}
		if err := FinalizePreAuth(ctx, q, config, r, use); err != nil {
			t.Fatal(err)
		}
		s, _ := r.Bindings()
		if _, err := q.Exec(ctx, `INSERT INTO session_store.preauth_effects VALUES($1)`, string(s.Binding.ID)); err != nil {
			t.Fatal(err)
		}
		if err := q.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		q = begin()
		if err := FinalizePreAuth(ctx, q, config, r, use); err != nil {
			t.Fatal("rollback terminalized flow", err)
		}
		if _, err := q.Exec(ctx, `INSERT INTO session_store.preauth_effects VALUES($1)`, string(s.Binding.ID)); err != nil {
			t.Fatal(err)
		}
		if err := q.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		q = begin()
		denied(FinalizePreAuth(ctx, q, config, r, use))
		denied(InsertPreAuth(ctx, q, config, r))
		var state, version string
		var effects int
		if err := q.QueryRow(ctx, `SELECT state,version::text,(SELECT count(*) FROM session_store.preauth_effects WHERE flow_id=$1) FROM session_store.preauth_transactions WHERE flow_id=$1`, string(s.Binding.ID)).Scan(&state, &version, &effects); err != nil || state != "consumed" || version != "3" || effects != 1 {
			t.Fatal("effects not atomic", err)
		}
	})
	t.Run("one reservation winner", func(t *testing.T) {
		begin := func() preAuthTestTx { return begin(t) }
		fixture := func(at time.Time) (session.PreAuthTransaction, PreAuthUse) { return fixture(t, at) }
		insert := func(r session.PreAuthTransaction) { insert(t, r) }
		denied := func(err error) { denied(t, err) }
		r, use := fixture(time.Now().UTC())
		insert(r)
		first := begin()
		second := begin()
		if err := ReservePreAuth(ctx, first, config, r, use); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { result <- ReservePreAuth(ctx, second, config, r, use) }()
		commitErr := first.Commit(ctx)
		loserErr := <-result
		if commitErr != nil {
			t.Fatal(commitErr)
		}
		denied(loserErr)
	})
	t.Run("database time after lock wait", func(t *testing.T) {
		begin := func() preAuthTestTx { return begin(t) }
		fixture := func(at time.Time) (session.PreAuthTransaction, PreAuthUse) { return fixture(t, at) }
		insert := func(r session.PreAuthTransaction) { insert(t, r) }
		denied := func(err error) { denied(t, err) }
		r, use := fixture(time.Now().UTC().Add(-5*time.Minute + 200*time.Millisecond))
		insert(r)
		locked := begin()
		waiter := begin()
		s, _ := r.Bindings()
		if _, err := locked.Exec(ctx, `UPDATE session_store.preauth_transactions SET version=version WHERE flow_id=$1`, string(s.Binding.ID)); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { result <- ReservePreAuth(ctx, waiter, config, r, use) }()
		// Let primary server time cross the stored exclusive deadline while the
		// row is held. A timestamp sampled before locking would wrongly admit.
		if _, err := locked.Exec(ctx, `SELECT pg_sleep(0.25)`); err != nil {
			t.Fatal(err)
		}
		if err := locked.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		denied(<-result)
	})
}
