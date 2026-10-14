//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"strconv"
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
	t.Run("reserved owner transfer preserves original flow", func(t *testing.T) {
		begin := func() preAuthTestTx { return begin(t) }
		fixture := func(at time.Time) (session.PreAuthTransaction, PreAuthUse) { return fixture(t, at) }
		insert := func(r session.PreAuthTransaction) { insert(t, r) }
		denied := func(err error) { denied(t, err) }
		r, first := fixture(time.Now().UTC())
		insert(r)
		s, _ := r.Bindings()
		q := begin()
		loaded, err := ReadPreAuth(ctx, q, config, s.Binding.Intent.TenantID, s.Binding.ID)
		want, _ := encodePreAuth(r)
		got, _ := encodePreAuth(loaded)
		if err != nil || !bytes.Equal(want, got) {
			t.Fatal("primary flow changed", err)
		}
		if _, err = ReadPreAuth(ctx, q, config, "tenant-b", s.Binding.ID); err == nil {
			t.Fatal("foreign flow loaded")
		}
		if err = ReservePreAuth(ctx, q, config, r, first); err != nil {
			t.Fatal(err)
		}
		if err = q.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		q = begin()
		if err = RequireReservedPreAuth(ctx, q, config, r, first); err != nil {
			t.Fatal("owner denied", err)
		}
		var invalid identity.InvalidInputError
		for _, next := range []uint64{0, 1, 3, ^uint64(0)} {
			if err = RebindPreAuth(ctx, q, config, r, first, next); !errors.As(err, &invalid) {
				t.Fatal("skipped generation accepted", err)
			}
		}
		changed := first
		changed.Fingerprint[0]++
		denied(RebindPreAuth(ctx, q, config, r, changed, 2))
		if err = RebindPreAuth(ctx, q, config, r, first, 2); err != nil {
			t.Fatal(err)
		}
		second := first
		second.Generation = 2
		denied(RequireReservedPreAuth(ctx, q, config, r, first))
		if err = RequireReservedPreAuth(ctx, q, config, r, second); err != nil {
			t.Fatal(err)
		}
		if err = q.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		q = begin()
		if err = RequireReservedPreAuth(ctx, q, config, r, first); err != nil {
			t.Fatal("rollback transferred ownership", err)
		}
		if err = RebindPreAuth(ctx, q, config, r, first, 2); err != nil {
			t.Fatal(err)
		}
		if err = q.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		q = begin()
		loaded, err = ReadPreAuth(ctx, q, config, s.Binding.Intent.TenantID, s.Binding.ID)
		got, _ = encodePreAuth(loaded)
		if err != nil || !bytes.Equal(want, got) {
			t.Fatal("takeover renewed original state", err)
		}
		denied(RebindPreAuth(ctx, q, config, r, first, 2))
		denied(FinalizePreAuth(ctx, q, config, r, first))
		if err = FinalizePreAuth(ctx, q, config, r, second); err != nil {
			t.Fatal("successor cannot finalize", err)
		}
		denied(RebindPreAuth(ctx, q, config, r, second, 3))
	})
	t.Run("reserved read locks exclude takeover", func(t *testing.T) {
		begin := func() preAuthTestTx { return begin(t) }
		fixture := func(at time.Time) (session.PreAuthTransaction, PreAuthUse) { return fixture(t, at) }
		insert := func(r session.PreAuthTransaction) { insert(t, r) }
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
		if err := RequireReservedPreAuth(ctx, q, config, r, use); err != nil {
			t.Fatal(err)
		}
		writer := begin()
		bounded, stop := context.WithTimeout(ctx, 100*time.Millisecond)
		err := RebindPreAuth(bounded, writer, config, r, use, 2)
		stop()
		var deadline identity.DeadlineExceededError
		if !errors.As(err, &deadline) {
			t.Fatal("share lock absent", err)
		}
		_ = writer.Rollback(ctx)
		if err = q.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("primary load denies indexed drift", func(t *testing.T) {
		begin := func() preAuthTestTx { return begin(t) }
		fixture := func(at time.Time) (session.PreAuthTransaction, PreAuthUse) { return fixture(t, at) }
		insert := func(r session.PreAuthTransaction) { insert(t, r) }
		r, _ := fixture(time.Now().UTC())
		insert(r)
		s, _ := r.Bindings()
		q := begin()
		if _, err := q.Exec(ctx, `UPDATE session_store.preauth_transactions SET digest_version=digest_version-1 WHERE flow_id=$1`, string(s.Binding.ID)); err != nil {
			t.Fatal(err)
		}
		var unavailable identity.UnavailableError
		if _, err := ReadPreAuth(ctx, q, config, s.Binding.Intent.TenantID, s.Binding.ID); !errors.As(err, &unavailable) {
			t.Fatal("indexed drift admitted", err)
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
	t.Run("proven noncommit release is terminal even after expiry", func(t *testing.T) {
		begin := func() preAuthTestTx { return begin(t) }
		fixture := func(at time.Time) (session.PreAuthTransaction, PreAuthUse) { return fixture(t, at) }
		insert := func(r session.PreAuthTransaction) { insert(t, r) }
		denied := func(err error) { denied(t, err) }
		for _, successor := range []uint64{1, 2} {
			r, use := fixture(time.Now().UTC().Add(-5*time.Minute + time.Second))
			insert(r)
			q := begin()
			if err := ReservePreAuth(ctx, q, config, r, use); err != nil {
				t.Fatal(err)
			}
			if err := q.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			s, _ := r.Bindings()
			q = begin()
			if _, err := q.Exec(ctx, `SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM($1::timestamptz-clock_timestamp())))+0.02)`, s.Binding.ExpiresAt); err != nil {
				t.Fatal(err)
			}
			denied(RequireReservedPreAuth(ctx, q, config, r, use))
			changed := use
			changed.Fingerprint[0]++
			denied(releasePreAuth(ctx, q, config, r, changed, successor))
			var invalid identity.InvalidInputError
			if err := releasePreAuth(ctx, q, config, r, use, 3); !errors.As(err, &invalid) {
				t.Fatal("skipped release generation accepted", err)
			}
			if err := releasePreAuth(ctx, q, config, r, use, successor); err != nil {
				t.Fatal("expired reserved state cannot release", err)
			}
			denied(releasePreAuth(ctx, q, config, r, use, successor))
			if err := q.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			q = begin()
			if err := releasePreAuth(ctx, q, config, r, use, successor); err != nil {
				t.Fatal("rollback terminalized release", err)
			}
			if err := q.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			q = begin()
			denied(ReservePreAuth(ctx, q, config, r, use))
			denied(FinalizePreAuth(ctx, q, config, r, use))
			denied(releasePreAuth(ctx, q, config, r, use, successor))
			var state, generation, version string
			var payload []byte
			if err := q.QueryRow(ctx, `SELECT state,generation::text,version::text,record FROM session_store.preauth_transactions WHERE flow_id=$1`, string(s.Binding.ID)).Scan(&state, &generation, &version, &payload); err != nil || state != "released" || generation != strconv.FormatUint(successor, 10) || version != "3" {
				t.Fatal("release state not terminal", err)
			}
			want, _ := encodePreAuth(r)
			if !bytes.Equal(want, payload) {
				t.Fatal("release changed original flow")
			}
		}
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
