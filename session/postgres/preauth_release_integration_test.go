//go:build integration

package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// Historical row fixture deliberately uses the old schema before upgrade.
// It grants no production admission; it proves constraint replacement preserves
// issued, unresolved and consumed primary records byte-for-byte.
func seedPreAuthReleaseUpgrade(t *testing.T, ctx context.Context, db *sql.DB) func() {
	t.Helper()
	type original struct {
		id      identity.PreAuthTransactionID
		state   string
		version int
		payload []byte
		rowJSON string
	}
	var originals []original
	for index, state := range []string{"issued", "reserved", "consumed"} {
		s, _ := testPreAuth(t, time.Now().UTC()).Bindings()
		id, err := identity.NewPreAuthTransactionID()
		if err != nil {
			t.Fatal(err)
		}
		s.Binding.ID = id
		copy(s.Cookie.Sum[:], []byte(s.Binding.ID))
		r, err := session.NewPreAuthTransaction(s)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := encodePreAuth(r)
		if err != nil {
			t.Fatal(err)
		}
		var command, fingerprint any
		var generation any
		if index > 0 {
			commandBytes, fingerprintBytes := [16]byte{1}, [32]byte{7}
			command = commandBytes[:]
			fingerprint = fingerprintBytes[:]
			generation = 1
		}
		if _, err = db.ExecContext(ctx, `INSERT INTO session_store.preauth_transactions(tenant_id,flow_id,record,issued_at,expires_at,digest_version,digest,issued_version,version,state,command_id,fingerprint,generation) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,$10,$11,$12)`, string(s.Binding.Intent.TenantID), string(s.Binding.ID), payload, s.Binding.IssuedAt.Format(storedTimeLayout), s.Binding.ExpiresAt.Format(storedTimeLayout), int64(s.Cookie.KeyVersion), s.Cookie.Sum[:], index+1, state, command, fingerprint, generation); err != nil {
			t.Fatal("old state seed", err)
		}
		var rowJSON string
		if err := db.QueryRowContext(ctx, `SELECT row_to_json(t)::text FROM session_store.preauth_transactions t WHERE tenant_id='tenant-a' AND flow_id=$1`, string(s.Binding.ID)).Scan(&rowJSON); err != nil {
			t.Fatal(err)
		}
		originals = append(originals, original{s.Binding.ID, state, index + 1, payload, rowJSON})
	}
	return func() {
		for _, want := range originals {
			var state string
			var version int
			var payload []byte
			if err := db.QueryRowContext(ctx, `SELECT state,version,record FROM session_store.preauth_transactions WHERE tenant_id='tenant-a' AND flow_id=$1`, string(want.id)).Scan(&state, &version, &payload); err != nil || state != want.state || version != want.version || !bytes.Equal(payload, want.payload) {
				t.Fatal("upgrade changed original primary state", err)
			}
			var rowJSON string
			if err := db.QueryRowContext(ctx, `SELECT row_to_json(t)::text FROM session_store.preauth_transactions t WHERE tenant_id='tenant-a' AND flow_id=$1`, string(want.id)).Scan(&rowJSON); err != nil || rowJSON != want.rowJSON {
				t.Fatal("upgrade changed indexed or custody metadata", err)
			}
		}
	}
}
