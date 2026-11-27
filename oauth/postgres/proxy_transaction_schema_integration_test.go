//go:build integration

package postgres

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// Opaque bytes exercise SQL custody shape, not encryption, command authority,
// or replay. Those remain contracts of the native owner and identity kernel.
func TestProxyTransactionForwardSchema(t *testing.T) {
	ctx, db := rpMigrationDatabase(t)
	prior, err := (MigrationSource{Schema: "oauth_rp", Version: 100}).Load(ctx)
	if err != nil {
		t.Fatal("load preceding OAuth schema", err)
	}
	if _, err := db.Exec(ctx, prior[0].UpSQL()); err != nil {
		t.Fatal("install preceding OAuth schema", err)
	}
	command, fingerprint := bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{1}, 32)
	const purpose = "identity.account.link-start"
	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','original-user','active',7)`, nil},
		{`INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'tenant-a',$2,$3,1,$4)`, []any{command, purpose, fingerprint, []byte{1}}},
		{`INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'tenant-a',$2)`, []any{command, purpose}},
		{rpInsertTransaction, []any{command, purpose, fingerprint, []byte("predecessor-custody")}},
	} {
		if _, err := db.Exec(ctx, seed.sql, seed.args...); err != nil {
			t.Fatal("populate preceding OAuth schema", err)
		}
	}
	var originalRow string
	if err := db.QueryRow(ctx, `SELECT row_to_json(t)::text FROM oauth_rp.transactions t`).Scan(&originalRow); err != nil {
		t.Fatal("snapshot preceding custody", err)
	}

	history, err := (ProxyTransactionMigrationSource{Schema: "oauth_rp", Version: 101}).Load(ctx)
	if err != nil || len(history) != 1 {
		t.Fatal("load additive proxy migration", err)
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal("begin proxy schema apply", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, history[0].UpSQL()); err != nil {
		t.Fatal("apply additive proxy schema", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("commit additive proxy schema", err)
	}
	var afterRow string
	if err := db.QueryRow(ctx, `SELECT row_to_json(t)::text FROM oauth_rp.transactions t`).Scan(&afterRow); err != nil || afterRow != originalRow {
		t.Fatal("proxy schema changed populated predecessor", err)
	}
	if _, err := db.Exec(ctx, history[0].UpSQL()); err == nil {
		t.Fatal("existing proxy table silently adopted")
	}

	issued := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	row := func(mark byte) []any {
		return []any{"tenant-a", "proxy-" + strconv.Itoa(int(mark)), bytes.Repeat([]byte{mark}, 16),
			bytes.Repeat([]byte{mark + 1}, 16), "production-a", "provider-a", 1,
			"https://identity.example/oauth/proxy/callback", 1, bytes.Repeat([]byte{mark}, 32),
			[]byte("binding-fixture"), []byte("state-proof-fixture"), []byte("pkce-fixture"),
			issued, issued.Add(5 * time.Minute), 1, nil, nil, nil}
	}
	const insert = `INSERT INTO oauth_rp.proxy_transactions
	 (tenant_id,transaction_id,origin_command_id,callback_command_id,production_deployment,
	 provider_id,configuration_version,production_callback_uri,state_key_version,state_lookup_digest,
	 binding_ciphertext,state_proof_ciphertext,pkce_ciphertext,issued_at,expires_at,version,
	 outcome,handoff_ciphertext,settled_at)
	 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`
	assertSQLState := func(t *testing.T, err error, state string) {
		t.Helper()
		var failure *pgconn.PgError
		if !errors.As(err, &failure) || failure.Code != state {
			t.Fatalf("expected SQL state %s, got %v", state, err)
		}
	}
	first := row(10)
	if _, err := db.Exec(ctx, insert, first...); err != nil {
		t.Fatal("store initial encrypted proxy custody without a fabricated local user", err)
	}

	for _, test := range []struct {
		name  string
		index int
		value any
	}{
		{"empty tenant", 0, ""}, {"empty transaction", 1, ""},
		{"short origin command", 2, []byte{1}}, {"short callback command", 3, []byte{1}},
		{"uppercase deployment", 4, "Production-a"}, {"long deployment", 4, strings.Repeat("a", 129)},
		{"uppercase provider", 5, "Provider-a"}, {"long provider", 5, strings.Repeat("a", 129)},
		{"zero configuration version", 6, 0}, {"empty production callback", 7, ""},
		{"oversized production callback", 7, strings.Repeat("a", 2049)},
		{"zero state key", 8, 0}, {"overflow state key", 8, int64(4294967296)},
		{"short lookup digest", 9, []byte{1}}, {"zero lookup digest", 9, make([]byte, 32)},
		{"empty binding", 10, []byte{}}, {"oversized binding", 10, make([]byte, 65537)},
		{"missing state proof", 11, nil}, {"missing pkce", 12, nil},
		{"empty state proof", 11, []byte{}}, {"oversized state proof", 11, make([]byte, 65537)},
		{"empty pkce", 12, []byte{}}, {"oversized pkce", 12, make([]byte, 4097)},
		{"nonpositive issuance", 13, time.Unix(0, 0).UTC()},
		{"infinite issuance", 13, pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}},
		{"infinite expiry", 14, pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}},
		{"nonpositive lifetime", 14, issued}, {"extended lifetime", 14, issued.Add(5*time.Minute + time.Microsecond)},
		{"open version two", 15, 2}, {"open has outcome", 16, 1},
		{"open has handoff", 17, []byte{1}}, {"open has settlement time", 18, issued},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := row(20)
			args[test.index] = test.value
			_, err := db.Exec(ctx, insert, args...)
			assertSQLState(t, err, "23514")
		})
	}
	t.Run("upper ciphertext and lookup key bounds remain usable", func(t *testing.T) {
		args := row(25)
		args[8], args[10], args[11], args[12] = int64(4294967295), make([]byte, 65536), make([]byte, 65536), make([]byte, 4096)
		if _, err := db.Exec(ctx, insert, args...); err != nil {
			t.Fatal("exact upper custody bounds rejected", err)
		}
	})
	for _, index := range []int{2, 3, 9} {
		t.Run("unique ownership "+strconv.Itoa(index), func(t *testing.T) {
			args := row(20)
			args[index] = first[index]
			_, err := db.Exec(ctx, insert, args...)
			assertSQLState(t, err, "23505")
		})
	}
	t.Run("global configured lookup rejects cross tenant alias", func(t *testing.T) {
		args := row(20)
		args[0], args[9] = "tenant-b", first[9]
		_, err := db.Exec(ctx, insert, args...)
		assertSQLState(t, err, "23505")
	})
	t.Run("same commands are scoped to tenant and lookup to deployment profile", func(t *testing.T) {
		for _, index := range []int{0, 4, 5, 6, 8} {
			args := row(byte(30 + index))
			args[9] = first[9]
			switch index {
			case 0:
				args[0], args[2], args[3], args[4] = "tenant-b", first[2], first[3], "production-b"
			case 4, 5:
				args[index] = "other-profile"
			case 6, 8:
				args[index] = 2
			}
			if _, err := db.Exec(ctx, insert, args...); err != nil {
				t.Fatal("distinct authorized lookup profile rejected", err)
			}
		}
	})

	const settle = `UPDATE oauth_rp.proxy_transactions
	 SET version=2,outcome=$3,handoff_ciphertext=$4,settled_at=$5,
	 state_proof_ciphertext=$6,pkce_ciphertext=$7 WHERE tenant_id=$1 AND transaction_id=$2`
	for _, test := range []struct {
		name    string
		outcome int
		handoff []byte
		settled any
		state   []byte
		pkce    []byte
	}{
		{"forward lacks handoff", 1, nil, issued, nil, nil},
		{"rejection has handoff", 2, []byte{1}, issued, nil, nil},
		{"unknown has no fake outcome", 3, nil, issued, nil, nil},
		{"forward empty handoff", 1, []byte{}, issued, nil, nil},
		{"forward oversized handoff", 1, make([]byte, 8193), issued, nil, nil},
		{"forward retains state", 1, []byte{1}, issued, []byte{1}, nil},
		{"forward retains pkce", 1, []byte{1}, issued, nil, []byte{1}},
		{"settlement predates issuance", 2, nil, issued.Add(-time.Microsecond), nil, nil},
		{"infinite settlement", 2, nil, pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}, nil, nil},
		{"settlement absent", 2, nil, nil, nil, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := db.Exec(ctx, settle, first[0], first[1], test.outcome, test.handoff, test.settled, test.state, test.pkce)
			assertSQLState(t, err, "23514")
		})
	}
	for _, outcome := range []int{1, 2} {
		args := row(byte(60 + outcome))
		if _, err := db.Exec(ctx, insert, args...); err != nil {
			t.Fatal("seed custody before terminal projection", err)
		}
		var handoff []byte
		if outcome == 1 {
			handoff = []byte("handoff-envelope-fixture")
		}
		if _, err := db.Exec(ctx, settle, args[0], args[1], outcome, handoff, issued.Add(time.Second), nil, nil); err != nil {
			t.Fatal("atomic terminal projection and secret erasure rejected", err)
		}
		var retained bool
		if err := db.QueryRow(ctx, `SELECT version=2 AND outcome=$3 AND settled_at IS NOT NULL
		 AND state_proof_ciphertext IS NULL AND pkce_ciphertext IS NULL AND binding_ciphertext=$4
		 AND state_lookup_digest=$5 AND origin_command_id=$6 AND callback_command_id=$7
		 FROM oauth_rp.proxy_transactions WHERE tenant_id=$1 AND transaction_id=$2`,
			args[0], args[1], outcome, args[10], args[9], args[2], args[3]).Scan(&retained); err != nil || !retained {
			t.Fatal("terminal erasure lost binding provenance", err)
		}
	}
	var unchanged bool
	if err := db.QueryRow(ctx, `SELECT (SELECT row_to_json(t)::text FROM oauth_rp.transactions t)=$1
	 AND (SELECT count(*)=1 AND min(version)=7 FROM identity.users)
	 AND (SELECT count(*)=1 FROM identity.commands)
	 AND NOT EXISTS(SELECT FROM pg_constraint WHERE conrelid='oauth_rp.proxy_transactions'::regclass AND contype='f')`, originalRow).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("proxy custody modified production identity or acquired local identity ownership", err)
	}
}
