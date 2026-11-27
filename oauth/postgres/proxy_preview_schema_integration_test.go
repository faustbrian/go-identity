//go:build integration

package postgres

import (
	"bytes"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// Opaque fixtures prove projection shape, not original-command authentication,
// live preview authorization, encryption or one-use reservation authority.
func TestProxyPreviewBindingForwardSchema(t *testing.T) {
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
			t.Fatal("populate preceding schema", err)
		}
	}
	var originalRow string
	if err := db.QueryRow(ctx, `SELECT row_to_json(t)::text FROM oauth_rp.transactions t`).Scan(&originalRow); err != nil {
		t.Fatal("snapshot populated predecessor", err)
	}

	history, err := (ProxyPreviewBindingMigrationSource{Schema: "oauth_rp", Version: 101}).Load(ctx)
	if err != nil || len(history) != 1 {
		t.Fatal("load additive preview binding migration", err)
	}
	if history[0].Name() != "identity_oauth_proxy_preview_bindings" || history[0].Version() != 101 || history[0].DownSQL() != "" {
		t.Fatal("preview migration lost its allocated forward-only history identity")
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal("begin preview schema apply", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, history[0].UpSQL()); err != nil {
		t.Fatal("apply additive preview schema", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("commit additive preview schema", err)
	}
	var empty bool
	if err := db.QueryRow(ctx, `SELECT NOT EXISTS(SELECT FROM oauth_rp.proxy_preview_bindings)`).Scan(&empty); err != nil || !empty {
		t.Fatal("preview migration did not create empty custody", err)
	}
	if _, err := db.Exec(ctx, history[0].UpSQL()); err == nil {
		t.Fatal("existing preview table silently adopted")
	}

	issued := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	row := func(mark byte) []any {
		return []any{"tenant-a", "preview-" + strconv.Itoa(int(mark)), bytes.Repeat([]byte{mark}, 16),
			bytes.Repeat([]byte{mark + 1}, 16), issued, issued.Add(5 * time.Minute),
			[]byte("binding-fixture"), []byte("proof-fixture"), 1, nil}
	}
	const insert = `INSERT INTO oauth_rp.proxy_preview_bindings
	 (tenant_id,flow_id,origin_command_id,callback_command_id,issued_at,expires_at,
	 binding_ciphertext,proof_ciphertext,version,settled_at)
	 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	wantState := func(t *testing.T, err error, state string) {
		t.Helper()
		var failure *pgconn.PgError
		if !errors.As(err, &failure) || failure.Code != state {
			t.Fatalf("expected SQL state %s, got %v", state, err)
		}
	}
	first := row(10)
	if _, err := db.Exec(ctx, insert, first...); err != nil {
		t.Fatal("store preview custody without fabricated local identity", err)
	}
	for _, test := range []struct {
		name  string
		index int
		value any
		state string
	}{
		{"empty tenant", 0, "", "23514"}, {"empty flow", 1, "", "23514"},
		{"short origin command", 2, []byte{1}, "23514"}, {"long origin command", 2, make([]byte, 17), "23514"},
		{"short callback command", 3, []byte{1}, "23514"}, {"long callback command", 3, make([]byte, 17), "23514"},
		{"nonpositive issuance", 4, time.Unix(0, 0).UTC(), "23514"},
		{"fractional issuance", 4, issued.Add(time.Microsecond), "23514"},
		{"infinite issuance", 4, pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}, "23514"},
		{"infinite expiry", 5, pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}, "23514"},
		{"fractional expiry", 5, issued.Add(time.Second + time.Microsecond), "23514"},
		{"nonpositive lifetime", 5, issued, "23514"},
		{"extended lifetime", 5, issued.Add(5*time.Minute + time.Second), "23514"},
		{"missing binding", 6, nil, "23502"}, {"empty binding", 6, []byte{}, "23514"},
		{"oversized binding", 6, make([]byte, 65537), "23514"},
		{"missing open proof", 7, nil, "23514"}, {"empty proof", 7, []byte{}, "23514"},
		{"oversized proof", 7, make([]byte, 65537), "23514"},
		{"zero version", 8, 0, "23514"}, {"open version two", 8, 2, "23514"},
		{"unsupported version", 8, 3, "23514"}, {"open has settlement", 9, issued, "23514"},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := row(20)
			args[test.index] = test.value
			_, err := db.Exec(ctx, insert, args...)
			wantState(t, err, test.state)
		})
	}
	t.Run("origin and callback must differ", func(t *testing.T) {
		args := row(20)
		args[3] = args[2]
		_, err := db.Exec(ctx, insert, args...)
		wantState(t, err, "23514")
	})
	t.Run("upper ciphertext bounds and clipped original deadline", func(t *testing.T) {
		args := row(25)
		args[5], args[6], args[7] = issued.Add(time.Second), make([]byte, 65536), make([]byte, 65536)
		if _, err := db.Exec(ctx, insert, args...); err != nil {
			t.Fatal("exact ciphertext bounds or clipped lifetime rejected", err)
		}
	})
	for _, index := range []int{1, 2, 3} {
		t.Run("unique tenant ownership "+strconv.Itoa(index), func(t *testing.T) {
			args := row(20)
			args[index] = first[index]
			_, err := db.Exec(ctx, insert, args...)
			wantState(t, err, "23505")
		})
	}
	t.Run("identical flow and command keys are tenant scoped", func(t *testing.T) {
		args := append([]any(nil), first...)
		args[0] = "tenant-b"
		if _, err := db.Exec(ctx, insert, args...); err != nil {
			t.Fatal("independent tenant custody rejected", err)
		}
	})

	const settle = `UPDATE oauth_rp.proxy_preview_bindings SET version=$3,proof_ciphertext=$4,settled_at=$5
	 WHERE tenant_id=$1 AND flow_id=$2`
	for _, test := range []struct {
		name    string
		version int
		proof   []byte
		settled any
	}{
		{"terminal proof retained", 2, []byte{1}, issued},
		{"terminal settlement absent", 2, nil, nil},
		{"terminal predates issuance", 2, nil, issued.Add(-time.Microsecond)},
		{"terminal infinite settlement", 2, nil, pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}},
		{"open proof erased", 1, nil, nil},
		{"unsupported terminal version", 3, nil, issued},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := db.Exec(ctx, settle, first[0], first[1], test.version, test.proof, test.settled)
			wantState(t, err, "23514")
		})
	}
	if _, err := db.Exec(ctx, settle, first[0], first[1], 2, nil, issued); err != nil {
		t.Fatal("terminal proof erasure at issuance rejected", err)
	}
	var retained bool
	if err := db.QueryRow(ctx, `SELECT version=2 AND proof_ciphertext IS NULL AND settled_at=$3
	 AND binding_ciphertext=$4 AND origin_command_id=$5 AND callback_command_id=$6
	 FROM oauth_rp.proxy_preview_bindings WHERE tenant_id=$1 AND flow_id=$2`,
		first[0], first[1], issued, first[6], first[2], first[3]).Scan(&retained); err != nil || !retained {
		t.Fatal("terminal erasure lost binding provenance", err)
	}
	var otherTenantOpen bool
	if err := db.QueryRow(ctx, `SELECT version=1 AND proof_ciphertext IS NOT NULL AND settled_at IS NULL
	 FROM oauth_rp.proxy_preview_bindings WHERE tenant_id='tenant-b' AND flow_id=$1`, first[1]).Scan(&otherTenantOpen); err != nil || !otherTenantOpen {
		t.Fatal("tenant-scoped settlement changed independent custody", err)
	}
	var expiryIndex bool
	if err := db.QueryRow(ctx, `SELECT indisvalid
	 AND regexp_replace(pg_get_expr(indpred,indrelid),'::numeric|[()[:space:]]','','g')='version=1'
	 AND pg_get_indexdef(indexrelid) LIKE '%(expires_at, tenant_id, flow_id)%'
	 FROM pg_index WHERE indexrelid='oauth_rp.proxy_preview_bindings_expiry'::regclass`).Scan(&expiryIndex); err != nil || !expiryIndex {
		t.Fatal("open-only bounded expiry index absent", err)
	}
	var unchanged bool
	if err := db.QueryRow(ctx, `SELECT (SELECT row_to_json(t)::text FROM oauth_rp.transactions t)=$1
	 AND (SELECT count(*)=1 AND min(version)=7 FROM identity.users)
	 AND (SELECT count(*)=1 FROM identity.commands)
	 AND NOT EXISTS(SELECT FROM pg_constraint WHERE conrelid='oauth_rp.proxy_preview_bindings'::regclass AND contype='f')`, originalRow).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("preview custody changed predecessor or acquired local identity authority", err)
	}
}
