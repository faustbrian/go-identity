//go:build integration

package postgres

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// Opaque fixtures exercise only stored custody shape. SQL provenance is not
// authenticated retirement authority or evidence that cleanup actually ran.
func TestProxyRetirementSchemaDoesNotRewriteExistingCustody(t *testing.T) {
	issued := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	retired := issued.Add(2 * time.Minute)
	retirementColumns := []string{"retirement_source_command_id", "retirement_source_version", "retired_at"}
	for _, test := range []struct {
		name          string
		kind          kernel.OAuthProxyRetirementKind
		source        migrations.Source
		table         string
		key           string
		insert        string
		row           func(byte) []any
		settle        string
		retire        string
		bearerColumns []string
		uniqueIndices []int
	}{
		{
			name: "production", kind: kernel.OAuthProxyRetireProduction,
			source: ProxyTransactionMigrationSource{Schema: "oauth_rp", Version: 101},
			table:  "proxy_transactions", key: "transaction_id",
			insert: `INSERT INTO oauth_rp.proxy_transactions
 (tenant_id,transaction_id,origin_command_id,callback_command_id,production_deployment,
 provider_id,configuration_version,production_callback_uri,state_key_version,state_lookup_digest,
 binding_ciphertext,state_proof_ciphertext,pkce_ciphertext,issued_at,expires_at,version,
 outcome,handoff_ciphertext,settled_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
			row: func(mark byte) []any {
				return []any{"tenant-a", "proxy-" + strconv.Itoa(int(mark)), bytes.Repeat([]byte{mark}, 16),
					bytes.Repeat([]byte{mark + 1}, 16), "production-a", "provider-a", 1,
					"https://identity.example/oauth/proxy/callback", 1, bytes.Repeat([]byte{mark}, 32),
					[]byte("binding-fixture"), []byte("state-proof-fixture"), []byte("pkce-fixture"),
					issued, issued.Add(5 * time.Minute), 1, nil, nil, nil}
			},
			settle: `UPDATE oauth_rp.proxy_transactions SET version=2,outcome=1,
 state_proof_ciphertext=NULL,pkce_ciphertext=NULL,handoff_ciphertext=$3,settled_at=$4
 WHERE tenant_id=$1 AND transaction_id=$2`,
			retire: `UPDATE oauth_rp.proxy_transactions SET version=3,
 state_proof_ciphertext=NULL,pkce_ciphertext=NULL,handoff_ciphertext=NULL,
 retirement_source_command_id=$3,retirement_source_version=$4,retired_at=$5
 WHERE tenant_id=$1 AND transaction_id=$2`,
			bearerColumns: []string{"state_proof_ciphertext", "pkce_ciphertext", "handoff_ciphertext"},
			uniqueIndices: []int{1, 2, 3, 9},
		},
		{
			name: "preview", kind: kernel.OAuthProxyRetirePreview,
			source: ProxyPreviewBindingMigrationSource{Schema: "oauth_rp", Version: 101},
			table:  "proxy_preview_bindings", key: "flow_id",
			insert: `INSERT INTO oauth_rp.proxy_preview_bindings
 (tenant_id,flow_id,origin_command_id,callback_command_id,issued_at,expires_at,
 binding_ciphertext,proof_ciphertext,version,settled_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			row: func(mark byte) []any {
				return []any{"tenant-a", "preview-" + strconv.Itoa(int(mark)), bytes.Repeat([]byte{mark}, 16),
					bytes.Repeat([]byte{mark + 1}, 16), issued, issued.Add(5 * time.Minute),
					[]byte("binding-fixture"), []byte("proof-fixture"), 1, nil}
			},
			settle: `UPDATE oauth_rp.proxy_preview_bindings SET version=2,proof_ciphertext=NULL,settled_at=$3
 WHERE tenant_id=$1 AND flow_id=$2`,
			retire: `UPDATE oauth_rp.proxy_preview_bindings SET version=3,proof_ciphertext=NULL,
 retirement_source_command_id=$3,retirement_source_version=$4,retired_at=$5
 WHERE tenant_id=$1 AND flow_id=$2`,
			bearerColumns: []string{"proof_ciphertext"}, uniqueIndices: []int{1, 2, 3},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, db := rpMigrationDatabase(t)
			for _, source := range []migrations.Source{MigrationSource{Schema: "oauth_rp", Version: 100}, test.source} {
				history, err := source.Load(ctx)
				if err != nil || len(history) != 1 {
					t.Fatal("load deployed predecessor schema", err)
				}
				if _, err := db.Exec(ctx, history[0].UpSQL()); err != nil {
					t.Fatal("install deployed predecessor schema", err)
				}
			}
			open, settled := test.row(10), test.row(20)
			for _, row := range [][]any{open, settled} {
				if _, err := db.Exec(ctx, test.insert, row...); err != nil {
					t.Fatal("populate original custody", err)
				}
			}
			settleArgs := []any{settled[0], settled[1], issued.Add(time.Second)}
			if test.kind == kernel.OAuthProxyRetireProduction {
				settleArgs = []any{settled[0], settled[1], []byte("handoff-envelope-fixture"), issued.Add(time.Second)}
			}
			if _, err := db.Exec(ctx, test.settle, settleArgs...); err != nil {
				t.Fatal("populate original known settlement", err)
			}
			otherTenant := append([]any(nil), open...)
			otherTenant[0] = "tenant-b"
			if test.kind == kernel.OAuthProxyRetireProduction {
				otherTenant[4] = "production-b"
			}
			if _, err := db.Exec(ctx, test.insert, otherTenant...); err != nil {
				t.Fatal("populate independently scoped custody", err)
			}

			qualified := "oauth_rp." + test.table
			var before, beforeKeys, oldChecks string
			var beforeFile, afterFile int64
			const relationFile = `SELECT pg_relation_filenode($1::regclass)::bigint`
			if err := db.QueryRow(ctx, relationFile, qualified).Scan(&beforeFile); err != nil {
				t.Fatal("read original custody relation file", err)
			}
			if err := db.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(t) ORDER BY tenant_id,`+test.key+`)::text FROM `+qualified+` t`).Scan(&before); err != nil {
				t.Fatal("snapshot populated predecessor semantics", err)
			}
			const keyDefinitions = `SELECT string_agg(pg_get_constraintdef(oid), E'\n' ORDER BY pg_get_constraintdef(oid))
 FROM pg_constraint WHERE conrelid=$1::regclass AND contype IN ('p','u')`
			if err := db.QueryRow(ctx, keyDefinitions, qualified).Scan(&beforeKeys); err != nil {
				t.Fatal("snapshot original primary and unique keys", err)
			}
			if err := db.QueryRow(ctx, `SELECT string_agg(conname,', ' ORDER BY conname)
 FROM pg_constraint WHERE conrelid=$1::regclass AND contype='c'`, qualified).Scan(&oldChecks); err != nil {
				t.Fatal("read deployed CHECK names", err)
			}
			t.Log("deployed custody CHECK names:", oldChecks)

			history, err := (ProxyRetirementMigrationSource{Schema: "oauth_rp", Version: 102, Kind: test.kind}).Load(ctx)
			if err != nil || len(history) != 2 {
				t.Fatal("load appended retirement migration", err)
			}
			for i, migration := range history {
				if migration.Version() != migrations.Version(102+i) || migration.DownSQL() != "" {
					t.Fatal("retirement migration lost allocated forward-only history")
				}
				if _, err := db.Exec(ctx, migration.UpSQL()); err != nil {
					t.Fatal("append retirement shape to populated custody", err)
				}
			}
			if err := db.QueryRow(ctx, relationFile, qualified).Scan(&afterFile); err != nil || beforeFile != afterFile {
				t.Fatal("retirement migration physically rewrote populated custody", err)
			}
			var after, afterKeys string
			if err := db.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(t)-$1::text[] ORDER BY tenant_id,`+test.key+`)::text FROM `+qualified+` t`, retirementColumns).Scan(&after); err != nil || after != before {
				t.Fatal("retirement migration rewrote original row semantics", err)
			}
			if err := db.QueryRow(ctx, keyDefinitions, qualified).Scan(&afterKeys); err != nil || afterKeys != beforeKeys {
				t.Fatal("retirement migration changed original primary or unique keys", err)
			}
			var noFabricatedRetirement bool
			if err := db.QueryRow(ctx, `SELECT bool_and(retirement_source_command_id IS NULL
 AND retirement_source_version IS NULL AND retired_at IS NULL) FROM `+qualified).Scan(&noFabricatedRetirement); err != nil || !noFabricatedRetirement {
				t.Fatal("migration fabricated retirement provenance for existing rows", err)
			}

			wantCheck := func(t *testing.T, err error) {
				t.Helper()
				var failure *pgconn.PgError
				if !errors.As(err, &failure) || failure.Code != "23514" {
					t.Fatalf("expected custody CHECK violation, got %v", err)
				}
			}
			sourceCommand := bytes.Repeat([]byte{70}, 16)
			for _, invalid := range []struct {
				name    string
				command []byte
				version any
				at      any
			}{
				{"missing source command", nil, 8, retired},
				{"short source command", []byte{70}, 8, retired},
				{"long source command", bytes.Repeat([]byte{70}, 17), 8, retired},
				{"zero source command", make([]byte, 16), 8, retired},
				{"missing source version", sourceCommand, nil, retired},
				{"zero source version", sourceCommand, 0, retired},
				{"missing retirement time", sourceCommand, 8, nil},
				{"infinite retirement time", sourceCommand, 8, pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}},
			} {
				t.Run(invalid.name, func(t *testing.T) {
					_, err := db.Exec(ctx, test.retire, open[0], open[1], invalid.command, invalid.version, invalid.at)
					wantCheck(t, err)
				})
			}
			for _, column := range test.bearerColumns {
				t.Run("retained "+column, func(t *testing.T) {
					statement := strings.Replace(test.retire, column+"=NULL", column+"=$6", 1)
					_, err := db.Exec(ctx, statement, open[0], open[1], sourceCommand, 8, retired, []byte("retained-bearer-fixture"))
					wantCheck(t, err)
				})
			}

			mutableColumns := append(append([]string{"version"}, retirementColumns...), test.bearerColumns...)
			stableRow := `SELECT (to_jsonb(t)-$3::text[])::text FROM ` + qualified + ` t WHERE tenant_id=$1 AND ` + test.key + `=$2`
			for _, row := range [][]any{open, settled} {
				var original, erased string
				if err := db.QueryRow(ctx, stableRow, row[0], row[1], mutableColumns).Scan(&original); err != nil {
					t.Fatal("snapshot original binding and settlement", err)
				}
				result, err := db.Exec(ctx, test.retire, row[0], row[1], sourceCommand, 8, retired)
				if err != nil || result.RowsAffected() != 1 {
					t.Fatal("erase exact custody with retirement provenance", err)
				}
				if err := db.QueryRow(ctx, stableRow, row[0], row[1], mutableColumns).Scan(&erased); err != nil || erased != original {
					t.Fatal("retirement changed original binding, outcome or settlement", err)
				}
				var validErasure bool
				erasureCheck := `SELECT version=3 AND retirement_source_command_id=$3
 AND retirement_source_version=8 AND retired_at=$4 AND binding_ciphertext IS NOT NULL`
				for _, column := range test.bearerColumns {
					erasureCheck += " AND " + column + " IS NULL"
				}
				if err := db.QueryRow(ctx, erasureCheck+` FROM `+qualified+` WHERE tenant_id=$1 AND `+test.key+`=$2`, row[0], row[1], sourceCommand, retired).Scan(&validErasure); err != nil || !validErasure {
					t.Fatal("retired row retained bearer custody or lost exact provenance", err)
				}
			}
			var independent bool
			if err := db.QueryRow(ctx, `SELECT version=1 AND settled_at IS NULL
 AND retirement_source_command_id IS NULL AND retirement_source_version IS NULL AND retired_at IS NULL
 FROM `+qualified+` WHERE tenant_id=$1 AND `+test.key+`=$2`, otherTenant[0], otherTenant[1]).Scan(&independent); err != nil || !independent {
				t.Fatal("tenant-scoped retirement changed independent custody", err)
			}
			for _, index := range test.uniqueIndices {
				t.Run("retired key remains occupied "+strconv.Itoa(index), func(t *testing.T) {
					candidate := test.row(40)
					candidate[index] = open[index]
					_, err := db.Exec(ctx, test.insert, candidate...)
					var failure *pgconn.PgError
					if !errors.As(err, &failure) || failure.Code != "23505" {
						t.Fatalf("retired custody released an original unique key: %v", err)
					}
				})
			}
		})
	}
}
