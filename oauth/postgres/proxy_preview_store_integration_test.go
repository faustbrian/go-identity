//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// Synthetic originals exercise native custody access, not AEAD, capability
// reservation, command recovery or session issuance. Those remain owner tests.
func TestProxyPreviewStoreNativeQueries(t *testing.T) {
	ctx, db := rpMigrationDatabase(t)
	base, err := (MigrationSource{Schema: "oauth_rp", Version: 100}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, base[0].UpSQL()); err != nil {
		t.Fatal("install preceding schema", err)
	}
	history, err := (ProxyPreviewBindingMigrationSource{Schema: "oauth_rp", Version: 101}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, history[0].UpSQL()); err != nil {
		t.Fatal("install preview custody", err)
	}
	// The five-minute window at 80 starts/second contains 24k rows. Dense and
	// sparse tenants share the same exact primary-key access shape.
	const seed = `INSERT INTO oauth_rp.proxy_preview_bindings
(tenant_id,flow_id,origin_command_id,callback_command_id,issued_at,expires_at,binding_ciphertext,proof_ciphertext,version)
SELECT CASE WHEN g%10=0 THEN 'tenant-small' ELSE 'tenant-dense' END,
translate(rtrim(encode(decode(md5('flow-'||g),'hex'),'base64'),'='),'+/','-_'),
decode(md5('origin-'||g),'hex'),decode(md5('callback-'||g),'hex'),
date_trunc('second',statement_timestamp())-interval '1 minute',
date_trunc('second',statement_timestamp())+interval '4 minutes',decode(md5('binding-'||g),'hex'),decode(md5('proof-'||g),'hex'),1
FROM generate_series(1,24000) g`
	if _, err := db.Exec(ctx, seed); err != nil {
		t.Fatal("populate skewed custody", err)
	}
	for _, id := range []int{123, 120} {
		binding, proof := make([]byte, 2048), make([]byte, 2048)
		for _, wire := range [][]byte{binding, proof} {
			if _, err := rand.Read(wire); err != nil {
				t.Fatal("generate incompressible opaque fixture", err)
			}
		}
		if _, err := db.Exec(ctx, `UPDATE oauth_rp.proxy_preview_bindings SET binding_ciphertext=$2,proof_ciphertext=$3 WHERE flow_id=$1`, proxyPreviewStoreFlow(id), binding, proof); err != nil {
			t.Fatal("install measured ciphertext-shaped originals", err)
		}
	}
	if _, err := db.Exec(ctx, `ANALYZE oauth_rp.proxy_preview_bindings`); err != nil {
		t.Fatal(err)
	}

	t.Run("read exposes only exact current open custody", func(t *testing.T) {
		flow := identity.PreAuthTransactionID(proxyPreviewStoreFlow(123))
		row, err := readProxyPreviewRow(ctx, db, "oauth_rp", "tenant-dense", flow)
		if err != nil || row.locator.Tenant != "tenant-dense" || row.locator.Flow != flow ||
			row.locator.OriginCommand != identity.CommandID(proxyPreviewStoreID("origin-123")) ||
			row.locator.CallbackCommand != identity.CommandID(proxyPreviewStoreID("callback-123")) ||
			len(row.binding) != 2048 || len(row.proof) != 2048 || row.observed.Before(row.locator.IssuedAt) || !row.observed.Before(row.locator.ExpiresAt) {
			t.Fatal("read lost exact original or database cutoff", err)
		}
		binding, proof := row.binding, row.proof
		row.clear()
		if row.locator != (proxyPreviewBindingLocator{}) || !row.observed.IsZero() || row.binding != nil || row.proof != nil ||
			!bytes.Equal(binding, make([]byte, len(binding))) || !bytes.Equal(proof, make([]byte, len(proof))) {
			t.Fatal("clear retained recoverable custody")
		}
		for _, test := range []struct {
			name   string
			tenant identity.TenantID
			flow   identity.PreAuthTransactionID
		}{
			{"foreign tenant", "tenant-small", flow},
			{"missing flow", "tenant-dense", identity.PreAuthTransactionID(proxyPreviewStoreFlow(30000))},
		} {
			t.Run(test.name, func(t *testing.T) {
				got, err := readProxyPreviewRow(ctx, db, "oauth_rp", test.tenant, test.flow)
				if !errors.Is(err, identity.ForbiddenError{}) || got.binding != nil || got.proof != nil {
					t.Fatal("nonmatching lookup disclosed custody", err)
				}
			})
		}
		for _, test := range []struct{ name, mutation string }{
			{"expired", `issued_at=date_trunc('second',statement_timestamp())-interval '5 minutes',expires_at=date_trunc('second',statement_timestamp())`},
			{"not yet issued", `issued_at=date_trunc('second',statement_timestamp())+interval '1 minute',expires_at=date_trunc('second',statement_timestamp())+interval '2 minutes'`},
			{"settled", `version=2,proof_ciphertext=NULL,settled_at=statement_timestamp()`},
		} {
			t.Run(test.name, func(t *testing.T) {
				tx, err := db.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				if _, err := tx.Exec(ctx, `UPDATE oauth_rp.proxy_preview_bindings SET `+test.mutation+` WHERE tenant_id='tenant-dense' AND flow_id=$1`, string(flow)); err != nil {
					t.Fatal(err)
				}
				got, err := readProxyPreviewRow(ctx, tx, "oauth_rp", "tenant-dense", flow)
				if !errors.Is(err, identity.ForbiddenError{}) || got.binding != nil || got.proof != nil {
					t.Fatal("noncurrent custody exposed", err)
				}
			})
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		got, err := readProxyPreviewRow(cancelled, db, "oauth_rp", "tenant-dense", flow)
		if !errors.Is(err, context.Canceled) || got.proof != nil {
			t.Fatal("read hid cancellation or retained custody", err)
		}
		var invalid identity.InvalidInputError
		if _, err := readProxyPreviewRow(ctx, db, "bad-schema", "tenant-dense", flow); !errors.As(err, &invalid) {
			t.Fatal("read accepted invalid schema", err)
		}
		if _, err := readProxyPreviewRow(ctx, db, "oauth_rp", "tenant-dense", "bad"); !errors.As(err, &invalid) {
			t.Fatal("read accepted malformed flow", err)
		}
	})

	t.Run("exact original mutation and settlement predicates", func(t *testing.T) {
		original, err := readProxyPreviewRow(ctx, db, "oauth_rp", "tenant-dense", identity.PreAuthTransactionID(proxyPreviewStoreFlow(123)))
		if err != nil {
			t.Fatal(err)
		}
		defer original.clear()
		for _, test := range []struct {
			name   string
			change func(*proxyPreviewRow)
		}{
			{"tenant", func(r *proxyPreviewRow) { r.locator.Tenant = "tenant-small" }},
			{"flow", func(r *proxyPreviewRow) { r.locator.Flow = identity.PreAuthTransactionID(proxyPreviewStoreFlow(30000)) }},
			{"origin", func(r *proxyPreviewRow) {
				r.locator.OriginCommand = identity.CommandID(proxyPreviewStoreID("changed-origin"))
			}},
			{"callback", func(r *proxyPreviewRow) {
				r.locator.CallbackCommand = identity.CommandID(proxyPreviewStoreID("changed-callback"))
			}},
			{"issuance", func(r *proxyPreviewRow) { r.locator.IssuedAt = r.locator.IssuedAt.Add(-time.Second) }},
			{"expiry", func(r *proxyPreviewRow) { r.locator.ExpiresAt = r.locator.ExpiresAt.Add(-time.Second) }},
			{"binding", func(r *proxyPreviewRow) { r.binding = []byte("different-binding") }},
			{"proof", func(r *proxyPreviewRow) { r.proof = []byte("different-proof") }},
		} {
			t.Run(test.name, func(t *testing.T) {
				changed := original
				test.change(&changed)
				args := proxyPreviewStoreOriginalArgs(changed)
				tx, err := db.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				for _, statement := range []string{requireProxyPreviewSQL("oauth_rp", false), settleProxyPreviewSQL("oauth_rp")} {
					tag, err := tx.Exec(ctx, statement, args...)
					if err != nil || tag.RowsAffected() != 0 {
						t.Fatal("substituted original locked or settled custody", err)
					}
				}
			})
		}
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		args := proxyPreviewStoreOriginalArgs(original)
		if tag, err := tx.Exec(ctx, requireProxyPreviewSQL("oauth_rp", false), args...); err != nil || tag.RowsAffected() != 1 {
			t.Fatal("exact original could not be locked", err)
		}
		if tag, err := tx.Exec(ctx, requireProxyPreviewSQL("oauth_rp", true), args[:7]...); err != nil || tag.RowsAffected() != 0 {
			t.Fatal("open original passed settled check", err)
		}
		if tag, err := tx.Exec(ctx, settleProxyPreviewSQL("oauth_rp"), args...); err != nil || tag.RowsAffected() != 1 {
			t.Fatal("exact original could not be settled", err)
		}
		if tag, err := tx.Exec(ctx, requireProxyPreviewSQL("oauth_rp", true), args[:7]...); err != nil || tag.RowsAffected() != 1 {
			t.Fatal("settled original could not be locked", err)
		}
		var recovered string
		if err := tx.QueryRow(ctx, recoverProxyPreviewBindingSQL("oauth_rp"), args[:3]...).Scan(&recovered); err != nil || recovered != string(original.locator.Flow) {
			t.Fatal("terminal custody lost original-command recovery evidence", err)
		}
		for _, statement := range []string{requireProxyPreviewSQL("oauth_rp", false), settleProxyPreviewSQL("oauth_rp")} {
			if tag, err := tx.Exec(ctx, statement, args...); err != nil || tag.RowsAffected() != 0 {
				t.Fatal("settled original was reused", err)
			}
		}
		var erased bool
		if err := tx.QueryRow(ctx, `SELECT version=2 AND proof_ciphertext IS NULL AND settled_at>=issued_at AND binding_ciphertext=$3
FROM oauth_rp.proxy_preview_bindings WHERE tenant_id=$1 AND flow_id=$2`, args[0], args[1], args[6]).Scan(&erased); err != nil || !erased {
			t.Fatal("settlement did not erase proof and retain provenance", err)
		}
	})

	t.Run("typed populated plans and repeated bounded samples", func(t *testing.T) {
		var version, columns, indexes string
		if err := db.QueryRow(ctx, `SELECT current_setting('server_version'),
(SELECT string_agg(column_name||':'||coalesce(domain_schema||'.'||domain_name,udt_schema||'.'||udt_name),', ' ORDER BY ordinal_position)
 FROM information_schema.columns WHERE table_schema='oauth_rp' AND table_name='proxy_preview_bindings'),
(SELECT string_agg(indexdef,E'\n' ORDER BY indexname) FROM pg_indexes WHERE schemaname='oauth_rp' AND tablename='proxy_preview_bindings')`).Scan(&version, &columns, &indexes); err != nil {
			t.Fatal("inspect populated fixture context", err)
		}
		t.Logf("PostgreSQL %s; 24k analyzed isolated rows, 90%% dense and 10%% sparse tenant; selected binding/proof 2048/2048 incompressible opaque bytes, background 16/16 bytes; sequential warm samples, no concurrent load or production claim", version)
		t.Logf("columns: %s\nindexes: %s", columns, indexes)
		for _, test := range []struct {
			name, tenant string
			id           int
		}{{"dense", "tenant-dense", 123}, {"sparse", "tenant-small", 120}} {
			t.Run(test.name, func(t *testing.T) {
				row, err := readProxyPreviewRow(ctx, db, "oauth_rp", identity.TenantID(test.tenant), identity.PreAuthTransactionID(proxyPreviewStoreFlow(test.id)))
				if err != nil {
					t.Fatal(err)
				}
				defer row.clear()
				original := proxyPreviewStoreOriginalArgs(row)
				for _, miss := range []bool{false, true} {
					args := append([]any(nil), original...)
					if miss {
						args[1] = proxyPreviewStoreFlow(30000)
					}
					want := int64(1)
					if miss {
						want = 0
					}
					name := fmt.Sprintf("miss=%v", miss)
					proxyPreviewStoreMeasure(t, ctx, db, "read "+name, readProxyPreviewSQL("oauth_rp"), args[:2], want, false, nil)
					proxyPreviewStoreMeasure(t, ctx, db, "recover "+name, recoverProxyPreviewBindingSQL("oauth_rp"), args[:3], want, false, nil)
					proxyPreviewStoreMeasure(t, ctx, db, "lock open "+name, requireProxyPreviewSQL("oauth_rp", false), args, want, false, nil)
					proxyPreviewStoreMeasure(t, ctx, db, "settle "+name, settleProxyPreviewSQL("oauth_rp"), args, want, false, nil)
					setup := func(tx pgx.Tx) {
						t.Helper()
						if tag, err := tx.Exec(ctx, settleProxyPreviewSQL("oauth_rp"), original...); err != nil || tag.RowsAffected() != 1 {
							t.Fatal("prepare terminal lock sample", err)
						}
					}
					proxyPreviewStoreMeasure(t, ctx, db, "lock settled "+name, requireProxyPreviewSQL("oauth_rp", true), args[:7], want, false, setup)
				}
				insert := append([]any(nil), original...)
				insert[1], insert[2], insert[3] = proxyPreviewStoreFlow(30001), bytes.Repeat([]byte{201}, 16), bytes.Repeat([]byte{202}, 16)
				proxyPreviewStoreMeasure(t, ctx, db, "insert", insertProxyPreviewSQL("oauth_rp"), insert, 1, true, nil)
			})
		}
	})
}

func proxyPreviewStoreID(label string) string {
	digest := md5.Sum([]byte(label)) // Stable synthetic identifiers, not a security digest.
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func proxyPreviewStoreFlow(id int) string { return proxyPreviewStoreID(fmt.Sprintf("flow-%d", id)) }

func proxyPreviewStoreOriginalArgs(row proxyPreviewRow) []any {
	l := row.locator
	origin, _ := base64.RawURLEncoding.DecodeString(string(l.OriginCommand))
	callback, _ := base64.RawURLEncoding.DecodeString(string(l.CallbackCommand))
	return []any{string(l.Tenant), string(l.Flow), origin, callback, l.IssuedAt, l.ExpiresAt, row.binding, row.proof}
}

func proxyPreviewStoreMeasure(t *testing.T, ctx context.Context, db *pgx.Conn, name, statement string, args []any, want int64, insert bool, setup func(pgx.Tx)) {
	t.Helper()
	bindings := make([]string, len(args))
	for i, arg := range args {
		bindings[i] = fmt.Sprintf("$%d=%T", i+1, arg)
	}
	t.Logf("%s native Go/pgx bindings: %s; SQL: %s", name, strings.Join(bindings, ", "), statement)
	const samples = 12
	var elapsed, fastest, slowest time.Duration
	for sample := range samples + 1 {
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				if err := tx.Rollback(cleanup); err != nil {
					t.Error("rollback measured fixture", err)
				}
			}()
			if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout='2s'; SET LOCAL lock_timeout='1s'`); err != nil {
				t.Fatal("bound measurement", err)
			}
			if setup != nil {
				setup(tx)
			}
			if sample == 0 {
				var raw []byte
				var plan []struct{ Plan proxyPreviewStorePlan }
				if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+statement, args...).Scan(&raw); err != nil || json.Unmarshal(raw, &plan) != nil || len(plan) != 1 || !plan[0].Plan.bounded(insert) {
					t.Fatalf("%s lost bounded single-original access: %v\n%s", name, err, raw)
				}
				t.Logf("%s instrumented plan: %s", name, raw)
				return
			}
			start := time.Now()
			tag, err := tx.Exec(ctx, statement, args...)
			duration := time.Since(start)
			if err != nil || tag.RowsAffected() != want {
				t.Fatalf("%s affected %d rows, want %d: %v", name, tag.RowsAffected(), want, err)
			}
			elapsed += duration
			if fastest == 0 || duration < fastest {
				fastest = duration
			}
			if duration > slowest {
				slowest = duration
			}
		}()
	}
	t.Logf("%s: %d warm samples mean=%s min=%s max=%s; includes Go/pgx round trip, excludes BEGIN/setup/ROLLBACK and commit durability; no full-operation or production claim", name, samples, elapsed/samples, fastest, slowest)
}

type proxyPreviewStorePlan struct {
	Kind       string `json:"Node Type"`
	Relation   string `json:"Relation Name"`
	Index      string `json:"Index Name"`
	Condition  string `json:"Index Cond"`
	Operation  string
	ActualRows float64 `json:"Actual Rows"`
	Loops      int     `json:"Actual Loops"`
	Searches   int     `json:"Index Searches"`
	Plans      []proxyPreviewStorePlan
}

func (p proxyPreviewStorePlan) bounded(insert bool) bool {
	if insert {
		return p.Kind == "ModifyTable" && p.Operation == "Insert" && p.Relation == "proxy_preview_bindings" && p.Loops == 1 && len(p.Plans) == 1 &&
			p.Plans[0].Kind == "Result" && p.Plans[0].ActualRows == 1 && p.Plans[0].Loops == 1 && len(p.Plans[0].Plans) == 0
	}
	if p.Relation == "proxy_preview_bindings" && p.Kind != "ModifyTable" {
		column := map[string]string{
			"proxy_preview_bindings_pkey":                              "flow_id",
			"proxy_preview_bindings_tenant_id_origin_command_id_key":   "origin_command_id",
			"proxy_preview_bindings_tenant_id_callback_command_id_key": "callback_command_id",
		}[p.Index]
		return (p.Kind == "Index Scan" || p.Kind == "Index Only Scan") && column != "" && p.Loops == 1 && p.ActualRows <= 1 && p.Searches <= 1 &&
			strings.Contains(p.Condition, "tenant_id") && strings.Contains(p.Condition, column)
	}
	if len(p.Plans) != 1 {
		return false
	}
	return p.Plans[0].bounded(false)
}
