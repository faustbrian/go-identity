//go:build integration && queryperformance

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// This is a bounded local query experiment, not production latency or full
// callback admission proof. Native invocation captures the actual pgx bindings;
// EXPLAIN reuses them rather than reconstructing an interpolated approximation.
func TestCallbackOperationQueryUsesBoundedStateIndex(t *testing.T) {
	ctx, phase, out, _, request, fixturePool, _ := storedRPCallbackFixture(t, 0)
	// Bulk fixture construction is separate from the one-second native call
	// budget; the shared migration fixture's thirty seconds is too short here.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	c := phase.service.config()
	profile := request.Callback.Profile()
	db := fixturePool.Raw()
	for _, statement := range []string{
		`CREATE TEMP TABLE callback_query_seed AS SELECT n,
 CASE WHEN n<=90000 THEN $1::text ELSE 'cold-'||(n%100)::text END AS tenant,
 decode(md5('callback-route:'||n::text),'hex') AS command,
 decode(md5('state-a:'||n::text)||md5('state-b:'||n::text),'hex') AS digest
 FROM generate_series(1,100000) n`,
		`INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
 SELECT command,tenant,'identity.oauth.signin-start',digest,1,decode('01','hex') FROM callback_query_seed`,
		`INSERT INTO identity.commands(command_id,tenant_id,purpose)
 SELECT command,tenant,'identity.oauth.signin-start' FROM callback_query_seed`,
		`INSERT INTO oauth_rp.transactions(tenant_id,transaction_id,origin_command_id,operation,preauth_id,
 provider_id,configuration_version,issuer,client_id,redirect_uri,response_mode,state_key_version,state_digest,
 pkce_key_version,pkce_commitment,pkce_ciphertext,state_proof_ciphertext,binding_ciphertext,issued_at,expires_at,version)
 SELECT seed.tenant,encode(seed.command,'hex'),seed.command,'identity.oauth.signin-start','preauth-'||seed.n,
 CASE WHEN seed.n%20=0 THEN 'foreign-provider' ELSE original.provider_id END,
 original.configuration_version,original.issuer,original.client_id,original.redirect_uri,'query',1,seed.digest,
 original.pkce_key_version,original.pkce_commitment,original.pkce_ciphertext,original.state_proof_ciphertext,
 original.binding_ciphertext,statement_timestamp()-CASE WHEN seed.n%5=0 THEN interval '5 minutes' ELSE interval '20 minutes' END,
 statement_timestamp()-CASE WHEN seed.n%5=0 THEN interval '-5 minutes' ELSE interval '10 minutes' END,1
 FROM callback_query_seed seed CROSS JOIN oauth_rp.transactions original WHERE original.transaction_id=$1`,
		`ANALYZE oauth_rp.transactions`,
	} {
		var args []any
		if strings.Contains(statement, "generate_series") {
			args = []any{string(request.TenantID)}
		} else if strings.Contains(statement, "CROSS JOIN") {
			args = []any{phase.input.binding().RecordID}
		}
		if _, err := db.Exec(ctx, statement, args...); err != nil {
			t.Fatal("representative RP storage seed failed", err)
		}
	}
	var engine string
	var total, hot, expired int
	if err := db.QueryRow(ctx, `SELECT version()`).Scan(&engine); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id=$1),count(*) FILTER(WHERE expires_at<clock_timestamp()) FROM oauth_rp.transactions`, string(request.TenantID)).Scan(&total, &hot, &expired); err != nil || total != 100001 || hot != 90001 || expired != 80000 {
		t.Fatal("representative cardinality/skew missing", err)
	}
	t.Logf("engine=%s rows=%d hot_tenant=%d expired=%d; isolated loopback, warm sequential client, no competing fixture load", engine, total, hot, expired)
	for _, statement := range []string{
		`SELECT column_name||'='||udt_schema||'.'||udt_name FROM information_schema.columns WHERE table_schema='oauth_rp' AND table_name='transactions' ORDER BY ordinal_position`,
		`SELECT indexdef FROM pg_indexes WHERE schemaname='oauth_rp' AND tablename='transactions' ORDER BY indexname`,
	} {
		rows, err := db.Query(ctx, statement)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var metadata string
			if err := rows.Scan(&metadata); err != nil {
				t.Fatal(err)
			}
			t.Log(metadata)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
	}

	trace := &callbackOperationQueryTrace{}
	connectionConfig := db.Config().ConnConfig
	pool, err := database.Connect(ctx, database.Config{DSN: connectionConfig.ConnString(), MaxConns: 1, Configure: func(config *database.PoolConfig) error {
		config.ConnConfig.Database = connectionConfig.Database
		config.ConnConfig.Tracer = trace
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := pool.Close(cleanup); err != nil {
			t.Error("traced fixture pool cleanup failed", err)
		}
	})
	phase.service.pool = pool
	phase.service.config = func() LinkServiceConfig { return c }
	query := strings.ReplaceAll(callbackOperationSQL, "@schema@", rpQuotedSchema(c.Schema))
	t.Logf("exact native SQL: %s", query)

	for _, test := range []struct {
		name   string
		keys   int
		change string
		want   string
	}{
		{"single-current-match", 1, "", "identity.account.link-start"},
		{"single-no-match", 1, "missing", ""},
		{"rotated-match", 2, "", "identity.account.link-start"},
		{"maximum-retained-match", 32, "", "identity.account.link-start"},
		{"maximum-retained-no-match", 32, "missing", ""},
		{"foreign-tenant", 32, "tenant", ""},
		{"foreign-provider", 1, "provider", ""},
		{"expired-match", 1, "expired", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			// The original row remains on the retained first key while the
			// current key rotates; configured maximum retention is 32 keys.
			c.StateKeys = map[uint32][32]byte{out.Binding.StateKeyVersion: c.StateKeys[out.Binding.StateKeyVersion]}
			for version := uint32(2); version <= uint32(test.keys); version++ {
				c.StateKeys[version] = [32]byte{byte(version)}
			}
			c.CurrentStateKeyVersion = uint32(test.keys)
			tenant, callback := request.TenantID, request.Callback
			if test.change == "tenant" {
				tenant = identity.TenantID("foreign-tenant")
			}
			if test.change == "missing" {
				callback, err = oauth.ParseQueryCallback(ctx, (url.Values{"code": {"synthetic"}, "state": {base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{111}, 32))}, "iss": {profile.Issuer}}).Encode(), profile)
				if err != nil {
					t.Fatal(err)
				}
				defer callback.Destroy()
			}
			if test.change == "provider" {
				if _, err := db.Exec(ctx, `UPDATE oauth_rp.transactions SET provider_id='foreign-provider' WHERE tenant_id=$1 AND transaction_id=$2`, string(request.TenantID), phase.input.binding().RecordID); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := db.Exec(ctx, `UPDATE oauth_rp.transactions SET provider_id=$3 WHERE tenant_id=$1 AND transaction_id=$2`, string(request.TenantID), phase.input.binding().RecordID, profile.ID); err != nil {
						t.Error(err)
					}
				}()
			}
			if test.change == "expired" {
				if _, err := db.Exec(ctx, `UPDATE oauth_rp.transactions SET issued_at=statement_timestamp()-interval '20 minutes',expires_at=statement_timestamp()-interval '10 minutes' WHERE tenant_id=$1 AND transaction_id=$2`, string(request.TenantID), phase.input.binding().RecordID); err != nil {
					t.Fatal(err)
				}
			}
			var samples []time.Duration
			for iteration := 0; iteration < 31; iteration++ {
				trace.count = 0
				start := time.Now()
				operation, err := phase.service.CallbackOperation(ctx, tenant, callback)
				elapsed := time.Since(start)
				if operation != test.want || (err != nil) != (test.want == "") || trace.count != 1 || trace.sql != query {
					t.Fatalf("native result/query amplification mismatch: operation=%q err=%v queries=%d", operation, err, trace.count)
				}
				if iteration > 0 {
					samples = append(samples, elapsed)
				}
			}
			slices.Sort(samples)
			var goTypes []string
			for _, binding := range trace.args {
				goTypes = append(goTypes, fmt.Sprintf("%T", binding))
			}
			if !reflect.DeepEqual(goTypes, []string{"string", "string", "[]int64", "[][]uint8", "uint64", "string", "string", "string"}) {
				t.Fatal("native binding types changed", goTypes)
			}
			if len(trace.args[2].([]int64)) != test.keys || len(trace.args[3].([][]byte)) != test.keys {
				t.Fatal("retained-key bound missing")
			}
			conn, err := db.Acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := conn.Conn().Prepare(ctx, "callback_operation_query_gate", query)
			conn.Release()
			if err != nil || !reflect.DeepEqual(prepared.ParamOIDs, []uint32{25, 25, 1016, 1001, 1700, 25, 25, 25}) {
				t.Fatal("parameter/column compatibility changed", err)
			}
			var plan []byte
			if err := db.QueryRow(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+query, trace.args...).Scan(&plan); err != nil {
				t.Fatal(err)
			}
			var explained []struct{ Plan callbackOperationQueryPlan }
			if err := json.Unmarshal(plan, &explained); err != nil || len(explained) != 1 {
				t.Fatal("execution plan unavailable", err)
			}
			index := callbackOperationStateIndex(t, explained[0].Plan)
			if index == nil || index.ActualLoops > test.keys || !strings.Contains(index.IndexCond, "state_key_version") || !strings.Contains(index.IndexCond, "state_digest") || !strings.Contains(index.IndexCond, "tenant_id") {
				t.Fatal("lookup no longer bounds work by retained keyed-state pairs")
			}
			t.Logf("keys=%d go_types=%v pg_oids=%v native_queries=1 native_rows=%d warm_n=30 median=%s min=%s max=%s; includes pool/native HMAC/roundtrip/scan overhead, excludes setup/provider exchange", test.keys, goTypes, prepared.ParamOIDs, trace.rows, samples[len(samples)/2], samples[0], samples[len(samples)-1])
			t.Logf("exact-binding plan=%s", plan)
		})
	}
}

type callbackOperationQueryTrace struct {
	count int
	sql   string
	args  []any
	rows  int64
}

func (trace *callbackOperationQueryTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	trace.count++
	trace.sql, trace.args = data.SQL, slices.Clone(data.Args)
	return ctx
}

func (trace *callbackOperationQueryTrace) TraceQueryEnd(_ context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	trace.rows = data.CommandTag.RowsAffected()
}

type callbackOperationQueryPlan struct {
	Relation    string                       `json:"Relation Name"`
	NodeType    string                       `json:"Node Type"`
	IndexCond   string                       `json:"Index Cond"`
	ActualLoops int                          `json:"Actual Loops"`
	Plans       []callbackOperationQueryPlan `json:"Plans"`
}

func callbackOperationStateIndex(t *testing.T, plan callbackOperationQueryPlan) *callbackOperationQueryPlan {
	t.Helper()
	if plan.Relation == "transactions" {
		if plan.NodeType != "Index Scan" && plan.NodeType != "Index Only Scan" {
			t.Fatal("RP lookup scanned beyond keyed-state index", plan.NodeType)
		}
		return &plan
	}
	for _, child := range plan.Plans {
		if found := callbackOperationStateIndex(t, child); found != nil {
			return found
		}
	}
	return nil
}
