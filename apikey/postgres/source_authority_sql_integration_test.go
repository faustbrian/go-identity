//go:build integration

package postgres_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgtype"
)

// Only these two source-fence SELECTs are captured. Their native bindings are
// nonsecret IDs; verification digests, bearers and query results are excluded.
type sourceQueryTrace struct {
	mu         sync.Mutex
	queries    map[string]sourceQueryBindings
	executions int
	failed     bool
}

type sourceQueryBindings struct {
	arguments  []any
	oids       []uint32
	formats    []int16
	executions int
}

// Work intentionally bypasses pgx.QueryTracer through PgConn.ExecParams. Observe
// only successfully sent frontend Parse/Bind frames, never received rows. Other
// Bind payloads are not decoded or retained, even during genuine key issuance.
type sourceProtocolWriter struct {
	destination io.Writer
	trace       *sourceQueryTrace
	selected    *pgproto3.Parse
}

func (w *sourceProtocolWriter) Write(data []byte) (int, error) {
	n, err := w.destination.Write(data)
	if err != nil || n != len(data) {
		return n, err
	}
	w.trace.mu.Lock()
	defer w.trace.mu.Unlock()
	for len(data) > 0 {
		// Startup is the sole untyped message; it has no selected SQL/bindings.
		if data[0] == 0 {
			break
		}
		if len(data) < 5 {
			w.trace.failed = true
			break
		}
		length := uint64(binary.BigEndian.Uint32(data[1:5]))
		if length < 4 || length+1 > uint64(len(data)) {
			w.trace.failed = true
			break
		}
		end := int(length) + 1
		body := data[5:end]
		switch data[0] {
		case 'P':
			w.selected = nil
			var parsed pgproto3.Parse
			if parsed.Decode(body) != nil {
				w.trace.failed = true
				break
			}
			key := strings.HasPrefix(parsed.Query, "SELECT record FROM identity_api_keys.keys ")
			configuration := strings.HasPrefix(parsed.Query, "SELECT authority_version::text,configuration_digest,enabled FROM identity_api_keys.configurations ")
			if (key || configuration) && strings.HasSuffix(parsed.Query, " FOR UPDATE") {
				w.selected = &parsed
			}
		case 'B':
			w.trace.executions++
			if w.selected == nil {
				break
			}
			var bound pgproto3.Bind
			if bound.Decode(body) != nil || bound.PreparedStatement != w.selected.Name || len(bound.Parameters) != len(w.selected.ParameterOIDs) {
				w.trace.failed = true
				break
			}
			arguments := make([]any, len(bound.Parameters))
			for i, value := range bound.Parameters {
				if value == nil || len(value) > 256 {
					w.trace.failed = true
					break
				}
				arguments[i] = string(value)
			}
			previous := w.trace.queries[w.selected.Query]
			w.trace.queries[w.selected.Query] = sourceQueryBindings{arguments: arguments, oids: slices.Clone(w.selected.ParameterOIDs), formats: slices.Clone(bound.ParameterFormatCodes), executions: previous.executions + 1}
			w.selected = nil
		case 'Q':
			w.trace.executions++
		}
		data = data[end:]
	}
	return n, err
}

func TestNativeSourceAuthorityExactQueriesAndFreshReadAfterExpiry(t *testing.T) {
	f := setupNativeConsumer(t)
	trace := &sourceQueryTrace{queries: make(map[string]sourceQueryBindings)}
	originalConfig := f.pool.Raw().Config().ConnConfig
	connection := originalConfig.ConnString()
	pool, err := database.Connect(f.ctx, database.Config{DSN: connection, MaxConns: 4, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = originalConfig.Database
		c.ConnConfig.RuntimeParams = maps.Clone(originalConfig.RuntimeParams)
		c.ConnConfig.BuildFrontend = func(reader io.Reader, writer io.Writer) *pgproto3.Frontend {
			return pgproto3.NewFrontend(reader, &sourceProtocolWriter{destination: writer, trace: trace})
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := pool.Close(cleanup); err != nil {
			t.Error("source observation pool cleanup failed")
		}
	}()
	f.pool = pool
	service, err := apikeypg.NewService(pool, f.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	binding := authenticatedSourceBinding(t, f, service)
	original, err := service.ObserveSourceAuthority(f.ctx, binding)
	if err != nil {
		t.Fatal(err)
	}
	trace.mu.Lock()
	clear(trace.queries)
	trace.executions, trace.failed = 0, false
	trace.mu.Unlock()
	coordinator, work, command := prepareSourceFence(t, f, service, original, false)
	result, err := coordinator.ApplyFeature(f.ctx, work, command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Commit(work, result); err != nil {
		t.Fatal(err)
	}
	trace.mu.Lock()
	queries := make(map[string]sourceQueryBindings, len(trace.queries))
	for sql, bindings := range trace.queries {
		bindings.arguments = slices.Clone(bindings.arguments)
		bindings.oids = slices.Clone(bindings.oids)
		bindings.formats = slices.Clone(bindings.formats)
		queries[sql] = bindings
	}
	executions, traceFailed := trace.executions, trace.failed
	trace.mu.Unlock()
	if traceFailed || len(queries) != 2 {
		t.Fatal("actual source fence did not execute exactly its two owned SELECT shapes")
	}
	t.Logf("complete real coordinator prepare/apply/commit: %d protocol executions; two owned source SELECT shapes called once in Apply and once at final check", executions)
	// Inert scale rows establish table volume/tenant skew only, never source
	// authentication. All accepted source facts still come from the real issued
	// row. Filler records are intentionally not offered as verified credentials.
	var wire []byte
	if err := pool.Raw().QueryRow(f.ctx, `SELECT record FROM identity_api_keys.keys WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3`, baselineTenant, binding.ConfigurationAuthority.ConfigurationID, string(binding.KeyID)).Scan(&wire); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(f.ctx, `INSERT INTO identity_api_keys.keys(tenant_id,configuration_id,key_id,user_id,pepper_version,lookup_digest,record)
 SELECT $1,$2,'source-scale-'||n::text,$3,1,sha256(convert_to('inert-source-'||n::text,'UTF8')),$4 FROM generate_series(1,100000) n`, baselineTenant, binding.ConfigurationAuthority.ConfigurationID, string(f.user), wire); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(f.ctx, `INSERT INTO identity_api_keys.configurations(tenant_id,configuration_id,configuration_digest,authority_version,enabled)
 SELECT 'source-scale-tenant-'||n::text,configuration_id,configuration_digest,1,true FROM identity_api_keys.configurations CROSS JOIN generate_series(1,100000) n WHERE tenant_id=$1 AND configuration_id=$2`, baselineTenant, binding.ConfigurationAuthority.ConfigurationID); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"identity_api_keys.keys", "identity_api_keys.configurations"} {
		if _, err := pool.Raw().Exec(f.ctx, "ANALYZE "+table); err != nil {
			t.Fatal(err)
		}
	}
	var server string
	if err := pool.Raw().QueryRow(f.ctx, `SELECT current_setting('server_version')`).Scan(&server); err != nil {
		t.Fatal(err)
	}
	t.Logf("PostgreSQL %s; 100001 keys concentrated in genuine tenant/profile/user; 100001 configurations across tenants; existing (tenant_id,configuration_id,key_id)/(tenant_id,configuration_id) primary indexes", server)
	for sql, bindings := range queries {
		args := bindings.arguments
		isKey := strings.Contains(sql, "identity_api_keys.keys")
		wantArguments := 2
		if isKey {
			wantArguments = 4
		}
		if len(args) != wantArguments || len(bindings.oids) != wantArguments || len(bindings.formats) != wantArguments || bindings.executions != 2 {
			t.Fatal("actual native source binding count changed")
		}
		for i, argument := range args {
			if _, ok := argument.(string); !ok || bindings.oids[i] != pgtype.TextOID || bindings.formats[i] != pgtype.BinaryFormatCode {
				t.Fatal("source ID binding lost native TextOID/binary encoding")
			}
		}
		cases := map[string][]any{"present": slices.Clone(args), "absent-tenant": slices.Clone(args)}
		cases["absent-tenant"][0] = "missing-source-tenant"
		if isKey {
			cases["absent-key"] = slices.Clone(args)
			cases["absent-key"][2] = "missing-source-key"
			cases["foreign-owner"] = slices.Clone(args)
			cases["foreign-owner"][3] = "foreign-source-user"
		} else {
			cases["absent-profile"] = slices.Clone(args)
			cases["absent-profile"][1] = "missing-source-profile"
		}
		for name, values := range cases {
			measureSourceQuery(t, f, sql, name, bindings, values, name == "present")
		}
	}
	// An expired observation is never renewed in place. A genuinely later
	// primary read may observe the same still-valid root under a distinct window.
	timer := time.NewTimer(max(time.Until(original.ValidUntil)+5*time.Millisecond, 0))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-f.ctx.Done():
		t.Fatal(f.ctx.Err())
	}
	if original.Validate(binding, f.config.Configuration, time.Now().UTC()) == nil {
		t.Fatal("expired original source observation remained usable")
	}
	started := time.Now()
	fresh, err := service.ObserveSourceAuthority(f.ctx, binding)
	if err != nil || !fresh.ReadStartedAt.After(original.ValidUntil) || !fresh.ValidUntil.After(original.ValidUntil) || fresh.Record.AuthorityVersion != original.Record.AuthorityVersion || !fresh.Record.ExpiresAt.Equal(binding.ExpiresAt) {
		t.Fatal("genuine later source read rewrote lineage/expiry or reused old proof", err)
	}
	if elapsed := time.Since(started); elapsed >= f.config.Configuration.Spec().MaximumRead {
		t.Fatal("scaled real source observation exceeded its configured read budget", elapsed)
	} else {
		t.Logf("scaled complete primary observation: %s", elapsed)
	}
}

func measureSourceQuery(t *testing.T, f nativeConsumerFixture, sql, name string, bindings sourceQueryBindings, args []any, present bool) {
	t.Helper()
	connection, err := f.pool.Raw().Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	values := make([][]byte, len(args))
	for i, argument := range args {
		values[i] = []byte(argument.(string))
	}
	query := func(statement string) pgx.Rows {
		return pgx.RowsFromResultReader(pgtype.NewMap(), connection.Conn().PgConn().ExecParams(f.ctx, statement, values, bindings.oids, bindings.formats, nil))
	}
	var plan []byte
	rows := query("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) " + sql)
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("source plan unavailable", rows.Err())
	}
	if err := rows.Scan(&plan); err != nil {
		t.Fatal(err)
	}
	if rows.Next() || rows.Err() != nil {
		t.Fatal("source plan result boundary changed", rows.Err())
	}
	rows.Close()
	if strings.Contains(string(plan), `"Node Type": "Seq Scan"`) || !strings.Contains(string(plan), `"Index Name"`) {
		t.Fatal("source point lookup lost indexed bounded access", name)
	}
	sanitized := string(plan)
	for i, value := range args {
		sanitized = strings.ReplaceAll(sanitized, value.(string), fmt.Sprintf("<arg%d:string>", i+1))
	}
	t.Logf("exact native SQL %s; case=%s; captured parameter OIDs=%v formats=%v; plan=%s", sql, name, bindings.oids, bindings.formats, sanitized)
	var minimum, maximum time.Duration
	for sample := 0; sample < 5; sample++ {
		started := time.Now()
		rows := query(sql)
		count := 0
		for rows.Next() {
			if _, err := rows.Values(); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			count++
		}
		err := rows.Err()
		rows.Close()
		elapsed := time.Since(started)
		if err != nil || count > 1 || present != (count == 1) {
			t.Fatal("source query result/cleanup mismatch", name, err)
		}
		if sample == 0 || elapsed < minimum {
			minimum = elapsed
		}
		maximum = max(maximum, elapsed)
	}
	t.Logf("case=%s; five exact ExecParams executions including transfer on one acquired connection; min=%s max=%s; EXPLAIN separately records examined rows/buffers", name, minimum, maximum)
}
