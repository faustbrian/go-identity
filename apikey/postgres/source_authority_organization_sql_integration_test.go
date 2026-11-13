//go:build integration

package postgres_test

import (
	"context"
	"io"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestNativeOrganizationSourceExactKeyQueryAtDenseOwnerScale(t *testing.T) {
	f := authenticatedOrganizationSource(t)
	observed, err := f.service.ObserveOrganizationSourceAuthority(f.native.ctx, f.binding)
	if err != nil {
		t.Fatal(err)
	}
	trace := &sourceQueryTrace{queries: make(map[string]sourceQueryBindings)}
	original := f.native.pool.Raw().Config().ConnConfig
	pool, err := database.Connect(f.native.ctx, database.Config{DSN: original.ConnString(), MaxConns: 4, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = original.Database
		c.ConnConfig.RuntimeParams = maps.Clone(original.RuntimeParams)
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
			t.Error("organization query observer pool cleanup", err)
		}
	}()
	f.native.pool = pool
	scope := identity.CommandBinding{TenantID: f.binding.Owner.Spec().TenantID, ActorKind: authorization.SubjectAPIKey, ActorID: identity.ActorID(f.binding.KeyID)}
	participant := &sourceFenceConsumer{service: f.service, organization: &observed}
	coordinator, work, command, _ := prepareSourceFenceParticipant(t, f.native, participant, scope, sourceFenceScopeProbePolicy{}, f.binding.KeyID, f.binding.AuthorityVersion, observed.ValidUntil)
	started := time.Now()
	result, err := coordinator.ApplyFeature(f.native.ctx, work, command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Commit(work, result); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual source-owning Apply/final commit elapsed=%s", time.Since(started))
	trace.mu.Lock()
	queries := maps.Clone(trace.queries)
	executions, failed := trace.executions, trace.failed
	trace.mu.Unlock()
	if failed || len(queries) != 2 {
		t.Fatal("org source did not execute the two actual owned fence shapes")
	}
	var sql string
	var bindings sourceQueryBindings
	for query, selected := range queries {
		if strings.Contains(query, "identity_api_keys.keys") {
			sql, bindings = query, selected
		}
	}
	if !strings.Contains(sql, "organization_id=$4") || len(bindings.arguments) != 4 || len(bindings.oids) != 4 || len(bindings.formats) != 4 || bindings.executions != 2 {
		t.Fatal("actual org source key query lost exact owner/native bindings")
	}
	for i, value := range bindings.arguments {
		if _, ok := value.(string); !ok || bindings.oids[i] != pgtype.TextOID || bindings.formats[i] != pgtype.BinaryFormatCode {
			t.Fatal("actual organization source IDs lost native TextOID/binary binding")
		}
	}
	// Inert rows provide dense owner/tenant skew, never authenticated facts.
	// Reuse unchanged config/query evidence; measure only the new org predicate.
	var record []byte
	if err := pool.Raw().QueryRow(f.native.ctx, `SELECT record FROM identity_api_keys.keys WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3`, baselineTenant, f.binding.ConfigurationAuthority.ConfigurationID, string(f.binding.KeyID)).Scan(&record); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(f.native.ctx, `INSERT INTO identity_api_keys.keys(tenant_id,configuration_id,key_id,organization_id,pepper_version,lookup_digest,record)
SELECT $1,$2,'org-source-scale-'||n::text,$3,1,sha256(convert_to('inert-org-source-'||n::text,'UTF8')),$4 FROM generate_series(1,10000) n`, baselineTenant, f.binding.ConfigurationAuthority.ConfigurationID, string(f.id), record); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(f.native.ctx, `ANALYZE identity_api_keys.keys`); err != nil {
		t.Fatal(err)
	}
	var server string
	if err := pool.Raw().QueryRow(f.native.ctx, `SELECT current_setting('server_version')`).Scan(&server); err != nil {
		t.Fatal(err)
	}
	t.Logf("PostgreSQL %s; isolated 10001 keys in exact tenant/config/org; existing text(directory_id) primary(tenant_id,configuration_id,key_id); real coordinator protocol executions=%d, changed key query twice", server, executions)
	cases := map[string][]any{"present": slices.Clone(bindings.arguments), "absent-key": slices.Clone(bindings.arguments), "absent-tenant": slices.Clone(bindings.arguments), "absent-profile": slices.Clone(bindings.arguments), "foreign-owner": slices.Clone(bindings.arguments)}
	cases["absent-key"][2] = "missing-org-source-key"
	cases["absent-tenant"][0] = "missing-org-source-tenant"
	cases["absent-profile"][1] = "missing-org-source-profile"
	cases["foreign-owner"][3] = "foreign-org-source-owner"
	for name, args := range cases {
		measureSourceQuery(t, f.native, sql, name, bindings, args, name == "present")
	}
}
