//go:build integration

package reference_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func newOAuthProxyProductionRuntimePool(t *testing.T, ctx context.Context, f liveStores) *database.Pool {
	t.Helper()
	var unique [8]byte
	if _, err := rand.Read(unique[:]); err != nil {
		t.Fatal("generate fixture-owned production runtime role", err)
	}
	role := "proxy_runtime_" + hex.EncodeToString(unique[:])
	roles := auditpg.RoleNames{Writer: role, Reader: role + "_reader", Retention: role + "_retention"}
	quoted := pgx.Identifier{role}.Sanitize()
	if _, err := f.pool.Raw().Exec(ctx, "CREATE ROLE "+quoted+" LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"); err != nil {
		t.Fatal("create isolated production runtime role", err)
	}
	var runtimePool *database.Pool
	created := []string{role}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if runtimePool != nil {
			if err := runtimePool.Close(bounded); err != nil {
				t.Error("close restricted production runtime pool", err)
			}
		}
		for _, table := range []string{"global_authorities", "tenant_authorities"} {
			name := pgx.Identifier{"identity", table}.Sanitize()
			if _, err := f.pool.Raw().Exec(bounded, "DROP POLICY IF EXISTS production_proxy_directory_read ON "+name+"; DROP POLICY IF EXISTS production_proxy_directory_lock ON "+name); err != nil {
				t.Error("release fixture-owned production directory policies", err)
			}
		}
		for _, name := range created {
			identifier := pgx.Identifier{name}.Sanitize()
			if _, err := f.pool.Raw().Exec(bounded, "DROP OWNED BY "+identifier+"; DROP ROLE "+identifier); err != nil {
				t.Error("release exact fixture-owned production role", err)
			}
		}
	})
	for _, name := range []string{roles.Reader, roles.Retention} {
		if _, err := f.pool.Raw().Exec(ctx, "CREATE ROLE "+pgx.Identifier{name}.Sanitize()+" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"); err != nil {
			t.Fatal("create isolated native audit role", err)
		}
		created = append(created, name)
	}
	auditGrants, err := auditpg.PrivilegeSQL(roles)
	if err != nil {
		t.Fatal("resolve native production audit grants", err)
	}
	if _, err := f.pool.Raw().Exec(ctx, auditGrants); err != nil {
		t.Fatal("grant native append-only production audit authority", err)
	}
	grants := []string{
		"GRANT USAGE ON SCHEMA identity, synthetic_oauth, risk_store TO " + quoted,
		"GRANT SELECT, INSERT, UPDATE ON identity.commands TO " + quoted,
		"GRANT SELECT, INSERT ON identity.identity_command_id_claims TO " + quoted,
		"GRANT UPDATE(command_id) ON identity.identity_command_id_claims TO " + quoted,
		"GRANT SELECT ON identity.global_authorities, identity.tenant_authorities TO " + quoted,
		"GRANT UPDATE(authority_id) ON identity.global_authorities TO " + quoted,
		"GRANT UPDATE(tenant_id) ON identity.tenant_authorities TO " + quoted,
		"GRANT SELECT, INSERT, UPDATE ON synthetic_oauth.proxy_transactions, public.capability_identity_one_use TO " + quoted,
		"GRANT SELECT, INSERT ON public.identity_outbox_bindings, public.outbox_messages TO " + quoted,
		"GRANT SELECT, INSERT, UPDATE ON risk_store.durable_counter_scopes, risk_store.durable_counter_windows TO " + quoted,
		"GRANT SELECT, INSERT ON risk_store.durable_counter_keys, risk_store.durable_counter_aliases, risk_store.durable_counter_attempts TO " + quoted,
		"GRANT SELECT, INSERT, UPDATE, DELETE ON public.rate_limit_states TO " + quoted,
	}
	for _, grant := range grants {
		if _, err := f.pool.Raw().Exec(ctx, grant); err != nil {
			t.Fatal("grant exact native production runtime table authority", err)
		}
	}
	// PostgreSQL 18 SELECT requires UPDATE on one column for FOR SHARE.
	// CREATE POLICY's command table permits locking through USING while its
	// UPDATE WITH CHECK denies every new row, including a key=key update.
	for _, table := range []string{"global_authorities", "tenant_authorities"} {
		name := pgx.Identifier{"identity", table}.Sanitize()
		policy := "ALTER TABLE " + name + " ENABLE ROW LEVEL SECURITY; " +
			"CREATE POLICY production_proxy_directory_read ON " + name + " FOR SELECT TO " + quoted + " USING (true); " +
			"CREATE POLICY production_proxy_directory_lock ON " + name + " FOR UPDATE TO " + quoted + " USING (true) WITH CHECK (false)"
		if _, err := f.pool.Raw().Exec(ctx, policy); err != nil {
			t.Fatal("install fixture deployment directory lock-only policies", err)
		}
	}
	runtimePool, err = database.New(ctx, database.Config{
		DSN: f.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 4,
		Configure: func(c *database.PoolConfig) error {
			c.ConnConfig.User, c.ConnConfig.Password = role, ""
			return nil
		},
	})
	if err != nil {
		t.Fatal("connect as isolated production runtime login", err)
	}
	assertOAuthProxyProductionRuntimePrivileges(t, ctx, runtimePool, role)
	for _, statement := range []string{
		"UPDATE identity.global_authorities SET authority_id=authority_id",
		"UPDATE identity.tenant_authorities SET tenant_id=tenant_id",
	} {
		_, err := runtimePool.Raw().Exec(ctx, statement)
		var denied *pgconn.PgError
		if !errors.As(err, &denied) || denied.Code != "42501" || !strings.Contains(denied.Message, "row-level security") {
			t.Fatal("directory lock-only role did not reject an actual update through its row policy")
		}
	}
	return runtimePool
}

func assertOAuthProxyProductionRuntimePrivileges(t *testing.T, ctx context.Context, pool *database.Pool, role string) {
	t.Helper()
	var isolated, noIdentityWrites, nativeAuditOnly, directoryLockOnly bool
	err := pool.Raw().QueryRow(ctx, `SELECT
 current_user=$1 AND session_user=$1 AND NOT r.rolsuper AND NOT r.rolbypassrls AND
 NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication AND
 NOT EXISTS (SELECT FROM pg_catalog.pg_auth_members WHERE member=r.oid) AND
 NOT EXISTS (SELECT FROM pg_catalog.pg_class WHERE relowner=r.oid) AND
 NOT EXISTS (SELECT FROM pg_catalog.pg_namespace WHERE nspowner=r.oid) AND
 NOT EXISTS (SELECT FROM pg_catalog.pg_database WHERE datname=current_database() AND datdba=r.oid),
 NOT has_table_privilege(current_user,'identity.users','INSERT,UPDATE,DELETE,TRUNCATE') AND
 NOT has_any_column_privilege(current_user,'identity.users','INSERT,UPDATE') AND
 NOT has_schema_privilege(current_user,'identity','CREATE') AND
 to_regclass('identity.accounts') IS NULL AND to_regnamespace('session_store') IS NULL,
 has_schema_privilege(current_user,'audit','USAGE') AND
 has_function_privilege(current_user,'audit.append_identity_record(text,bytea,integer,numeric,bytea,bytea)','EXECUTE') AND
 has_function_privilege(current_user,'audit.identity_record_status(text,bytea,integer,numeric,bytea)','EXECUTE') AND
 NOT has_table_privilege(current_user,'audit.records','SELECT,INSERT,UPDATE,DELETE,TRUNCATE') AND
 NOT has_table_privilege(current_user,'audit.identity_command_bindings','SELECT,INSERT,UPDATE,DELETE,TRUNCATE'),
 has_column_privilege(current_user,'identity.global_authorities','authority_id','UPDATE') AND
 has_column_privilege(current_user,'identity.tenant_authorities','tenant_id','UPDATE') AND
 NOT has_column_privilege(current_user,'identity.global_authorities','version','UPDATE') AND
 NOT has_column_privilege(current_user,'identity.tenant_authorities','version','UPDATE') AND
 NOT has_column_privilege(current_user,'identity.tenant_authorities','enabled','UPDATE') AND
 (SELECT relrowsecurity FROM pg_catalog.pg_class WHERE oid='identity.global_authorities'::regclass) AND
 (SELECT relrowsecurity FROM pg_catalog.pg_class WHERE oid='identity.tenant_authorities'::regclass)
 FROM pg_catalog.pg_roles r WHERE r.rolname=current_user`, role).Scan(&isolated, &noIdentityWrites, &nativeAuditOnly, &directoryLockOnly)
	if err != nil || !isolated || !noIdentityWrites || !nativeAuditOnly || !directoryLockOnly {
		t.Fatal("actual production login is not isolated, identity-write-free, native-audit-only and directory-lock-only", err)
	}
}
