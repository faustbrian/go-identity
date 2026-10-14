//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"testing"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// This fixture proves the populated storage upgrade, not administrative
// authorization or native transition execution. Existing restrictions remain
// legacy intervals until the mutation owner installs attributable custody.
func testLockoutStatePopulatedUpgrade(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	const original = `SELECT jsonb_agg(jsonb_build_array(tenant_id,operation,dimension,counter_id,version,policy_version,started_at,expires_at) ORDER BY tenant_id,operation,dimension,counter_id)::text FROM risk_store.counter_lockouts`
	var before, after string
	var count, active, expired, commands int
	if err := pool.Raw().QueryRow(ctx, original).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE expires_at>clock_timestamp()),count(*) FILTER(WHERE expires_at<=clock_timestamp()),(SELECT count(*) FROM identity.commands) FROM risk_store.counter_lockouts`).Scan(&count, &active, &expired, &commands); err != nil || count < 1 || active < 1 || expired < 1 || commands < 1 {
		t.Fatal("fixture lacks populated restrictions/commands", err)
	}
	history, err := lockoutStateHistory().Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Raw().Exec(ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal("upgrade", err)
	}
	if err = pool.Raw().QueryRow(ctx, original).Scan(&after); err != nil || before != after {
		t.Fatal("upgrade reset a restriction or original interval", err)
	}
	var untouched bool
	var commandCount int
	if err = pool.Raw().QueryRow(ctx, `SELECT bool_and(record_id IS NULL AND ended_at IS NULL AND command_id IS NULL AND binding_digest IS NULL AND command_operation IS NULL),(SELECT count(*) FROM identity.commands) FROM risk_store.counter_lockouts`).Scan(&untouched, &commandCount); err != nil || !untouched || commandCount != commands {
		t.Fatal("upgrade invented native custody or changed command history", err)
	}
	for _, change := range []string{
		`ended_at=expires_at`,
		`record_id='AAAAAAAAAAAAAAAAAAAAAA'`,
		`binding_digest=decode(repeat('01',32),'hex')`,
		`record_id='AAAAAAAAAAAAAAAAAAAAAA',command_id=decode(repeat('01',16),'hex'),binding_digest=decode(repeat('02',32),'hex'),command_operation='identity.risk.end-lockout',ended_at=expires_at`,
		`record_id='AAAAAAAAAAAAAAAAAAAAAB',command_id=decode(repeat('01',16),'hex'),binding_digest=decode(repeat('02',32),'hex'),command_operation='identity.risk.start-lockout'`,
	} {
		if _, err = pool.Raw().Exec(ctx, `UPDATE risk_store.counter_lockouts SET `+change+` WHERE tenant_id='lockout-active'`); err == nil {
			t.Fatal("partial, noncanonical or foreign native transition accepted")
		}
	}
	if err = pool.Raw().QueryRow(ctx, original).Scan(&after); err != nil || before != after {
		t.Fatal("rejected mutation damaged retained state", err)
	}
	// These structural command fixtures are not executed transitions; they
	// prove complete linkage can preserve the original restriction interval.
	seed := func(operation string) []byte {
		t.Helper()
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := base64.RawURLEncoding.DecodeString(string(id))
		if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'lockout-active',$2,$3,1,$4)`, raw, operation, wrappingKey(1), []byte{1}); err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'lockout-active',$2)`, raw, operation); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	start := seed("identity.risk.start-lockout")
	end := seed("identity.risk.end-lockout")
	if _, err = pool.Raw().Exec(ctx, `UPDATE risk_store.counter_lockouts SET record_id='AAAAAAAAAAAAAAAAAAAAAA',command_id=$1,binding_digest=$2,command_operation='identity.risk.start-lockout' WHERE tenant_id='lockout-active'`, start, wrappingKey(2)); err == nil {
		t.Fatal("zero subject ID accepted as native aggregate identity")
	}
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE risk_store.counter_lockouts SET record_id=$1,command_id=$2,binding_digest=$3,command_operation='identity.risk.start-lockout' WHERE tenant_id='lockout-active'`, string(id), start, wrappingKey(2)); err != nil {
		t.Fatal("complete same-tenant start linkage rejected", err)
	}
	for _, change := range []string{
		`ended_at=expires_at`,
		`command_operation='identity.risk.end-lockout',ended_at=expires_at`,
		`command_operation='identity.risk.end-lockout'`,
		`record_id=NULL`,
	} {
		if _, err = pool.Raw().Exec(ctx, `UPDATE risk_store.counter_lockouts SET `+change+` WHERE tenant_id='lockout-active'`); err == nil {
			t.Fatal("inconsistent attributable state accepted")
		}
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE risk_store.counter_lockouts SET command_id=$1,binding_digest=$2,command_operation='identity.risk.end-lockout',ended_at=expires_at WHERE tenant_id='lockout-active'`, end, wrappingKey(3)); err != nil {
		t.Fatal("complete same-tenant end linkage rejected", err)
	}
	if err = pool.Raw().QueryRow(ctx, original).Scan(&after); err != nil || before != after {
		t.Fatal("end representation rewrote original restriction interval", err)
	}
	var ended bool
	if err = pool.Raw().QueryRow(ctx, `SELECT ended_at IS NOT NULL AND command_id=$1 AND record_id=$2 FROM risk_store.counter_lockouts WHERE tenant_id='lockout-active'`, end, string(id)).Scan(&ended); err != nil || !ended {
		t.Fatal("end linkage lost", err)
	}
}
