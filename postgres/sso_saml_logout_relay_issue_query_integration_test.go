//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestSSOSAMLLogoutRelayIssuePreparationQueriesAtScale(t *testing.T) {
	ctx, pool, _ := anonymousKernelDatabase(t)
	preparation := PreparationMigrationSource{Base: MigrationSource{}, Version: 16}
	admission := AdmissionPreparationMigrationSource{Base: preparation, Version: 17}
	counter := CounterPreparationMigrationSource{Base: admission, Version: 18}
	prior := SSOSAMLIDPConfirmationPreparationErasureMigrationSource{Base: counter, Version: 19}
	history, err := (SSOSAMLLogoutRelayIssuePreparationErasureMigrationSource{Base: prior, Version: 20}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range history[len(history)-5:] {
		if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
			t.Fatal(err)
		}
	}
	_, _, spec, _, _ := samlLogoutRelayIssueFixture(t)
	b, op := spec.Binding, spec.Operation
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	scope := commandSafeFields(b, &op)
	digest, owner := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 16)
	state, opened := "pending", time.Now().UTC().Truncate(time.Microsecond)
	lease := opened.Add(time.Minute)
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
SELECT decode(md5('relay-m27-scale-'||n),'hex'),$1,$2,$3,1,$4 FROM generate_series(1,20000) n`, string(b.TenantID), b.OperationID, digest, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
VALUES($1,$2,$3,$4,1,$5)`, id, string(b.TenantID), b.OperationID, digest, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose,state,generation,attempt,lease_owner,lease_until,heartbeat_at,created_at,updated_at)
SELECT command_id,tenant_id,purpose,$3,1,1,$4,$5,$6,$6,$6
FROM identity.identity_command_id_claims WHERE tenant_id=$1 AND purpose=$2`, string(b.TenantID), b.OperationID, state, owner, lease, opened); err != nil {
		t.Fatal(err)
	}
	// Install real profile metadata, with deliberately noncompressible 64 KiB
	// custody to account for the optional-column to_jsonb guard's row cost.
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_profile=4,preparation_declaration=$2 WHERE command_id=$1`, id, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_started_generation=1,preparation_ciphertext_generation=1,
preparation_ciphertext=(SELECT decode(string_agg(md5('relay-m27-ciphertext-'||n),'' ORDER BY n),'hex') FROM generate_series(1,4096) n)
WHERE command_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	// The new purpose is eligible only on definitive terminalization, not for
	// manual removal of an unresolved preparation.
	_, err = pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_ciphertext=NULL,preparation_ciphertext_generation=NULL WHERE command_id=$1`, id)
	var guard *pgconn.PgError
	if !errors.As(err, &guard) || guard.Code != "23514" || guard.Message != "identity command preparation immutable" {
		t.Fatal("pending relay custody was not protected by the trigger", err)
	}
	if _, err := pool.Raw().Exec(ctx, `ANALYZE identity.commands; ANALYZE identity.identity_command_id_claims`); err != nil {
		t.Fatal(err)
	}
	query := pool.Raw().QueryRow
	for _, test := range []struct {
		name string
		stmt string
		args []any
		read func(context.Context, func(context.Context, string, ...any) pgx.Row, string, []any) error
	}{
		{"prepared terminal hit", optionalCommandPreparationTerminalFenceSQL, []any{id, string(b.TenantID), b.OperationID, "1", owner, true}, func(ctx context.Context, query func(context.Context, string, ...any) pgx.Row, stmt string, args []any) error {
			var matched, erasing bool
			if err := query(ctx, stmt, args...).Scan(&matched, &erasing); err != nil {
				return err
			}
			if !matched || !erasing {
				return invalidWork()
			}
			return nil
		}},
		{"predecessor ordinary terminal hit", optionalCommandPreparationTerminalFenceSQL, []any{id, string(b.TenantID), b.OperationID, "1", owner, false}, func(ctx context.Context, query func(context.Context, string, ...any) pgx.Row, stmt string, args []any) error {
			var matched, erasing bool
			if err := query(ctx, stmt, args...).Scan(&matched, &erasing); err != nil {
				return err
			}
			if !matched || erasing {
				return invalidWork()
			}
			return nil
		}},
		{"preparation recovery hit", observedRetainedPreparationSQL, []any{id, string(b.TenantID), b.OperationID, scope, digest, state, lease}, func(ctx context.Context, query func(context.Context, string, ...any) pgx.Row, stmt string, args []any) error {
			var profile int16
			var declaration []byte
			if err := query(ctx, stmt, args...).Scan(&profile, &declaration); err != nil {
				return err
			}
			if profile != 4 || !bytes.Equal(scope, declaration) {
				return invalidWork()
			}
			return nil
		}},
		{"preparation recovery changed fence", observedRetainedPreparationSQL, []any{id, string(b.TenantID), b.OperationID, scope, digest, state, lease.Add(time.Microsecond)}, func(ctx context.Context, query func(context.Context, string, ...any) pgx.Row, stmt string, args []any) error {
			var profile int16
			var declaration []byte
			err := query(ctx, stmt, args...).Scan(&profile, &declaration)
			if !errors.Is(err, pgx.ErrNoRows) {
				return invalidWork()
			}
			return nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var plan []byte
			if err := query(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+test.stmt, test.args...).Scan(&plan); err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(plan, []byte("Index Scan")) || bytes.Contains(plan, []byte("Seq Scan")) {
				t.Fatal("exact journal fence did not use an indexed lookup")
			}
			began := time.Now()
			for range 12 {
				if err := test.read(ctx, query, test.stmt, test.args); err != nil {
					t.Fatal(err)
				}
			}
			elapsed := time.Since(began)
			if elapsed >= time.Second {
				t.Fatalf("12 scoped database observations exceeded 1s: %s", elapsed)
			}
			t.Logf("20,001 same-tenant same-purpose journal rows, indexed; 12 prepared calls in %s, binding types %T/%T/%T", elapsed, test.args[0], test.args[1], test.args[2])
		})
	}
}
