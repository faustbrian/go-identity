//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

func testOneTapStartStorage(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	b, record, provider := oneTapStorageFixture(t)
	c := Config{Schema: "session_store", MaximumDuration: time.Second}
	id := mustCommandBytes(t, b.CommandID)
	// Seed the already-reserved command lineage; the workflow's coordinator
	// owns journal admission. This fixture exercises the borrowed storage Work.
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,$3,$4,1,$5)`, id, string(b.TenantID), b.OperationID, make([]byte, 32), []byte{0xa0}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,$3)`, id, string(b.TenantID), b.OperationID); err != nil {
		t.Fatal(err)
	}
	assertEffectCounts := func(want int) {
		t.Helper()
		var flows, evidence int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2),(SELECT count(*) FROM session_store.preauth_issuances WHERE tenant_id=$1 AND command_id=$3 AND purpose=$4)`, string(b.TenantID), b.RecordID, id, b.OperationID).Scan(&flows, &evidence); err != nil || flows != want || evidence != want {
			t.Fatal("unexpected browser flow/evidence counts", flows, evidence, err)
		}
	}
	legacyCount := func() int {
		t.Helper()
		var count int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM session_store.preauth_issuances WHERE purpose='identity.session.preauth-issue'`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	legacy := legacyCount()
	if legacy == 0 {
		t.Fatal("verify forward migrations on populated legacy history")
	}
	stage := func(commit bool) error {
		t.Helper()
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if err := stagePreAuthIssue(ctx, preAuthTestTx{tx}, c, b, record, provider); err != nil {
			return err
		}
		if commit {
			return tx.Commit(ctx)
		}
		return tx.Rollback(ctx)
	}
	var oldConstraint *pgconn.PgError
	if err := stage(false); !errors.As(err, &oldConstraint) || oldConstraint.Code != "23514" {
		t.Fatal("old schema did not reproduce the evidence-write failure", err)
	}
	assertEffectCounts(0)
	history, err := (OneTapStartPreAuthMigrationSource{Schema: c.Schema, Version: 70, ValidationVersion: 71}).Load(ctx)
	if err != nil || len(history) != 2 {
		t.Fatal("missing separate metadata and validation steps", err)
	}
	for _, m := range history {
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, m.UpSQL()); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal("apply forward pre-auth schema", err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := stage(false); err != nil {
		t.Fatal("stage rolled back One Tap flow", err)
	}
	assertEffectCounts(0)
	if status, err := readPreAuthIssueEvidence(ctx, pool.Raw(), c, b); err != nil || status != kernel.RecoveryNotCommitted {
		t.Fatal("rolled-back evidence became committed", status, err)
	}
	if err := stage(true); err != nil {
		t.Fatal("stage committed One Tap flow", err)
	}
	assertEffectCounts(1)
	want, err := encodePreAuth(record)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadProviderPreAuth(ctx, pool.Raw(), c, b.TenantID, identity.PreAuthTransactionID(b.RecordID), provider)
	if err != nil {
		t.Fatal("native read changed original browser flow", err)
	}
	canonical, err := encodePreAuth(got)
	if err != nil || !bytes.Equal(canonical, want) {
		t.Fatal("native read changed original browser flow bytes", err)
	}
	if _, err := pool.Raw().Exec(ctx, `DELETE FROM session_store.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2`, string(b.TenantID), b.RecordID); err != nil {
		t.Fatal(err)
	}
	if status, err := readPreAuthIssueEvidence(ctx, pool.Raw(), c, b); err != nil || status != kernel.RecoveryCommitted {
		t.Fatal("flow retirement destroyed exact committed evidence", status, err)
	}
	b.PolicyVersion--
	if status, err := readPreAuthIssueEvidence(ctx, pool.Raw(), c, b); err == nil || status != kernel.RecoveryUnknown {
		t.Fatal("a different original policy version recovered committed evidence", status, err)
	}
	if legacyCount() != legacy {
		t.Fatal("optional One Tap schema changed legacy issuance evidence")
	}
}
