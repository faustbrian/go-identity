//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"os"
	"strconv"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Direct SQL is restricted to testing migration constraints. It does not prove
// native participant authorization, reservation, or terminal transition policy.
func TestRiskReservationPopulatedUpgrade(t *testing.T) {
	dsn := os.Getenv("IDENTITY_RISK_POSTGRES_TEST_DSN")
	config, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" {
		t.Fatal("explicit disposable loopback identity_test required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		if err := admin.Close(cleanup); err != nil {
			t.Error("admin cleanup")
		}
	}()
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "risk_reservation_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("owned database cleanup")
		}
	}()
	config.Database = name
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	kernel, err := (identitypostgres.MigrationSource{}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	base := IssuanceIDMigrationSource{Base: MigrationSource{Schema: "risk_store", Version: 20}, Version: 21}
	history, err := base.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	install := func(history []migrations.Migration) {
		t.Helper()
		runner, err := migrations.NewRunner(issuanceHistory(append(append([]migrations.Migration(nil), kernel...), history...)), backend)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = runner.Up(ctx); err != nil {
			t.Fatal("migration execution", err)
		}
	}
	install(history)
	seedCommand := func(tenant, purpose string) []byte {
		t.Helper()
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := base64.RawURLEncoding.DecodeString(string(id))
		if _, err = db.ExecContext(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,$3,$4,1,$5)`, raw, tenant, purpose, wrappingKey(1), []byte{1}); err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,$3)`, raw, tenant, purpose); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	cipher, err := newRecordCipher(map[string][]byte{"wrapping_v1": wrappingKey(1)}, "wrapping_v1")
	if err != nil {
		t.Fatal(err)
	}
	var bindings []identity.CommandBinding
	var records []risk.EvidenceRecord
	var envelopes [][]byte
	for index := range 2 {
		raw := seedCommand("tenant", "identity.risk.evaluate")
		issue, _ := evaluatedIssueAt(t, risk.PhoneResetInitiation, time.Now().UTC().Truncate(time.Microsecond), base64.RawURLEncoding.EncodeToString(raw))
		record, err := issue.Materialize(issue.Prepared().PreparedAt)
		if err != nil {
			t.Fatal(err)
		}
		binding := issueBinding(issue.Prepared())
		binding.RecordID = string(binding.CommandID)
		if index == 0 {
			binding.RecordID = "rei1_1_" + base64.RawURLEncoding.EncodeToString(record.IntentDigest[:])
		}
		envelope, err := cipher.seal(ctx, binding, record)
		if err != nil {
			t.Fatal(err)
		}
		digest := bindingDigest(binding)
		if _, err = db.ExecContext(ctx, `INSERT INTO risk_store.issued_evidence VALUES($1,$2,$3,$4,$5,$6,$7::numeric,$8,$9,$10,$11,$12,$13,$14,'issued',$15)`, "tenant", raw, binding.OperationID, binding.RecordID, string(binding.UserID), issue.Prepared().Binding.Purpose, strconv.FormatUint(binding.PolicyVersion, 10), int64(record.KeyVersion), digest[:], record.IntentDigest[:], record.ProofDigest[:], record.EvidenceDigest[:], record.IssuedAt, record.ExpiresAt, envelope); err != nil {
			t.Fatal(err)
		}
		bindings = append(bindings, binding)
		records = append(records, record)
		envelopes = append(envelopes, envelope)
	}
	var before string
	if err := db.QueryRowContext(ctx, `SELECT jsonb_agg(to_jsonb(e) ORDER BY record_id)::text FROM risk_store.issued_evidence e`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	// First prove the actual installed schema lacks one-use ownership.
	if _, err := db.ExecContext(ctx, `UPDATE risk_store.issued_evidence SET state='reserved' WHERE record_id=$1`, bindings[0].RecordID); err == nil {
		t.Fatal("baseline unexpectedly permits ownerless reservation")
	}
	upgraded, err := (ReservationMigrationSource{Base: base, Version: 22}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	install(upgraded)
	install(upgraded)
	var unchanged bool
	if err := db.QueryRowContext(ctx, `SELECT jsonb_agg(to_jsonb(e)-ARRAY['reservation_command_id','reservation_purpose','reservation_fingerprint','reservation_generation','reserved_at'] ORDER BY record_id)=$1::jsonb FROM risk_store.issued_evidence e`, before).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("populated custody changed", err)
	}
	var owners int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM risk_store.issued_evidence WHERE num_nonnulls(reservation_command_id,reservation_purpose,reservation_fingerprint,reservation_generation,reserved_at)<>0`).Scan(&owners); err != nil || owners != 0 {
		t.Fatal("migration invented ownership", err)
	}
	for i, binding := range bindings {
		metadata := records[i]
		metadata.Reference = risk.RiskEvidenceRef{}
		if restored, err := cipher.open(ctx, binding, metadata, envelopes[i]); err != nil || restored != records[i] {
			t.Fatal("retained encrypted response lost", err)
		}
	}
	consumer := seedCommand("tenant", "identity.phone.password-reset-request")
	foreign := seedCommand("foreign", "identity.phone.password-reset-request")
	args := []any{"reserved", consumer, "identity.phone.password-reset-request", wrappingKey(2), "1", records[0].IssuedAt, bindings[0].RecordID}
	for _, tc := range []struct {
		name  string
		index int
		value any
		allow bool
	}{
		{"reserved", 0, "reserved", true}, {"finalized", 0, "finalized", true}, {"released", 0, "released", true}, {"revoked-owned", 0, "revoked", true},
		{"issued-owned", 0, "issued", false}, {"expired-owned", 0, "expired", false}, {"unknown-state", 0, "unknown", false},
		{"missing-owner", 1, nil, false}, {"foreign-tenant", 1, foreign, false}, {"short-owner", 1, []byte{1}, false},
		{"issuance-as-owner", 1, mustCommandBytes(t, bindings[0].CommandID), false},
		{"missing-purpose", 2, nil, false}, {"wrong-phase", 2, "identity.phone.password-reset-complete", false},
		{"short-fingerprint", 3, []byte{1}, false}, {"zero-fingerprint", 3, make([]byte, 32), false},
		{"zero-generation", 4, "0", false}, {"fraction-generation", 4, "1.1", false}, {"negative-generation", 4, "-1", false},
		{"max-generation", 4, "18446744073709551615", true}, {"overflow-generation", 4, "18446744073709551616", false},
		{"before-issue", 5, records[0].IssuedAt.Add(-time.Microsecond), false}, {"at-expiry", 5, records[0].ExpiresAt, false},
		{"missing-time", 5, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := append([]any(nil), args...)
			values[tc.index] = tc.value
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			_, err = tx.ExecContext(ctx, `UPDATE risk_store.issued_evidence SET state=$1,reservation_command_id=$2,reservation_purpose=$3,reservation_fingerprint=$4,reservation_generation=$5::numeric,reserved_at=$6 WHERE record_id=$7`, values...)
			if (err == nil) != tc.allow {
				t.Fatalf("ownership constraint allowance=%t: %v", tc.allow, err)
			}
		})
	}
	for _, state := range []string{"issued", "expired", "revoked", "reserved", "finalized", "released"} {
		t.Run("ownerless-"+state, func(t *testing.T) {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			_, err = tx.ExecContext(ctx, `UPDATE risk_store.issued_evidence SET state=$1 WHERE record_id=$2`, state, bindings[0].RecordID)
			allowed := state == "issued" || state == "expired" || state == "revoked"
			if (err == nil) != allowed {
				t.Fatalf("ownerless state allowance=%t: %v", allowed, err)
			}
		})
	}
	// A fresh full history uses the same constraints, not an upgrade-only schema.
	fresh, err := (ReservationMigrationSource{Base: IssuanceIDMigrationSource{Base: MigrationSource{Schema: "risk_fresh", Version: 30}, Version: 31}, Version: 32}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	install(append(append([]migrations.Migration(nil), upgraded...), fresh...))
	if _, err := db.ExecContext(ctx, `INSERT INTO risk_fresh.issued_evidence SELECT * FROM risk_store.issued_evidence`); err != nil {
		t.Fatal("fresh install lost issued-row compatibility", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE risk_fresh.issued_evidence SET state=$1,reservation_command_id=$2,reservation_purpose=$3,reservation_fingerprint=$4,reservation_generation=$5::numeric,reserved_at=$6 WHERE record_id=$7`, args...)
	if err != nil {
		t.Fatal("fresh install cannot represent ownership", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		t.Fatal("fresh install owner missing", err)
	}
}

func mustCommandBytes(t *testing.T, id identity.CommandID) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(string(id))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
