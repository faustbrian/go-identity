//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"
)

// This exercises actual migration constraints, not native replay or healthy
// publication authority. The existing populated-upgrade fixture owns the DB.
func testVelocitySchema(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	for _, table := range []string{"velocity_attempts", "velocity_snapshots", "velocity_aliases", "velocity_epochs"} {
		var count int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM risk_store."+table).Scan(&count); err != nil || count != 0 {
			t.Fatal("migration invented recovery rows", err)
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	digest := wrappingKey(1)
	args := []any{"tenant", digest, "identity.password.signin", "before_credential_or_provider_work", "1", wrappingKey(2), wrappingKey(3), now, now, int64(300000000), int64(10), "committed"}
	const insert = `INSERT INTO risk_store.velocity_attempts(tenant_id,namespace_digest,operation,phase,policy_version,attempt_digest,counter_fingerprint,prepared_at,recorded_at,window_us,attempt_limit,outcome) VALUES($1,$2,$3,$4,$5::numeric,$6,$7,$8,$9,$10,$11,$12) RETURNING sequence`
	var sequence int64
	if err := db.QueryRowContext(ctx, insert, args...).Scan(&sequence); err != nil {
		t.Fatal("ephemeral journal requires protected command", err)
	}
	if _, err := db.ExecContext(ctx, insert, args...); err == nil {
		t.Fatal("logical attempt duplicated")
	}
	foreignPolicy := append([]any(nil), args...)
	foreignPolicy[4] = "2"
	if _, err := db.ExecContext(ctx, insert, foreignPolicy...); err == nil {
		t.Fatal("changed policy created another logical attempt")
	}
	for _, tc := range []struct {
		name  string
		index int
		value any
	}{
		{"empty-tenant", 0, ""}, {"short-namespace", 1, []byte{1}}, {"zero-namespace", 1, make([]byte, 32)},
		{"unknown-operation", 2, "UPPER"}, {"protected-phase", 3, "reserve_with_owning_command"},
		{"zero-policy", 4, "0"}, {"fraction-policy", 4, "1.5"}, {"overflow-policy", 4, "18446744073709551616"},
		{"raw-attempt", 5, []byte("request")}, {"zero-fingerprint", 6, make([]byte, 32)},
		{"infinite-time", 7, "infinity"}, {"before-prepared", 8, now.Add(-time.Microsecond)},
		{"zero-window", 9, int64(0)}, {"large-window", 9, int64(3600000001)},
		{"zero-limit", 10, int64(0)}, {"large-limit", 10, int64(121)}, {"bad-outcome", 11, "allow"},
	} {
		t.Run("velocity-"+tc.name, func(t *testing.T) {
			values := append([]any(nil), args...)
			values[tc.index] = tc.value
			// Avoid uniqueness being the reason an invalid row fails.
			if tc.index != 5 {
				values[5] = wrappingKey(4)
			}
			if _, err := db.ExecContext(ctx, insert, values...); err == nil {
				t.Fatal("invalid journal row admitted")
			}
		})
	}
	read := append([]any(nil), args...)
	read[3] = "before_return"
	read[9] = int64(60000000)
	read[10] = int64(120)
	var readSequence int64
	if err := db.QueryRowContext(ctx, insert, read...).Scan(&readSequence); err != nil {
		t.Fatal("neutral read profile rejected", err)
	}
	const snapshot = `INSERT INTO risk_store.velocity_snapshots(sequence,phase,window_us,dimension,value,observed_at,started_at,expires_at) VALUES($1,$2,$3,$4,1,$5,$5,$6)`
	for _, dimension := range []string{"tenant", "canonical_network", "device", "canonical_identifier_digest"} {
		if _, err := db.ExecContext(ctx, snapshot, sequence, args[3], args[9], dimension, now, now.Add(5*time.Minute)); err != nil {
			t.Fatal("authentication dimension rejected", err)
		}
	}
	for _, dimension := range []string{"tenant", "subject_or_network"} {
		if _, err := db.ExecContext(ctx, snapshot, readSequence, read[3], read[9], dimension, now, now.Add(time.Minute)); err != nil {
			t.Fatal("read dimension rejected", err)
		}
	}
	if _, err := db.ExecContext(ctx, snapshot, readSequence, read[3], read[9], "device", now, now.Add(time.Minute)); err == nil {
		t.Fatal("cross-profile dimension admitted")
	}
	const alias = `INSERT INTO risk_store.velocity_aliases(sequence,dimension,key_rank,key_version,key_id) VALUES($1,'tenant',$2,$3,$4)`
	for version := 1; version <= 4; version++ {
		key := "rv1:" + string(rune('0'+version)) + ":" + strings.Repeat("a", 43)
		if _, err := db.ExecContext(ctx, alias, sequence, version, version, key); err != nil {
			t.Fatal("retained alias rejected", err)
		}
	}
	if _, err := db.ExecContext(ctx, alias, sequence, 5, 5, "rv1:5:"+strings.Repeat("a", 43)); err == nil {
		t.Fatal("unbounded aliases admitted")
	}
	if _, err := db.ExecContext(ctx, alias, readSequence, 1, 2, "rv1:1:"+strings.Repeat("a", 43)); err == nil {
		t.Fatal("alias version mismatch admitted")
	}
	const epoch = `INSERT INTO risk_store.velocity_epochs(tenant_id,namespace_digest,epoch,generation,maximum_window_us) VALUES('tenant',$1,$2,1,3600000000)`
	boot := digest[:16]
	if _, err := db.ExecContext(ctx, epoch, digest, boot); err != nil {
		t.Fatal("boot marker rejected", err)
	}
	var state string
	if err := db.QueryRowContext(ctx, `SELECT state FROM risk_store.velocity_epochs`).Scan(&state); err != nil || state != "unavailable" {
		t.Fatal("boot became healthy", err)
	}
	for _, statement := range []string{
		`UPDATE risk_store.velocity_epochs SET state='healthy'`,
		`UPDATE risk_store.velocity_epochs SET state='replaying'`,
		`UPDATE risk_store.velocity_epochs SET lease_owner=decode('01','hex')`,
		`UPDATE risk_store.velocity_epochs SET replay_from='infinity',replay_through='infinity'`,
		`UPDATE risk_store.velocity_epochs SET epoch=decode('01','hex')`,
		`UPDATE risk_store.velocity_epochs SET generation=0`,
	} {
		if _, err := db.ExecContext(ctx, statement); err == nil {
			t.Fatal("invalid epoch state admitted")
		}
	}
	if _, err := db.ExecContext(ctx, epoch, digest, wrappingKey(2)[:16]); err == nil {
		t.Fatal("two active epoch owners admitted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE risk_store.velocity_epochs SET state='healthy',healthy_at=$1,replay_from=$2,replay_through=$1`, now, now.Add(-time.Minute)); err == nil {
		t.Fatal("insufficient replay interval admitted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE risk_store.velocity_epochs SET state='healthy',healthy_at=$1,replay_from=$2,replay_through=$1`, now, now.Add(-time.Hour)); err != nil {
		t.Fatal("covered replay storage rejected", err)
	}
	// SQL may represent coverage; only the future native fenced reconciler can
	// prove those timestamps correspond to actual replay and publish in Valkey.
}
