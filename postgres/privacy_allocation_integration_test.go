//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Tests the private provisional SQL phase, not configured public execution,
// native session/proof consumption, contributor cuts or a runnable export.
func TestPrivacyAllocationIntegration(t *testing.T) {
	dsn := os.Getenv("IDENTITY_POSTGRES_TEST_DSN")
	config, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" {
		t.Fatal("explicit disposable loopback identity_test required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("disposable cluster unavailable")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if admin.Close(cleanup) != nil {
			t.Error("admin cleanup failed")
		}
	}()
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "privacy_allocation_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("database cleanup failed")
		}
	}()
	config.Database = name
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	base := StatusMigrationSource{Base: MigrationSource{}, Version: 10}
	runner, err := migrations.NewRunner(base, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal(err)
	}
	const canonical = "AQEBAQEBAQEBAQEBAQEBAQ"
	if _, err := db.ExecContext(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version) VALUES($1,$1,'active',3,4),('imported','01ARZ3NDEKTSV4RRFFQ69G5FAV','banned',18446744073709551615,18446744073709551615)`, canonical); err != nil {
		t.Fatal(err)
	}
	next, err := migrations.NewRunner(PrivacyExportJobMigrationSource{Base: PrivacyExportMigrationSource{Base: base, Version: 11}, Version: 12}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := next.Up(ctx); err != nil {
		t.Fatal("populated privacy upgrade failed", err)
	}
	if _, err := next.Up(ctx); err != nil {
		t.Fatal("migration replay failed", err)
	}
	var imported, status, version, authority, epoch, disposition string
	if err := db.QueryRowContext(ctx, `SELECT user_id,status,version::text,authority_version::text,privacy_epoch::text,privacy_disposition FROM identity.users WHERE tenant_id='imported'`).Scan(&imported, &status, &version, &authority, &epoch, &disposition); err != nil || imported != "01ARZ3NDEKTSV4RRFFQ69G5FAV" || status != "banned" || version != "18446744073709551615" || authority != version || epoch != "1" || disposition != "idle" {
		t.Fatal("migration rewrote existing identity", err)
	}
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 4, Configure: func(native *database.PoolConfig) error { native.ConnConfig.Database = name; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if pool.Close(cleanup) != nil {
			t.Error("pool cleanup failed")
		}
	}()
	request := func() identity.PrivacyExportRequestCommand {
		c := identity.PrivacyExportRequestCommand{Binding: identity.CommandBinding{CommandID: identity.CommandID(canonical), TenantID: identity.TenantID(canonical), UserID: identity.UserID(canonical), ActorID: identity.ActorID(canonical), ActorKind: authorization.SubjectUser, OperationID: "identity.privacy-export.request", PolicyID: "privacy-policy", PolicyVersion: 1, SchemaID: "identity-privacy-export", SchemaVersion: 1, CorrelationID: canonical}, ExpectedIdentityVersion: 3, ExpectedAuthorityVersion: 4, ExpectedPrivacyEpoch: 1, SessionID: "session", SessionVersion: 1, MaximumBytes: 256 << 20, ArtifactTTL: 24 * time.Hour}
		for _, owner := range identity.PrivacyExportContributorsV1() {
			c.Projections = append(c.Projections, identity.PrivacyExportProjectionSpecV1{ContributorID: owner, ProjectionID: identity.PrivacyExportStagedSubjectV1})
		}
		return c
	}
	reset := func() {
		t.Helper()
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active',version=3,authority_version=4,privacy_epoch=1,privacy_disposition='idle' WHERE tenant_id=$1 AND user_id=$1`, canonical); err != nil {
			t.Fatal(err)
		}
	}
	open := func(t *testing.T, c identity.PrivacyExportRequestCommand) (Work, pgx.Tx) {
		t.Helper()
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		bounded, stop := context.WithTimeout(ctx, time.Second)
		w := Work{state: &workState{tx: tx, ctx: bounded, cancel: stop, binding: c.Binding, generation: 1}}
		t.Cleanup(func() {
			invalidateWork(w)
			cleanup, done := context.WithTimeout(context.Background(), time.Second)
			defer done()
			_ = tx.Rollback(cleanup)
		})
		return w, tx
	}
	readEpoch := func() string {
		t.Helper()
		var got string
		if err := pool.Raw().QueryRow(ctx, `SELECT privacy_epoch::text FROM identity.users WHERE tenant_id=$1 AND user_id=$1`, canonical).Scan(&got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	seal := func(t *testing.T, c identity.PrivacyExportRequestCommand, a privacyAllocation, change func(*identity.PrivacyExportSnapshotSpecV1)) (identity.PrivacyExportSnapshotV1, identity.PrivacyExportEvidenceKey) {
		t.Helper()
		key, err := identity.NewPrivacyExportEvidenceKey(7, [32]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		spec := identity.PrivacyExportSnapshotSpecV1{ExportID: a.exportID, TenantID: c.Binding.TenantID, SubjectID: c.Binding.UserID, CommandID: c.Binding.CommandID, IdentityVersion: a.identityVersion, PrivacyEpoch: a.privacyEpoch, LifecycleSequence: 9, RequestedAtMicroseconds: a.requestedAtMicroseconds}
		// Synthetic cuts test storage integrity only, never owner cut provenance.
		for _, projection := range c.Projections {
			spec.Cuts = append(spec.Cuts, identity.PrivacyExportContributorCutV1{ContributorID: projection.ContributorID, ProjectionID: projection.ProjectionID, CheckpointPosition: math.MaxUint64})
		}
		if change != nil {
			change(&spec)
		}
		snapshot, err := key.SealSnapshotV1(spec)
		if err != nil {
			t.Fatal(err)
		}
		return snapshot, key
	}
	t.Run("snapshot and epoch roll back together", func(t *testing.T) {
		reset()
		c := request()
		w, tx := open(t, c)
		a, err := allocatePrivacyExport(ctx, w, c)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, key := seal(t, c, a, nil)
		receipt, err := persistPrivacyExportAllocation(ctx, w, c, snapshot, key)
		if err != nil || receipt.Status != identity.PrivacyExportQueued || receipt.Snapshot.PrivacyEpoch != 2 {
			t.Fatal("snapshot not persisted", err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.privacy_export_jobs`).Scan(&count); err != nil || count != 0 || readEpoch() != "1" {
			t.Fatal("rollback left job or epoch", err)
		}
	})
	for _, name := range []string{"no allocation", "wrong key", "changed command", "changed timestamp", "changed projection", "changed intent", "duplicate", "changed identity", "changed authority", "changed epoch", "destruction after allocation"} {
		t.Run("storage denies "+name, func(t *testing.T) {
			reset()
			c := request()
			w, tx := open(t, c)
			a, err := allocatePrivacyExport(ctx, w, c)
			if err != nil {
				t.Fatal(err)
			}
			change := func(spec *identity.PrivacyExportSnapshotSpecV1) {
				switch name {
				case "changed command":
					spec.CommandID = "AgICAgICAgICAgICAgICAg"
				case "changed timestamp":
					spec.RequestedAtMicroseconds++
				case "changed projection":
					spec.Cuts[0].ProjectionID = identity.PrivacyExportSubjectJournalV1
				}
			}
			snapshot, key := seal(t, c, a, change)
			if name == "no allocation" {
				w.state.privacyAllocation = nil
			}
			if name == "wrong key" {
				key, _ = identity.NewPrivacyExportEvidenceKey(7, [32]byte{2})
			}
			if name == "changed intent" {
				c.MaximumBytes++
			}
			changes := map[string]string{
				"changed identity":             "version=4",
				"changed authority":            "authority_version=5",
				"changed epoch":                "privacy_epoch=3",
				"destruction after allocation": "privacy_disposition='deletion-pending'",
			}
			if change := changes[name]; change != "" {
				if _, err := w.Exec(ctx, "UPDATE identity.users SET "+change+" WHERE tenant_id=$1", canonical); err != nil {
					t.Fatal(err)
				}
			}
			if name == "duplicate" {
				if _, err := persistPrivacyExportAllocation(ctx, w, c, snapshot, key); err != nil {
					t.Fatal(err)
				}
			}
			got, err := persistPrivacyExportAllocation(ctx, w, c, snapshot, key)
			if err == nil || got.Status != "" || w.usable() == nil {
				t.Fatal("invalid storage left usable Work")
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if readEpoch() != "1" {
				t.Fatal("failed storage advanced epoch")
			}
		})
	}
	t.Run("committed bytes reconstruct without changing snapshot", func(t *testing.T) {
		reset()
		c := request()
		w, tx := open(t, c)
		a, err := allocatePrivacyExport(ctx, w, c)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, key := seal(t, c, a, nil)
		want, err := persistPrivacyExportAllocation(ctx, w, c, snapshot, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := pool.Raw().Exec(ctx, `DELETE FROM identity.privacy_export_jobs`); err != nil {
				t.Error(err)
			}
		}()
		var wire, digest []byte
		var storedEpoch, status string
		if err := pool.Raw().QueryRow(ctx, `SELECT receipt,snapshot_digest,privacy_epoch::text,status FROM identity.privacy_export_jobs WHERE tenant_id=$1 AND user_id=$1 AND export_id=$2`, canonical, string(a.exportID)).Scan(&wire, &digest, &storedEpoch, &status); err != nil {
			t.Fatal(err)
		}
		var got identity.PrivacyExportRequestReceipt
		if json.Unmarshal(wire, &got) != nil || got.Snapshot.Digest != want.Snapshot.Digest || string(digest) != string(want.Snapshot.Digest[:]) || storedEpoch != "2" || status != "queued" {
			t.Fatal("snapshot changed in storage")
		}
		verified, err := key.VerifySnapshotV1(got.Snapshot)
		if err != nil || !verified.Valid() || got.Snapshot.Contributors[0].Checkpoint.Position != math.MaxUint64 || got.Snapshot.EvidenceKeyVersion != 7 || readEpoch() != "2" {
			t.Fatal("stored snapshot cannot be reconstructed", err)
		}
		c.ExpectedPrivacyEpoch = 2
		w, tx = open(t, c)
		a, err = allocatePrivacyExport(ctx, w, c)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, key = seal(t, c, a, nil)
		if got, err := persistPrivacyExportAllocation(ctx, w, c, snapshot, key); err == nil || got.Status != "" || w.usable() == nil {
			t.Fatal("command ID rebound to a second job")
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if readEpoch() != "2" {
			t.Fatal("duplicate command advanced epoch")
		}
	})
	t.Run("active cursor failure poisons work after cursor closes", func(t *testing.T) {
		reset()
		c := request()
		w, tx := open(t, c)
		rows, err := w.Query(ctx, "SELECT 1")
		if err != nil {
			t.Fatal(err)
		}
		got, allocationErr := allocatePrivacyExport(ctx, w, c)
		rows.Close()
		if allocationErr == nil || got != (privacyAllocation{}) || w.usable() == nil {
			t.Fatal("ignored allocation failure left Work usable after cursor close")
		}
		if _, err := w.Exec(ctx, "SELECT 1"); err == nil {
			t.Fatal("failed Work accepted further execution")
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if readEpoch() != "1" {
			t.Fatal("failed allocation changed privacy epoch")
		}
	})
	t.Run("rollback preserves original epoch", func(t *testing.T) {
		reset()
		c := request()
		w, tx := open(t, c)
		allocation, err := allocatePrivacyExport(ctx, w, c)
		if err != nil || allocation.privacyEpoch != 2 || allocation.identityVersion != 3 || allocation.authorityVersion != 4 || allocation.requestedAtMicroseconds <= 0 {
			t.Fatal("native allocation failed", err)
		}
		if _, err := identity.ParsePrivacyExportJobID(string(allocation.exportID)); err != nil {
			t.Fatal("invalid owner-generated export ID")
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if readEpoch() != "1" {
			t.Fatal("rollback left an allocation prefix")
		}
	})
	for _, tc := range []struct {
		name, sql string
		change    func(*identity.PrivacyExportRequestCommand)
	}{
		{name: "blocked", sql: `UPDATE identity.users SET status='banned' WHERE tenant_id=$1`},
		{name: "pending anonymization", sql: `UPDATE identity.users SET privacy_disposition='anonymization-pending' WHERE tenant_id=$1`},
		{name: "pending deletion", sql: `UPDATE identity.users SET privacy_disposition='deletion-pending' WHERE tenant_id=$1`},
		{name: "stale user", change: func(c *identity.PrivacyExportRequestCommand) { c.ExpectedIdentityVersion = 2 }},
		{name: "future authority", change: func(c *identity.PrivacyExportRequestCommand) { c.ExpectedAuthorityVersion = 5 }},
		{name: "stale privacy", sql: `UPDATE identity.users SET privacy_epoch=2 WHERE tenant_id=$1`},
		{name: "foreign tenant", change: func(c *identity.PrivacyExportRequestCommand) { c.Binding.TenantID = "AgICAgICAgICAgICAgICAg" }},
		{name: "missing subject", sql: `DELETE FROM identity.users WHERE tenant_id=$1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reset()
			c := request()
			if tc.change != nil {
				tc.change(&c)
			}
			if tc.name == "missing subject" {
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version) VALUES($1,$1,'active',3,4)`, canonical); err != nil {
						t.Fatal(err)
					}
				}()
			}
			if tc.sql != "" {
				if _, err := pool.Raw().Exec(ctx, tc.sql, canonical); err != nil {
					t.Fatal(err)
				}
			}
			w, tx := open(t, c)
			got, err := allocatePrivacyExport(ctx, w, c)
			if err == nil || got.exportID != "" || w.usable() == nil {
				t.Fatal("ineligible allocation succeeded or ignored failure remained usable")
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("same fence has one durable winner", func(t *testing.T) {
		reset()
		c := request()
		var wg sync.WaitGroup
		results := make(chan error, 2)
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				tx, err := pool.Raw().Begin(ctx)
				if err != nil {
					results <- err
					return
				}
				defer tx.Rollback(ctx)
				bounded, stop := context.WithTimeout(ctx, 2*time.Second)
				w := Work{state: &workState{tx: tx, ctx: bounded, cancel: stop, binding: c.Binding, generation: 1}}
				defer invalidateWork(w)
				_, err = allocatePrivacyExport(ctx, w, c)
				if err == nil {
					err = tx.Commit(ctx)
				}
				results <- err
			}()
		}
		wg.Wait()
		close(results)
		wins, conflicts := 0, 0
		for err := range results {
			if err == nil {
				wins++
			} else {
				var conflict identity.ConflictError
				if errors.As(err, &conflict) {
					conflicts++
				} else {
					t.Fatal("unexpected allocation race failure", err)
				}
			}
		}
		if wins != 1 || conflicts != 1 || readEpoch() != "2" {
			t.Fatal("allocation fence was not single-winner")
		}
	})
	t.Run("full width counters and terminal overflow", func(t *testing.T) {
		reset()
		max := strconv.FormatUint(math.MaxUint64, 10)
		before := strconv.FormatUint(math.MaxUint64-1, 10)
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET version=$2::text::numeric,authority_version=$2::text::numeric,privacy_epoch=$3::text::numeric WHERE tenant_id=$1`, canonical, max, before); err != nil {
			t.Fatal(err)
		}
		c := request()
		c.ExpectedIdentityVersion = math.MaxUint64
		c.ExpectedAuthorityVersion = math.MaxUint64
		c.ExpectedPrivacyEpoch = math.MaxUint64 - 1
		w, tx := open(t, c)
		got, err := allocatePrivacyExport(ctx, w, c)
		if err != nil || got.privacyEpoch != math.MaxUint64 || got.identityVersion != math.MaxUint64 || got.authorityVersion != math.MaxUint64 {
			t.Fatal("full-width counters narrowed", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		c.ExpectedPrivacyEpoch = math.MaxUint64
		w, tx = open(t, c)
		got, err = allocatePrivacyExport(ctx, w, c)
		if err == nil || got.exportID != "" || w.usable() == nil {
			t.Fatal("terminal privacy epoch wrapped")
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if readEpoch() != max {
			t.Fatal("overflow changed terminal authority")
		}
	})
	t.Run("lifecycle writer lock cannot be bypassed", func(t *testing.T) {
		reset()
		writer, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Rollback(ctx)
		if _, err := writer.Exec(ctx, `UPDATE identity.users SET privacy_disposition='deletion-pending' WHERE tenant_id=$1`, canonical); err != nil {
			t.Fatal(err)
		}
		c := request()
		w, tx := open(t, c)
		short, stop := context.WithTimeout(ctx, 20*time.Millisecond)
		defer stop()
		got, err := allocatePrivacyExport(short, w, c)
		var deadline identity.DeadlineExceededError
		if !errors.As(err, &deadline) || got.exportID != "" || w.usable() == nil {
			t.Fatal("allocation bypassed lifecycle lock")
		}
		// pgx may close the connection on a query deadline. A closed connection
		// cannot retain a transaction; do not mistake that cleanup for a live tx.
		if err := tx.Rollback(ctx); err != nil && !tx.Conn().IsClosed() {
			t.Fatal(err)
		}
		if err := writer.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		w, tx = open(t, c)
		got, err = allocatePrivacyExport(ctx, w, c)
		var denied identity.ForbiddenError
		if !errors.As(err, &denied) || got.exportID != "" {
			t.Fatal("pending destruction lost after lock", err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if readEpoch() != "1" {
			t.Fatal("denial advanced privacy authority")
		}
	})
	t.Run("domain constraints reject invalid persisted state", func(t *testing.T) {
		reset()
		for _, sql := range []string{`UPDATE identity.users SET privacy_epoch=0 WHERE tenant_id=$1`, `UPDATE identity.users SET privacy_epoch=1.5 WHERE tenant_id=$1`, `UPDATE identity.users SET privacy_epoch=18446744073709551616 WHERE tenant_id=$1`, `UPDATE identity.users SET privacy_disposition='unknown' WHERE tenant_id=$1`} {
			if _, err := pool.Raw().Exec(ctx, sql, canonical); err == nil {
				t.Fatal("invalid privacy authority persisted")
			}
		}
		if readEpoch() != "1" {
			t.Fatal("failed constraint left a prefix")
		}
	})
}
