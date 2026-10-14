//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func testCoordinatorReservation(t *testing.T, ctx context.Context, pool *database.Pool) {
	fixture, _, raw := coordinatorFixture(t)
	config := CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}}
	c, err := NewCoordinator(pool, fixture.registry, config)
	if err != nil {
		t.Fatal(err)
	}
	config.RetainedFingerprintKeys[1] = [32]byte{9}
	// Keep this namespace independent of the private foundation fixtures.
	binding := codecBinding()
	binding.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	// Audit binding is independent of random record ID, but binds command ID.
	_, record, _ := auditFixture(t)
	record = changedAudit(t, record, func(in *audit.RecordInput) { in.Attributes["command.id"] = string(binding.CommandID) }, "", true)
	raw.Audits[0].BindingDigest, err = AuditBindingDigest(binding, record)
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: binding, Status: identity.StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := c.PrepareCommandPlan(binding, command, raw)
	if err != nil {
		t.Fatal(err)
	}
	r, result, err := c.ReserveCommand(ctx, binding, command, plan)
	if err != nil || r.state == nil || result.Outcome != identity.CommitOutcomeInProgress || result.Validate() != nil {
		t.Fatal("reservation not owned", err)
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(binding.CommandID))
	var frozen []byte
	var generation string
	if err := pool.Raw().QueryRow(ctx, `SELECT command_plan,generation::text FROM identity.commands WHERE command_id=$1`, id).Scan(&frozen, &generation); err != nil || len(frozen) == 0 || generation != "1" {
		t.Fatal("missing durable plan")
	}
	// A conflicting plan on an expired row must roll back the tentative takeover.
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	var unchangedGeneration string
	changedAfterExpiry := plan
	changedAfterExpiry.Audits = append([]AuditPlan(nil), plan.Audits...)
	changedAfterExpiry.Audits[0].MaxRecordBytes--
	changedAfterExpiry, err = c.PrepareCommandPlan(binding, command, changedAfterExpiry)
	if err != nil {
		t.Fatal(err)
	}
	var conflict identity.ConflictError
	if _, result, err := c.ReserveCommand(ctx, binding, command, changedAfterExpiry); !errors.As(err, &conflict) || result.Outcome != identity.CommitOutcomeConflict {
		t.Fatal("expired conflicting plan admitted", err)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT generation::text FROM identity.commands WHERE command_id=$1`, id).Scan(&unchangedGeneration); err != nil || unchangedGeneration != "1" {
		t.Fatal("failed admission committed takeover")
	}
	// Restore a live lease for the busy branch; the private test fixture owns it.
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()+interval '1 minute' WHERE command_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	replay, result, err := c.ReserveCommand(ctx, binding, command, plan)
	if err != nil || replay.state != nil || result.Outcome != identity.CommitOutcomeInProgress || result.Validate() != nil {
		t.Fatal("busy replay acquired authority", err)
	}
	changed := plan
	changed.Audits = append([]AuditPlan(nil), plan.Audits...)
	changed.Audits[0].MaxRecordBytes--
	changed, err = c.PrepareCommandPlan(binding, command, changed)
	if err != nil {
		t.Fatal(err)
	}
	if r, result, err := c.ReserveCommand(ctx, binding, command, changed); !errors.As(err, &conflict) || r.state != nil || result.Outcome != identity.CommitOutcomeConflict {
		t.Fatal("different frozen plan admitted", err)
	}
	rotated := config
	rotated.CurrentFingerprintKeyVersion = 2
	rotated.RetainedFingerprintKeys = map[uint32][32]byte{1: {1}, 2: {2}}
	next, err := NewCoordinator(pool, fixture.registry, rotated)
	if err != nil {
		t.Fatal(err)
	}
	nextPlan, err := next.PrepareCommandPlan(binding, command, raw)
	if err != nil || nextPlan.Digest == plan.Digest {
		t.Fatal("new key not used")
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
		t.Fatal("lease fixture failed")
	}
	takeover, result, err := next.ReserveCommand(ctx, binding, command, nextPlan)
	if err != nil || takeover.state == nil || takeover.state.journal.generation != 2 || result.Outcome != identity.CommitOutcomeInProgress {
		t.Fatal("retained-key takeover failed", err)
	}
	var after []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT command_plan FROM identity.commands WHERE command_id=$1`, id).Scan(&after); err != nil || !bytes.Equal(frozen, after) {
		t.Fatal("rotation changed frozen authority")
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET command_plan=$2 WHERE command_id=$1`, id, []byte{1}); err == nil {
		t.Fatal("frozen plan mutable")
	}
	for _, value := range [][]byte{nil, {}, make([]byte, 65537)} {
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET command_plan=$2 WHERE command_id=$1`, id, value); err == nil {
			t.Fatal("invalid replacement plan admitted")
		}
	}
	// Existing receipts are replayed only after the frozen plan still matches.
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	receipt := identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeNotCommitted}
	if err := terminalizeJournal(ctx, tx, takeover.state.request, takeover.state.journal, takeover.state.owner, receipt, "denied"); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if r, result, err := next.ReserveCommand(ctx, binding, command, nextPlan); err != nil || r.state != nil || result.Outcome != receipt.Outcome || result.Binding != binding {
		t.Fatal("historical terminal receipt lost", err)
	}
	// Missing historical key never becomes a new claim or lease generation.
	rotated.RetainedFingerprintKeys = map[uint32][32]byte{2: {2}}
	missing, err := NewCoordinator(pool, fixture.registry, rotated)
	if err != nil {
		t.Fatal(err)
	}
	var unavailable identity.UnavailableError
	if r, result, err := missing.ReserveCommand(ctx, binding, command, nextPlan); !errors.As(err, &unavailable) || r.state != nil || result.Outcome != identity.CommitOutcomeInvalid {
		t.Fatal("missing key changed claim", err)
	}
	var count int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(binding.TenantID), string(binding.UserID)).Scan(&count); err != nil || count != 0 {
		t.Fatal("reservation performed domain mutation")
	}
	// A database failure after creating a global claim and journal must roll back
	// both writes. Do not fabricate a terminal denial for unobserved commands.
	if _, err := pool.Raw().Exec(ctx, `ALTER TABLE identity.commands ADD CONSTRAINT identity_test_reject_plan CHECK(command_plan IS NULL) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	freshBinding := binding
	freshBinding.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	freshCommand, err := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: freshBinding, Status: identity.StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	freshPlan, err := c.PrepareCommandPlan(freshBinding, freshCommand, raw)
	if err != nil {
		t.Fatal(err)
	}
	if r, result, err := c.ReserveCommand(ctx, freshBinding, freshCommand, freshPlan); !errors.As(err, &unavailable) || r.state != nil || result.Outcome != identity.CommitOutcomeInvalid {
		t.Fatal("SQL rejection fabricated outcome", err)
	}
	freshID, _ := base64.RawURLEncoding.DecodeString(string(freshBinding.CommandID))
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1`, freshID).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed transaction leaked claim")
	}
	if _, err := pool.Raw().Exec(ctx, `ALTER TABLE identity.commands DROP CONSTRAINT identity_test_reject_plan`); err != nil {
		t.Fatal(err)
	}
	// Force and observe an actual unique-key wait, not merely two goroutines
	// that might execute serially. The competing caller must become busy after
	// the first complete reservation commits, never acquire another generation.
	ownerTx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ownerTx.Rollback(context.Background())
	request, err := prepareClaim(freshCommand, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	disposition, err := lockCommandClaim(ctx, ownerTx, request, c.keys)
	if err != nil || disposition != claimNew {
		t.Fatal("concurrency claim failed", err)
	}
	if _, err := reserveJournal(ctx, ownerTx, request, disposition, [16]byte{7}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := c.freezePlan(ctx, ownerTx, freshBinding, request, disposition, freshPlan); err != nil {
		t.Fatal(err)
	}
	observer, err := pgx.ConnectConfig(ctx, pool.Raw().Config().ConnConfig.Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close(context.Background())
	type competingResult struct {
		reservation Reservation
		result      identity.CommandResult
		err         error
	}
	done := make(chan competingResult, 1)
	workerCtx, stopWorker := context.WithCancel(ctx)
	go func() {
		r, result, err := c.ReserveCommand(workerCtx, freshBinding, freshCommand, freshPlan)
		done <- competingResult{r, result, err}
	}()
	joined := false
	defer func() {
		stopWorker()
		_ = ownerTx.Rollback(context.Background())
		if !joined {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Error("reservation worker did not stop")
			}
		}
	}()
	waitCtx, stopWait := context.WithTimeout(ctx, 500*time.Millisecond)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	defer stopWait()
	for {
		var blocked bool
		if err := observer.QueryRow(waitCtx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1::int=ANY(pg_blocking_pids(pid)))`, int64(ownerTx.Conn().PgConn().PID())).Scan(&blocked); err != nil {
			t.Fatal("reservation lock wait unobserved")
		}
		if blocked {
			break
		}
		select {
		case <-ticker.C:
		case <-waitCtx.Done():
			t.Fatal("reservation did not wait on global claim")
		}
	}
	if err := ownerTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case outcome := <-done:
		joined = true
		if outcome.err != nil || outcome.reservation.state != nil || outcome.result.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("concurrent replay gained authority", outcome.err)
		}
	case <-ctx.Done():
		t.Fatal("reservation worker unavailable")
	}
	// Replay identity is global, not merely tenant-scoped.
	otherBinding := binding
	otherBinding.TenantID = "tenant-b"
	otherCommand, err := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: otherBinding, Status: identity.StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	otherPlan, err := c.PrepareCommandPlan(otherBinding, otherCommand, raw)
	if err != nil {
		t.Fatal(err)
	}
	if r, result, err := c.ReserveCommand(ctx, otherBinding, otherCommand, otherPlan); !errors.As(err, &conflict) || r.state != nil || result.Outcome != identity.CommitOutcomeConflict {
		t.Fatal("cross-tenant command ID reused", err)
	}
	// A real deferred failure reaches COMMIT, not an earlier Exec error. Even
	// this server-proven rollback is conservatively Unknown after commit starts.
	if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION identity.identity_test_reject_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='test commit rejection'; END $$;
CREATE CONSTRAINT TRIGGER identity_test_reject_commit AFTER UPDATE ON identity.commands DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.command_plan IS NOT NULL) EXECUTE FUNCTION identity.identity_test_reject_commit();`); err != nil {
		t.Fatal("commit-failure fixture unavailable")
	}
	commitBinding := binding
	commitBinding.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	commitCommand, err := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: commitBinding, Status: identity.StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	commitPlan, err := c.PrepareCommandPlan(commitBinding, commitCommand, raw)
	if err != nil {
		t.Fatal(err)
	}
	if r, result, err := c.ReserveCommand(ctx, commitBinding, commitCommand, commitPlan); !errors.As(err, &unavailable) || r.state != nil || result.Outcome != identity.CommitOutcomeUnknown || result.Validate() != nil {
		t.Fatal("commit attempt not unknown", err)
	}
	commitID, _ := base64.RawURLEncoding.DecodeString(string(commitBinding.CommandID))
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1`, commitID).Scan(&count); err != nil || count != 0 {
		t.Fatal("commit rejection was retried or persisted")
	}
	if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER identity_test_reject_commit ON identity.commands; DROP FUNCTION identity.identity_test_reject_commit();`); err != nil {
		t.Fatal("commit fixture cleanup failed")
	}
}

type priorPlanHistory struct{}

func (priorPlanHistory) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (MigrationSource{}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return history[:4], nil
}

// Upgrade real migration-4 data through the owned runner; do not backfill a
// plan onto a previously executed command whose participants are unknowable.
func testCoordinatorPlanUpgrade(t *testing.T, ctx context.Context, parent *database.Pool) {
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "identity_plan_upgrade_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := parent.Raw().Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := parent.Raw().Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("upgrade database cleanup failed")
		}
	})
	config := parent.Raw().Config().ConnConfig.Copy()
	config.Database = name
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	old, err := migrations.NewRunner(priorPlanHistory{}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := old.Up(ctx); err != nil || len(result.Records()) != 4 {
		t.Fatal("old history install failed", err)
	}
	pool, err := database.Connect(ctx, database.Config{DSN: config.ConnString(), Configure: func(native *database.PoolConfig) error { native.ConnConfig.Database = name; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if pool.Close(cleanup) != nil {
			t.Error("upgrade pool cleanup failed")
		}
	}()
	fixture, command, raw := coordinatorFixture(t)
	q, err := prepareClaim(command, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	d, err := lockCommandClaim(ctx, tx, q, fixture.keys)
	if err != nil || d != claimNew {
		_ = tx.Rollback(ctx)
		t.Fatal("old claim setup failed", err)
	}
	if _, err := reserveJournal(ctx, tx, q, d, [16]byte{1}, time.Second); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	upgraded, err := migrations.NewRunner(MigrationSource{}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('old-tenant','old-user','active',1)`); err != nil {
		t.Fatal("old binary user fixture failed")
	}
	if result, err := upgraded.Up(ctx); err != nil || len(result.Records()) != 5 || result.Records()[0].Version() != 5 || result.Records()[1].Version() != 6 || result.Records()[2].Version() != 7 || result.Records()[3].Version() != 8 || result.Records()[4].Version() != 9 {
		t.Fatal("populated forward upgrade failed", err)
	}
	legacy, err := NewRepository(pool, Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if user, err := legacy.Get(ctx, identity.GetUserQuery{TenantID: "old-tenant", UserID: "old-user"}); err != nil || user.Version != 1 {
		t.Fatal("populated attribute upgrade changed old structural user")
	}
	if state, err := legacy.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: "old-tenant", UserID: "old-user", MaximumIdentifiers: 128}); err != nil || state.AuthorityVersion != 1 || len(state.Identifiers) != 0 || state.User.Version != 1 {
		t.Fatal("populated directory upgrade changed old structural user", err)
	}
	if page, err := legacy.List(ctx, identity.ListUsersQuery{TenantID: "old-tenant", Filters: identity.UserListFilters{Statuses: []identity.Status{identity.StatusActive}}, Limit: 10, ExpiresAt: time.Now().Add(time.Second)}); err != nil || len(page.Users) != 1 || page.Users[0].ID != "old-user" {
		t.Fatal("populated listing upgrade lost old user", err)
	}
	oldProfileSchema := storageSchema()
	oldProfileSchema.Fields[0].Default = identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: "not-a-backfill"}}
	profiles, err := NewRepository(pool, Config{MaximumDuration: time.Second, AttributeSchemas: []identity.AttributeSchema{oldProfileSchema}, ProfileSchema: ProfileSchemaRef{ID: "fields", Version: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if record, err := profiles.GetProfile(ctx, identity.ProfileQuery{TenantID: "old-tenant", UserID: "old-user"}); err != nil || record.Profile.ID != "old-user" || record.Profile.Name != "" || record.Profile.Image != "" || len(record.Profile.AdditionalFields) != 0 {
		t.Fatal("old structural user fabricated profile defaults", err)
	}
	var fabricated int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.user_attributes`).Scan(&fabricated); err != nil || fabricated != 0 {
		t.Fatal("attribute upgrade fabricated old values")
	}
	c, err := NewCoordinator(pool, fixture.registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := c.PrepareCommandPlan(codecBinding(), command, raw)
	if err != nil {
		t.Fatal(err)
	}
	var unavailable identity.UnavailableError
	if r, result, err := c.ReserveCommand(ctx, codecBinding(), command, plan); !errors.As(err, &unavailable) || r.state != nil || result.Outcome != identity.CommitOutcomeInvalid {
		t.Fatal("legacy plan invented", err)
	}
	var isNull bool
	if err := pool.Raw().QueryRow(ctx, `SELECT command_plan IS NULL FROM identity.commands`).Scan(&isNull); err != nil || !isNull {
		t.Fatal("legacy plan backfilled")
	}
}
