//go:build integration

package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
)

func testVelocityPage(t *testing.T, ctx context.Context, journal VelocityJournal, cfg VelocityJournalConfig, dsn, databaseName string) {
	t.Helper()
	prepare := func(attempt string) risk.CounterCommand {
		var now time.Time
		if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			t.Fatal(err)
		}
		coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: cfg.Policy, Keys: cfg.Keys, Store: neverVelocityStore{}, Clock: func() time.Time { return now }, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		command, err := coordinator.Prepare(risk.Context{Tenant: "page-tenant", Operation: "identity.profile.get", Attempt: attempt}, risk.Subject{User: "user"}, risk.BeforeReturn)
		if err != nil {
			t.Fatal(err)
		}
		return command
	}
	first := prepare("first")
	receipt, err := journal.RecordAttempt(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	secondReceipt, err := journal.RecordAttempt(ctx, prepare("second"))
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := recovery.Acquire(ctx, "page-tenant", [16]byte{44})
	if err != nil {
		t.Fatal(err)
	}
	var epochBefore string
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT row_to_json(e)::text FROM risk_store.velocity_epochs e WHERE tenant_id='page-tenant' AND namespace_digest=$1`, journal.state.namespace).Scan(&epochBefore); err != nil {
		t.Fatal(err)
	}
	page, err := recovery.ReadPage(ctx, lease, VelocityReplayCursor{}, 1)
	if err != nil || len(page.Records()) != 1 {
		t.Fatal("first bounded native page", err)
	}
	var epochAfter string
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT row_to_json(e)::text FROM risk_store.velocity_epochs e WHERE tenant_id='page-tenant' AND namespace_digest=$1`, journal.state.namespace).Scan(&epochAfter); err != nil || epochAfter != epochBefore {
		t.Fatal("page advanced epoch/progress", err)
	}
	original := page.Records()[0].Projection()
	// PG-ID-01/PG-PROJ-01: recovery retains the original authenticated lookup,
	// not a new command, sequence identity or freshly derived fingerprint.
	profile, err := risk.NewVelocityReplayIdentity(cfg.Namespace, cfg.JournalKey)
	if err != nil {
		t.Fatal(err)
	}
	attemptDigest, err := profile.Attempt(first)
	if err != nil {
		t.Fatal(err)
	}
	var storedAttempt, storedFingerprint, storedNamespace []byte
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT attempt_digest,counter_fingerprint,namespace_digest FROM risk_store.velocity_attempts WHERE sequence=$1`, receipt.state.sequence).Scan(&storedAttempt, &storedFingerprint, &storedNamespace); err != nil {
		t.Fatal(err)
	}
	if original.Tenant != "page-tenant" || original.Namespace != profile.Namespace() || original.AttemptDigest != attemptDigest || original.Fingerprint != first.Bindings().Fingerprint || hex.EncodeToString(storedAttempt) != hex.EncodeToString(original.AttemptDigest[:]) || hex.EncodeToString(storedFingerprint) != original.Fingerprint || hex.EncodeToString(storedNamespace) != hex.EncodeToString(original.Namespace[:]) {
		t.Fatal("original authenticated replay binding unavailable")
	}
	legacyNamespace := velocityMAC(cfg.JournalKey, "identity-risk-velocity-namespace-v1", cfg.Namespace)
	binding := first.Bindings()
	legacyAttempt := velocityMAC(cfg.JournalKey, "identity-risk-velocity-attempt-v1", hex.EncodeToString(legacyNamespace), binding.Tenant, string(binding.Operation), string(binding.Phase), binding.Attempt)
	if hex.EncodeToString(storedNamespace) != hex.EncodeToString(legacyNamespace) || hex.EncodeToString(storedAttempt) != hex.EncodeToString(legacyAttempt) {
		t.Fatal("existing journal digest framing changed")
	}
	if original.Outcome != VelocityReplayPending || len(original.Targets) != 2 || len(original.Snapshot) != 0 || original.ID == "" {
		t.Fatal("pending facts changed")
	}
	page, err = recovery.ReadPage(ctx, lease, page.Next(), 1)
	if err != nil || len(page.Records()) != 1 || page.Records()[0].Projection().ID == original.ID {
		t.Fatal("page skipped or duplicated record", err)
	}
	page, err = recovery.ReadPage(ctx, lease, page.Next(), 1)
	if err != nil || len(page.Records()) != 0 {
		t.Fatal("current observation not empty", err)
	}
	// Lower attempt sequence is unchanged: its later result needs a new native
	// change position, not a cursor that permanently considers it consumed.
	if err := journal.RecordResult(ctx, receipt, risk.CounterUnknown, nil); err != nil {
		t.Fatal(err)
	}
	page, err = recovery.ReadPage(ctx, lease, page.Next(), 1)
	if err != nil || len(page.Records()) != 1 {
		t.Fatal("lower late declaration lost", err)
	}
	late := page.Records()[0].Projection()
	if late.ID != original.ID || late.Outcome != VelocityReplayUnknown || !late.PreparedAt.Equal(original.PreparedAt) || !late.RecordedAt.Equal(original.RecordedAt) || late.AttemptDigest != original.AttemptDigest || late.Fingerprint != original.Fingerprint || late.Tenant != original.Tenant || late.Namespace != original.Namespace {
		t.Fatal("late declaration changed original identity/time")
	}
	if _, err := journal.RecordAttempt(ctx, prepare("after-empty")); err != nil {
		t.Fatal(err)
	}
	page, err = recovery.ReadPage(ctx, lease, page.Next(), 1000)
	if err != nil || len(page.Records()) != 1 {
		t.Fatal("late insertion lost", err)
	}
	for _, batch := range []int{-1, 0, 1001} {
		if _, err := recovery.ReadPage(ctx, lease, page.Next(), batch); err == nil {
			t.Fatal("invalid batch accepted")
		}
	}
	// Exact terminal replay must not advance change ordering or redelivery.
	if err := journal.RecordResult(ctx, receipt, risk.CounterUnknown, nil); err != nil {
		t.Fatal(err)
	}
	empty, err := recovery.ReadPage(ctx, lease, page.Next(), 100)
	if err != nil || len(empty.Records()) != 0 {
		t.Fatal("idempotent declaration created another change", err)
	}
	newLease, err := recovery.Renew(ctx, lease)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := recovery.ReadPage(ctx, lease, page.Next(), 1); err == nil || got.state != nil {
		t.Fatal("superseded lease accepted")
	}
	if got, err := recovery.ReadPage(ctx, newLease, page.Next(), 1); err != nil || len(got.Records()) != 0 {
		t.Fatal("renewal lost continuation", err)
	}
	lease = newLease
	foreign, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := foreign.ReadPage(ctx, lease, page.Next(), 1); err == nil || got.state != nil {
		t.Fatal("foreign recovery accepted custody")
	}
	// A copied projection cannot mutate its source record's retained aliases.
	all, err := recovery.ReadPage(ctx, lease, VelocityReplayCursor{}, 100)
	if err != nil || len(all.Records()) != 3 {
		t.Fatal("retained pages incomplete", err)
	}
	immutable := all.Records()[0]
	view := immutable.Projection()
	expected := view.Targets[0].Keys[0].Encoded
	view.Targets[0].Keys[0].Encoded = "changed"
	if immutable.Projection().Targets[0].Keys[0].Encoded != expected {
		t.Fatal("projection aliases record")
	}
	var unavailable identity.UnavailableError
	var position int64
	var seal []byte
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT replay_position,replay_seal FROM risk_store.velocity_attempts WHERE sequence=$1`, receipt.state.sequence).Scan(&position, &seal); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct{ mutate, restore string }{
		{`UPDATE risk_store.velocity_attempts SET replay_position=replay_position+100000 WHERE sequence=$1`, `UPDATE risk_store.velocity_attempts SET replay_position=replay_position-100000 WHERE sequence=$1`},
		{`UPDATE risk_store.velocity_attempts SET outcome='not_committed' WHERE sequence=$1`, `UPDATE risk_store.velocity_attempts SET outcome='unknown' WHERE sequence=$1`},
	} {
		if _, err := cfg.Pool.Raw().Exec(ctx, change.mutate, receipt.state.sequence); err != nil {
			t.Fatal(err)
		}
		if got, err := recovery.ReadPage(ctx, lease, VelocityReplayCursor{}, 100); !errors.As(err, &unavailable) || got.state != nil {
			t.Fatal("corrupt change granted partial page", err)
		}
		if _, err := cfg.Pool.Raw().Exec(ctx, change.restore, receipt.state.sequence); err != nil {
			t.Fatal(err)
		}
	}
	// PG-AUTH-01: a valid preceding record must not escape when a later
	// record's newly projected original binding no longer matches its seal.
	for _, field := range []string{"attempt_digest", "counter_fingerprint"} {
		query := `UPDATE risk_store.velocity_attempts SET ` + field + `=set_byte(` + field + `,0,get_byte(` + field + `,0)#1) WHERE sequence=$1`
		if _, err := cfg.Pool.Raw().Exec(ctx, query, secondReceipt.state.sequence); err != nil {
			t.Fatal(err)
		}
		if got, err := recovery.ReadPage(ctx, lease, VelocityReplayCursor{}, 100); !errors.As(err, &unavailable) || got.state != nil {
			t.Fatal("unauthenticated replay binding leaked a partial page", err)
		}
		if _, err := cfg.Pool.Raw().Exec(ctx, query, secondReceipt.state.sequence); err != nil {
			t.Fatal(err)
		}
	}
	// Authenticated pre-position history is initialized, never silently lost.
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_attempts SET replay_position=NULL,position_seal=NULL WHERE sequence=$1`, receipt.state.sequence); err != nil {
		t.Fatal(err)
	}
	initialized, err := recovery.ReadPage(ctx, lease, page.Next(), 100)
	if err != nil || len(initialized.Records()) != 1 || initialized.Records()[0].Projection().ID != original.ID {
		t.Fatal("authenticated original initialization lost", err)
	}
	var newPosition int64
	var positionSeal []byte
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT replay_position,position_seal FROM risk_store.velocity_attempts WHERE sequence=$1`, receipt.state.sequence).Scan(&newPosition, &positionSeal); err != nil || newPosition <= position {
		t.Fatal("initialized position did not advance", err)
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_attempts SET replay_position=NULL,position_seal=NULL,replay_seal=NULL WHERE sequence=$1`, receipt.state.sequence); err != nil {
		t.Fatal(err)
	}
	if got, err := recovery.ReadPage(ctx, lease, VelocityReplayCursor{}, 100); !errors.As(err, &unavailable) || got.state != nil {
		t.Fatal("legacy unsigned history blessed", err)
	}
	var remainsNull bool
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT replay_position IS NULL AND position_seal IS NULL AND replay_seal IS NULL FROM risk_store.velocity_attempts WHERE sequence=$1`, receipt.state.sequence).Scan(&remainsNull); err != nil || !remainsNull {
		t.Fatal("unverifiable history changed", err)
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_attempts SET replay_position=$2,position_seal=$3,replay_seal=$4 WHERE sequence=$1`, receipt.state.sequence, newPosition, positionSeal, seal); err != nil {
		t.Fatal(err)
	}
	testVelocityPageWide(t, ctx, cfg)
	testVelocityPageCancellation(t, ctx, recovery, lease)
	testVelocityPageAfterExpiry(t, ctx, journal)
	testVelocityPageWriterFence(t, ctx, journal, cfg, dsn, databaseName)
	testVelocityPageAck(t, ctx, journal, cfg, dsn, databaseName, prepare("lost-page-ack"))
}

func testVelocityPageWriterFence(t *testing.T, ctx context.Context, journal VelocityJournal, cfg VelocityJournalConfig, dsn, databaseName string) {
	t.Helper()
	writerPool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = databaseName
		c.ConnConfig.RuntimeParams["application_name"] = "velocity-writer-fence"
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := writerPool.Close(cleanup); err != nil {
			t.Error("page writer pool cleanup")
		}
	}()
	writerCfg := cfg
	writerCfg.Pool = writerPool
	writer, err := NewVelocityJournal(writerCfg)
	if err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: cfg.Policy, Keys: cfg.Keys, Store: neverVelocityStore{}, Clock: func() time.Time { return now }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(attempt string) risk.CounterCommand {
		command, err := coordinator.Prepare(risk.Context{Tenant: "writer-fence-result", Operation: "identity.profile.get", Attempt: attempt}, risk.Subject{User: "user"}, risk.BeforeReturn)
		if err != nil {
			t.Fatal(err)
		}
		return command
	}
	command := prepare("page-overlap")
	receipt, err := writer.RecordAttempt(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := owner.Acquire(ctx, "writer-fence-result", [16]byte{49})
	if err != nil {
		t.Fatal(err)
	}
	before, err := owner.ReadPage(ctx, lease, VelocityReplayCursor{}, 1)
	if err != nil || len(before.Records()) != 1 {
		t.Fatal("pending overlap not observed", err)
	}
	var snapshot []risk.Counter
	for _, target := range command.Bindings().Targets {
		snapshot = append(snapshot, risk.Counter{Kind: string(target.Dimension), Value: 9, ObservedAt: now, WindowStartedAt: now, WindowExpiresAt: now.Add(command.Bindings().Window)})
	}
	blocker, err := cfg.Pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	type response struct {
		page VelocityReplayPage
		err  error
	}
	read := make(chan response, 1)
	writerDone, pageStarted, pageDone := false, false, false
	defer func() {
		velocityRollback(blocker)
		if !writerDone {
			<-written
		}
		if pageStarted && !pageDone {
			<-read
		}
	}()
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(99123,2)`); err != nil {
		writerDone = true
		t.Fatal(err)
	}
	go func() { written <- writer.RecordResult(ctx, receipt, risk.CounterCommitted, snapshot) }()
	waitFor := func(query string) bool {
		for i := 0; i < 40; i++ {
			if _, err := blocker.Exec(ctx, `SELECT pg_stat_clear_snapshot()`); err != nil {
				return false
			}
			var waiting bool
			if err := blocker.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event='advisory' AND query LIKE $1)`, query).Scan(&waiting); err != nil {
				return false
			}
			if waiting {
				return true
			}
			if _, err := blocker.Exec(ctx, `SELECT pg_sleep(0.005)`); err != nil {
				return false
			}
		}
		return false
	}
	if !waitFor("%velocity_attempts SET outcome=%") {
		t.Fatal("native declaration never reached latch")
	}
	// A higher visible record exists before the delayed declaration's change.
	if _, err := journal.RecordAttempt(ctx, prepare("page-higher")); err != nil {
		t.Fatal(err)
	}
	pageStarted = true
	go func() { page, err := owner.ReadPage(ctx, lease, before.Next(), 100); read <- response{page, err} }()
	if !waitFor("SELECT pg_advisory_xact_lock(%") {
		t.Fatal("page crossed unresolved native declaration")
	}
	velocityRollback(blocker)
	writeErr := <-written
	writerDone = true
	result := <-read
	pageDone = true
	if writeErr != nil || result.err != nil || len(result.page.Records()) != 2 {
		t.Fatal("overlap page incomplete", writeErr, result.err)
	}
	matched := false
	for _, record := range result.page.Records() {
		b := record.Projection()
		if b.ID == before.Records()[0].Projection().ID {
			matched = b.Outcome == VelocityReplayCommitted && len(b.Snapshot) == 2
			for _, counter := range b.Snapshot {
				matched = matched && counter.Value == 9 && counter.ObservedAt.Equal(now)
			}
		}
	}
	if !matched {
		t.Fatal("page missed lower original terminal history")
	}
}

func testVelocityPageAck(t *testing.T, ctx context.Context, journal VelocityJournal, cfg VelocityJournalConfig, dsn, databaseName string, command risk.CounterCommand) {
	t.Helper()
	receipt, err := journal.RecordAttempt(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_attempts SET replay_position=NULL,position_seal=NULL WHERE sequence=$1`, receipt.state.sequence); err != nil {
		t.Fatal(err)
	}
	faultPool, fault := newCommitAckPool(t, ctx, dsn, databaseName, nil)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := faultPool.Close(cleanup); err != nil {
			t.Error("page fault pool cleanup")
		}
	}()
	cfg.Pool = faultPool
	faultJournal, err := NewVelocityJournal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: faultJournal, MaximumWindow: time.Hour, LeaseDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	// A different trusted boot needs expiry of the earlier page owner. This
	// fixture releases that already-tested lease by authoritative database time.
	if _, err := journal.state.pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET lease_expires_at=clock_timestamp()-interval '1 microsecond' WHERE tenant_id='page-tenant' AND namespace_digest=$1`, journal.state.namespace); err != nil {
		t.Fatal(err)
	}
	lease, err := owner.Acquire(ctx, "page-tenant", [16]byte{47})
	if err != nil {
		t.Fatal(err)
	}
	fault.velocityReplay.Store(receipt.state.sequence)
	page, err := owner.ReadPage(ctx, lease, VelocityReplayCursor{}, 100)
	var unavailable identity.UnavailableError
	if !errors.As(err, &unavailable) || page.state != nil || fault.hits.Load() != 1 {
		t.Fatal("lost page ack granted records/cursor", err)
	}
	var position int64
	if err := journal.state.pool.Raw().QueryRow(ctx, `SELECT replay_position FROM risk_store.velocity_attempts WHERE sequence=$1`, receipt.state.sequence).Scan(&position); err != nil || position <= 0 {
		t.Fatal("fault did not commit native initialization", err)
	}
	if page, err := owner.ReadPage(ctx, lease, VelocityReplayCursor{}, 100); err != nil || len(page.Records()) != 4 {
		t.Fatal("page lost after real commit ambiguity", err)
	}
}

func testVelocityPageAfterExpiry(t *testing.T, ctx context.Context, journal VelocityJournal) {
	t.Helper()
	owner, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := owner.Acquire(ctx, "page-expiry", [16]byte{48})
	if err != nil {
		t.Fatal(err)
	}
	before, err := owner.ReadPage(ctx, lease, VelocityReplayCursor{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	blocker, err := journal.state.pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer velocityRollback(blocker)
	if err := owner.state.lock(ctx, blocker, "page-expiry"); err != nil {
		t.Fatal(err)
	}
	type response struct {
		page VelocityReplayPage
		err  error
	}
	finished := make(chan response, 1)
	go func() { page, err := owner.ReadPage(ctx, lease, before.Next(), 1); finished <- response{page, err} }()
	waiting := false
	for i := 0; i < 40; i++ {
		if _, err := blocker.Exec(ctx, `SELECT pg_stat_clear_snapshot()`); err != nil {
			break
		}
		if err := blocker.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event='advisory' AND query LIKE 'SELECT pg_advisory_xact_lock(%')`).Scan(&waiting); err != nil {
			break
		}
		if waiting {
			break
		}
		if _, err := blocker.Exec(ctx, `SELECT pg_sleep(0.005)`); err != nil {
			break
		}
	}
	if waiting {
		_, err = blocker.Exec(ctx, `SELECT pg_sleep(0.15)`)
	}
	velocityRollback(blocker)
	result := <-finished
	if !waiting || err != nil || result.err == nil || result.page.state != nil {
		t.Fatal("post-lock page expiry ignored", err, result.err)
	}
	newLease, err := owner.Acquire(ctx, "page-expiry", [16]byte{48})
	if err != nil {
		t.Fatal(err)
	}
	if page, err := owner.ReadPage(ctx, newLease, before.Next(), 1); err == nil || page.state != nil {
		t.Fatal("takeover reused prior generation cursor")
	}
}

func testVelocityPageWide(t *testing.T, ctx context.Context, cfg VelocityJournalConfig) {
	t.Helper()
	cfg.Namespace = "reference/page-wide"
	for _, version := range []uint32{5, 4} {
		key, err := risk.NewCounterDigestKey(version, wrappingKey(byte(version+10)))
		if err != nil {
			t.Fatal(err)
		}
		cfg.Keys = append(cfg.Keys, key)
	}
	journal, err := NewVelocityJournal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: cfg.Policy, Keys: cfg.Keys, Store: neverVelocityStore{}, Clock: func() time.Time { return now }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	command, err := coordinator.Prepare(risk.Context{Tenant: "page-wide", Operation: "identity.password.signin", Attempt: "wide"}, risk.Subject{Network: "2001:db8::1", Device: "device", IdentifierDigest: fmt.Sprintf("%064x", 1)}, risk.BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := journal.RecordAttempt(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot []risk.Counter
	for _, target := range command.Bindings().Targets {
		snapshot = append(snapshot, risk.Counter{Kind: string(target.Dimension), Value: math.MaxUint64, ObservedAt: now, WindowStartedAt: now, WindowExpiresAt: now.Add(command.Bindings().Window)})
	}
	if err := journal.RecordResult(ctx, receipt, risk.CounterCommitted, snapshot); err != nil {
		t.Fatal(err)
	}
	recovery, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := recovery.Acquire(ctx, "page-wide", [16]byte{45})
	if err != nil {
		t.Fatal(err)
	}
	page, err := recovery.ReadPage(ctx, lease, VelocityReplayCursor{}, 100)
	if err != nil || len(page.Records()) != 1 {
		t.Fatal("wide record lost", err)
	}
	b := page.Records()[0].Projection()
	profile, err := risk.NewVelocityReplayIdentity(cfg.Namespace, cfg.JournalKey)
	if err != nil {
		t.Fatal(err)
	}
	attemptDigest, err := profile.Attempt(command)
	if err != nil || b.Namespace != profile.Namespace() || b.AttemptDigest != attemptDigest || b.Tenant != "page-wide" || b.Fingerprint != command.Bindings().Fingerprint {
		t.Fatal("committed wide binding changed", err)
	}
	if b.Outcome != VelocityReplayCommitted || len(b.Targets) != 4 || len(b.Snapshot) != 4 {
		t.Fatal("wide record incomplete")
	}
	for _, target := range b.Targets {
		if len(target.Keys) != 4 {
			t.Fatal("retained aliases truncated")
		}
	}
	for _, counter := range b.Snapshot {
		if counter.Value != math.MaxUint64 || !counter.ObservedAt.Equal(now) || !counter.WindowStartedAt.Equal(now) || !counter.WindowExpiresAt.Equal(now.Add(command.Bindings().Window)) {
			t.Fatal("original unsigned snapshot changed")
		}
	}
	// This tenant does not exist in the original namespace; namespace/tenant
	// filtering must not leak the otherwise valid independently keyed record.
	otherCfg := cfg
	otherCfg.Namespace = "reference/page-empty"
	otherJournal, err := NewVelocityJournal(otherCfg)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: otherJournal, MaximumWindow: time.Hour, LeaseDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	otherLease, err := other.Acquire(ctx, "page-wide", [16]byte{46})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := other.ReadPage(ctx, otherLease, VelocityReplayCursor{}, 100); err != nil || len(got.Records()) != 0 {
		t.Fatal("namespace leaked records", err)
	}
	if got, err := other.ReadPage(ctx, otherLease, page.Next(), 100); err == nil || got.state != nil {
		t.Fatal("foreign cursor accepted")
	}
}

func testVelocityPageCancellation(t *testing.T, ctx context.Context, recovery VelocityRecovery, lease VelocityRecoveryLease) {
	t.Helper()
	blocker, err := recovery.state.journal.pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer velocityRollback(blocker)
	if err := recovery.state.lock(ctx, blocker, lease.state.tenant); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	defer cancel()
	type response struct {
		page VelocityReplayPage
		err  error
	}
	finished := make(chan response, 1)
	go func() {
		page, err := recovery.ReadPage(cancelled, lease, VelocityReplayCursor{}, 1)
		finished <- response{page, err}
	}()
	waiting := false
	for i := 0; i < 40; i++ {
		if _, err := blocker.Exec(ctx, `SELECT pg_stat_clear_snapshot()`); err != nil {
			break
		}
		if err := blocker.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event='advisory' AND query LIKE 'SELECT pg_advisory_xact_lock(%')`).Scan(&waiting); err != nil {
			break
		}
		if waiting {
			break
		}
		if _, err := blocker.Exec(ctx, `SELECT pg_sleep(0.005)`); err != nil {
			break
		}
	}
	cancel()
	velocityRollback(blocker)
	result := <-finished
	if !waiting || result.err == nil || result.page.state != nil {
		t.Fatal("cancelled page escaped lock", result.err)
	}
	if got, err := recovery.ReadPage(ctx, lease, VelocityReplayCursor{}, 1); err != nil || len(got.Records()) != 1 {
		t.Fatal("cancelled page leaked custody", err)
	}
}
