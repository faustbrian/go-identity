//go:build integration

package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
)

type neverVelocityStore struct{}

func (neverVelocityStore) Mutate(context.Context, risk.CounterCommand) (risk.CounterResult, error) {
	panic("journal dispatched counter store")
}

func testVelocityJournal(t *testing.T, ctx context.Context, dsn, databaseName string) {
	t.Helper()
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 4, Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = databaseName; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		if err := pool.Close(cleanup); err != nil {
			t.Error("journal pool cleanup")
		}
	}()
	policyConfig := protectedConfig(t).CommandCounters
	older, err := risk.NewCounterDigestKey(6, wrappingKey(6))
	if err != nil {
		t.Fatal(err)
	}
	policyConfig.Keys = append(policyConfig.Keys, older)
	cfg := VelocityJournalConfig{Pool: pool, Schema: "risk_store", Namespace: "reference/test", JournalKey: wrappingKey(5), Policy: policyConfig.Policy, Keys: policyConfig.Keys, Timeout: time.Second}
	journal, err := NewVelocityJournal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(attempt string, subject risk.Subject, phase risk.Phase) risk.CounterCommand {
		var preparedAt time.Time
		if err := pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&preparedAt); err != nil {
			t.Fatal(err)
		}
		coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: cfg.Policy, Keys: cfg.Keys, Store: neverVelocityStore{}, Clock: func() time.Time { return preparedAt }, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		op := risk.Action("identity.password.signin")
		if phase == risk.BeforeReturn {
			op = "identity.profile.get"
		}
		command, err := coordinator.Prepare(risk.Context{Tenant: "native-tenant", Operation: op, Attempt: attempt}, subject, phase)
		if err != nil {
			t.Fatal(err)
		}
		return command
	}
	subject := risk.Subject{Network: "2001:db8::1", Device: "device", IdentifierDigest: strings.Repeat("a", 64)}
	command := prepare("logical-attempt", subject, risk.BeforeCredential)
	var handles [4]VelocityAttempt
	var failures [4]error
	var wg sync.WaitGroup
	for i := range handles {
		wg.Add(1)
		go func() { defer wg.Done(); handles[i], failures[i] = journal.RecordAttempt(ctx, command) }()
	}
	wg.Wait()
	winners := 0
	for i, h := range handles {
		if failures[i] == nil {
			if h.state == nil || h.state.owner != journal.state {
				t.Fatal("foreign receipt")
			}
			winners++
		} else {
			var unavailable identity.UnavailableError
			if !errors.As(failures[i], &unavailable) || h.state != nil {
				t.Fatal("unsafe concurrent replay", failures[i])
			}
		}
	}
	if winners != 1 {
		t.Fatal("duplicate intent winners", winners)
	}
	var count, aliases, snapshots int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM risk_store.velocity_attempts WHERE tenant_id='native-tenant'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("journal duplicated", err)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM risk_store.velocity_aliases a JOIN risk_store.velocity_attempts v USING(sequence) WHERE v.tenant_id='native-tenant'`).Scan(&aliases); err != nil || aliases != 8 {
		t.Fatal("incomplete pending intent", err)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM risk_store.velocity_snapshots a JOIN risk_store.velocity_attempts v USING(sequence) WHERE v.tenant_id='native-tenant'`).Scan(&snapshots); err != nil || snapshots != 0 {
		t.Fatal("journal fabricated snapshot", err)
	}
	var before string
	if err := pool.Raw().QueryRow(ctx, `SELECT row_to_json(v)::text FROM risk_store.velocity_attempts v WHERE tenant_id='native-tenant'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if h, err := journal.RecordAttempt(ctx, prepare("logical-attempt", subject, risk.BeforeCredential)); err == nil || h.state != nil {
		t.Fatal("pending replay permitted redispatch")
	}
	subject.Device = "different"
	if _, err := journal.RecordAttempt(ctx, prepare("logical-attempt", subject, risk.BeforeCredential)); !errors.Is(err, risk.ErrInvalidCounterCommand) {
		t.Fatal("changed intent replay admitted", err)
	}
	var after string
	if err := pool.Raw().QueryRow(ctx, `SELECT row_to_json(v)::text FROM risk_store.velocity_attempts v WHERE tenant_id='native-tenant'`).Scan(&after); err != nil || after != before {
		t.Fatal("replay refreshed or altered pending intent", err)
	}
	foreign := cfg
	foreign.Policy = protectedConfig(t).CommandCounters.Policy
	foreignJournal, err := NewVelocityJournal(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreignJournal.RecordAttempt(ctx, command); !errors.Is(err, risk.ErrInvalidCounterCommand) {
		t.Fatal("foreign policy accepted", err)
	}
	foreign = cfg
	foreign.Keys = append([]risk.CounterDigestKey(nil), cfg.Keys...)
	foreign.Keys[0], err = risk.NewCounterDigestKey(7, wrappingKey(7))
	if err != nil {
		t.Fatal(err)
	}
	foreignJournal, err = NewVelocityJournal(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreignJournal.RecordAttempt(ctx, command); !errors.Is(err, risk.ErrInvalidCounterCommand) {
		t.Fatal("foreign secret custody admitted", err)
	}
	protected, err := risk.NewCommandCounterPolicy(*policyConfig)
	if err != nil {
		t.Fatal(err)
	}
	protectedCommand, err := protected.Prepare(risk.Context{Tenant: "native-tenant", Operation: "identity.password.change", Attempt: "protected"}, risk.Subject{User: "user", Session: "session", Network: "2001:db8::1"}, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.RecordAttempt(ctx, protectedCommand); !errors.Is(err, risk.ErrInvalidCounterCommand) {
		t.Fatal("protected lane admitted", err)
	}
	for _, mutate := range []func(*VelocityJournalConfig){
		func(c *VelocityJournalConfig) { c.Schema = "public" }, func(c *VelocityJournalConfig) { c.Namespace = "" },
		func(c *VelocityJournalConfig) { c.JournalKey = make([]byte, 32) }, func(c *VelocityJournalConfig) { c.Timeout = 0 },
		func(c *VelocityJournalConfig) { c.Policy = risk.Policy{} }, func(c *VelocityJournalConfig) { c.Keys = nil },
		func(c *VelocityJournalConfig) { c.Keys = []risk.CounterDigestKey{{}} }, func(c *VelocityJournalConfig) { c.Keys = []risk.CounterDigestKey{cfg.Keys[0], cfg.Keys[0]} },
	} {
		bad := cfg
		mutate(&bad)
		if _, err := NewVelocityJournal(bad); err == nil {
			t.Fatal("invalid custody accepted")
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := journal.RecordAttempt(canceled, command); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	if _, err := journal.RecordAttempt(nil, command); err == nil {
		t.Fatal("nil context admitted")
	}
	neutral := prepare("read-attempt", risk.Subject{User: "user"}, risk.BeforeReturn)
	if _, err := journal.RecordAttempt(ctx, neutral); err != nil {
		t.Fatal("read profile rejected", err)
	}
	// A failure after the journal row/target is inserted must roll back the prefix.
	if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION risk_store.reject_velocity_alias() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic failure'; END $$; CREATE TRIGGER reject_velocity_alias BEFORE INSERT ON risk_store.velocity_aliases FOR EACH ROW EXECUTE FUNCTION risk_store.reject_velocity_alias()`); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.RecordAttempt(ctx, prepare("failed-attempt", subject, risk.BeforeCredential)); err == nil {
		t.Fatal("injected failure ignored")
	}
	if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER reject_velocity_alias ON risk_store.velocity_aliases; DROP FUNCTION risk_store.reject_velocity_alias()`); err != nil {
		t.Fatal(err)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM risk_store.velocity_attempts WHERE tenant_id='native-tenant'`).Scan(&count); err != nil || count != 2 {
		t.Fatal("partial intent survived rollback", err)
	}
	testVelocityResults(t, ctx, pool, journal, cfg, prepare, dsn, databaseName)
	testVelocityRecovery(t, ctx, pool, journal, cfg, dsn, databaseName)
	testVelocityWriterFence(t, ctx, pool, cfg, dsn, databaseName)
	testVelocityIntegrity(t, ctx, journal, cfg)
	testVelocityPage(t, ctx, journal, cfg, dsn, databaseName)
	testVelocityOwnedHistory(t, ctx, journal, cfg)
	testVelocityAppliedAck(t, ctx, journal, cfg, dsn, databaseName)
	testVelocityClosure(t, ctx, journal, cfg)
	testVelocityCoverage(t, ctx, journal, cfg)
	testVelocityOwnedClosure(t, ctx, journal, cfg)
}
