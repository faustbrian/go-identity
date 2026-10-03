//go:build integration

package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
)

// This proves transaction drain at acquisition, not completeness of future
// pages. Post-acquisition declarations remain evidence, never effect authority.
func testVelocityWriterFence(t *testing.T, ctx context.Context, pool *database.Pool, cfg VelocityJournalConfig, dsn, databaseName string) {
	t.Helper()
	writerPool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 4, Configure: func(c *database.PoolConfig) error {
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
			t.Error("writer pool cleanup")
		}
	}()
	cfg.Pool = writerPool
	cfg.Namespace = "reference/writer-fence"
	journal, err := NewVelocityJournal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(tenant, attempt string, phase risk.Phase) risk.CounterCommand {
		t.Helper()
		var now time.Time
		if err := pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			t.Fatal(err)
		}
		coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: cfg.Policy, Keys: cfg.Keys, Store: neverVelocityStore{}, Clock: func() time.Time { return now }, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		subject := risk.Subject{Network: "2001:db8::1", Device: "device", IdentifierDigest: strings.Repeat("a", 64)}
		operation := risk.Action("identity.password.signin")
		if phase == risk.BeforeReturn {
			subject = risk.Subject{User: "user"}
			operation = "identity.profile.get"
		}
		command, err := coordinator.Prepare(risk.Context{Tenant: tenant, Operation: operation, Attempt: attempt}, subject, phase)
		if err != nil {
			t.Fatal(err)
		}
		return command
	}
	// Test-owned SQL latches stop an actual native writer immediately before
	// transaction completion. No proxy manufactures a committed outcome.
	if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION risk_store.hold_velocity_writer() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF current_setting('application_name')='velocity-writer-fence' THEN
  IF TG_OP='INSERT' AND NEW.tenant_id='writer-fence-attempt' THEN PERFORM pg_advisory_xact_lock(99123,1); END IF;
  IF TG_OP='UPDATE' AND NEW.tenant_id='writer-fence-result' AND OLD.outcome='pending' AND NEW.outcome<>'pending' THEN PERFORM pg_advisory_xact_lock(99123,2); END IF;
 END IF; RETURN NEW; END $$;
 CREATE TRIGGER hold_velocity_insert BEFORE INSERT ON risk_store.velocity_attempts FOR EACH ROW EXECUTE FUNCTION risk_store.hold_velocity_writer();
 CREATE TRIGGER hold_velocity_update BEFORE UPDATE ON risk_store.velocity_attempts FOR EACH ROW EXECUTE FUNCTION risk_store.hold_velocity_writer()`); err != nil {
		t.Fatal(err)
	}

	type acquisition struct {
		lease VelocityRecoveryLease
		err   error
	}
	for _, resultWrite := range []bool{false, true} {
		tenant := "writer-fence-attempt"
		phase := risk.BeforeCredential
		latch := int32(1)
		if resultWrite {
			tenant = "writer-fence-result"
			phase = risk.BeforeReturn
			latch = 2
		}
		command := prepare(tenant, "first", phase)
		var receipt VelocityAttempt
		var snapshot []risk.Counter
		if resultWrite {
			receipt, err = journal.RecordAttempt(ctx, command)
			if err != nil {
				t.Fatal(err)
			}
			var now time.Time
			if err := pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
				t.Fatal(err)
			}
			for _, target := range command.Bindings().Targets {
				snapshot = append(snapshot, risk.Counter{Kind: string(target.Dimension), Value: 7, ObservedAt: now, WindowStartedAt: now, WindowExpiresAt: now.Add(command.Bindings().Window)})
			}
		}
		func() {
			blocker, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			written := make(chan error, 1)
			acquired := make(chan acquisition, 1)
			writerDone, acquisitionStarted, acquisitionDone := false, false, false
			defer func() {
				velocityRollback(blocker)
				if !writerDone {
					<-written
				}
				if acquisitionStarted && !acquisitionDone {
					<-acquired
				}
			}()
			if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(99123,$1)`, latch); err != nil {
				writerDone = true
				t.Fatal(err)
			}
			go func() {
				if resultWrite {
					written <- journal.RecordResult(ctx, receipt, risk.CounterCommitted, snapshot)
				} else {
					_, err := journal.RecordAttempt(ctx, command)
					written <- err
				}
			}()
			waiting := false
			for i := 0; i < 40; i++ {
				// Activity snapshots are transaction-cached; discard the previous
				// observation before asserting a new backend's actual wait.
				if _, err := blocker.Exec(ctx, `SELECT pg_stat_clear_snapshot()`); err != nil {
					t.Fatal(err)
				}
				if err := blocker.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name='velocity-writer-fence' AND wait_event='advisory' AND query LIKE '%velocity_attempts%')`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				if _, err := blocker.Exec(ctx, `SELECT pg_sleep(0.005)`); err != nil {
					t.Fatal(err)
				}
			}
			if !waiting {
				select {
				case err := <-written:
					writerDone = true
					t.Fatal("native writer returned before latch", err)
				default:
				}
				t.Fatal("native writer did not reach database latch")
			}
			// A higher sequence commits first while the lower native write remains
			// invisible. Sequence allocation cannot stand in for a commit watermark.
			var lower int64
			if resultWrite {
				lower = receipt.state.sequence
			} else if err := blocker.QueryRow(ctx, `SELECT last_value FROM risk_store.velocity_attempts_sequence_seq`).Scan(&lower); err != nil {
				t.Fatal(err)
			}
			peerCfg := cfg
			peerCfg.Pool = pool
			peer, err := NewVelocityJournal(peerCfg)
			if err != nil {
				t.Fatal(err)
			}
			higher, err := peer.RecordAttempt(ctx, prepare(tenant, "higher-visible", phase))
			if err != nil || higher.state == nil || higher.state.sequence <= lower {
				t.Fatal("late sequence fixture invalid", err)
			}
			if !resultWrite {
				var visible int64
				if err := blocker.QueryRow(ctx, `SELECT min(sequence) FROM risk_store.velocity_attempts WHERE tenant_id=$1 AND namespace_digest=$2`, tenant, journal.state.namespace).Scan(&visible); err != nil || visible != higher.state.sequence {
					t.Fatal("lower insertion was not hidden", err)
				}
			}
			acquisitionStarted = true
			go func() {
				lease, err := recovery.Acquire(ctx, tenant, [16]byte{byte(latch)})
				acquired <- acquisition{lease, err}
			}()
			var early *acquisition
			waiting = false
			for i := 0; i < 40; i++ {
				select {
				case value := <-acquired:
					early = &value
					acquisitionDone = true
				default:
				}
				if early != nil {
					break
				}
				if _, err := blocker.Exec(ctx, `SELECT pg_stat_clear_snapshot()`); err != nil {
					t.Fatal(err)
				}
				if err := blocker.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name='velocity-writer-fence' AND wait_event='advisory' AND query LIKE 'SELECT pg_advisory_xact_lock(%')`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				if _, err := blocker.Exec(ctx, `SELECT pg_sleep(0.005)`); err != nil {
					t.Fatal(err)
				}
			}
			if waiting {
				// Waiting recovery cannot globally stall another tenant or namespace.
				if _, err := journal.RecordAttempt(ctx, prepare("writer-other", "independent-"+tenant, risk.BeforeReturn)); err != nil {
					t.Fatal("tenant fence collision", err)
				}
				otherCfg := cfg
				otherCfg.Pool = pool
				otherCfg.Namespace = "reference/writer-other"
				other, err := NewVelocityJournal(otherCfg)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := other.RecordAttempt(ctx, prepare(tenant, "different-namespace", phase)); err != nil {
					t.Fatal("namespace fence collision", err)
				}
			}
			velocityRollback(blocker)
			writerError := <-written
			writerDone = true
			var recovered acquisition
			if early != nil {
				recovered = *early
			} else {
				recovered = <-acquired
				acquisitionDone = true
			}
			if !waiting || early != nil {
				t.Fatal("recovery crossed unresolved native writer")
			}
			if writerError != nil || recovered.err != nil || recovered.lease.state == nil {
				t.Fatal("writer drain failed", writerError, recovered.err)
			}
			var targets, aliases int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM risk_store.velocity_targets t JOIN risk_store.velocity_attempts a USING(sequence) WHERE a.tenant_id=$1 AND a.namespace_digest=$2`, tenant, journal.state.namespace).Scan(&targets); err != nil || targets != 2*len(command.Bindings().Targets) {
				t.Fatal("intent incomplete at recovery", err)
			}
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM risk_store.velocity_aliases t JOIN risk_store.velocity_attempts a USING(sequence) WHERE a.tenant_id=$1 AND a.namespace_digest=$2`, tenant, journal.state.namespace).Scan(&aliases); err != nil || aliases != 2*len(command.Bindings().Targets)*len(cfg.Keys) {
				t.Fatal("aliases incomplete at recovery", err)
			}
			var first int64
			if err := pool.Raw().QueryRow(ctx, `SELECT min(sequence) FROM risk_store.velocity_attempts WHERE tenant_id=$1 AND namespace_digest=$2`, tenant, journal.state.namespace).Scan(&first); err != nil || first != lower {
				t.Fatal("lower sequence missing after drain", err)
			}
			if resultWrite {
				if _, err := journal.ReadResult(ctx, command); err != nil {
					t.Fatal("result missing after writer drain", err)
				}
				for _, counter := range snapshot {
					var observed, started, expires time.Time
					var value string
					if err := pool.Raw().QueryRow(ctx, `SELECT value::text,observed_at,started_at,expires_at FROM risk_store.velocity_snapshots WHERE sequence=$1 AND dimension=$2`, receipt.state.sequence, counter.Kind).Scan(&value, &observed, &started, &expires); err != nil || value != "7" || !observed.Equal(counter.ObservedAt) || !started.Equal(counter.WindowStartedAt) || !expires.Equal(counter.WindowExpiresAt) {
						t.Fatal("drain changed original evidence", err)
					}
				}
				if err := journal.RecordResult(ctx, receipt, risk.CounterCommitted, snapshot); err != nil {
					t.Fatal("terminal replay lost after acquisition", err)
				}
			}
		}()
	}
	// Declarations after acquisition must remain recordable: they carry explicit
	// evidence, not effects or a complete replay watermark.
	late := prepare("writer-fence-result", "late-declaration", risk.BeforeReturn)
	lateReceipt, err := journal.RecordAttempt(ctx, late)
	if err != nil {
		t.Fatal("journal intent became effect admission", err)
	}
	if err := journal.RecordResult(ctx, lateReceipt, risk.CounterUnknown, nil); err != nil {
		t.Fatal("late unknown evidence discarded", err)
	}
	if _, err := journal.ReadResult(ctx, late); err != nil {
		t.Fatal("late unknown history unavailable", err)
	}

	blocker, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer velocityRollback(blocker)
	if err := recovery.state.lock(ctx, blocker, "writer-fence-cancel"); err != nil {
		t.Fatal(err)
	}
	cancelCommand := prepare("writer-fence-cancel", "cancel", risk.BeforeCredential)
	cancelled, cancel := context.WithCancel(ctx)
	defer cancel()
	type writeResult struct {
		receipt VelocityAttempt
		err     error
	}
	finished := make(chan writeResult, 1)
	go func() {
		receipt, err := journal.RecordAttempt(cancelled, cancelCommand)
		finished <- writeResult{receipt, err}
	}()
	waiting := false
	for i := 0; i < 40; i++ {
		if _, err := blocker.Exec(ctx, `SELECT pg_stat_clear_snapshot()`); err != nil {
			break
		}
		if err := blocker.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name='velocity-writer-fence' AND wait_event='advisory' AND query LIKE 'SELECT pg_advisory_xact_lock_shared(%')`).Scan(&waiting); err != nil {
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
	var unavailable identity.UnavailableError
	if !waiting || !errors.As(result.err, &unavailable) || result.receipt.state != nil {
		t.Fatal("cancelled writer escaped fence", result.err)
	}
	var count int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM risk_store.velocity_attempts WHERE tenant_id='writer-fence-cancel'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("cancelled writer persisted", err)
	}
}
