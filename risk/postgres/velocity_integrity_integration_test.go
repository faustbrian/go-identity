//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

// SQL-valid replacement values must not acquire the original journal's custody.
func testVelocityIntegrity(t *testing.T, ctx context.Context, journal VelocityJournal, cfg VelocityJournalConfig) {
	t.Helper()
	var now time.Time
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: cfg.Policy, Keys: cfg.Keys, Store: neverVelocityStore{}, Clock: func() time.Time { return now }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	command, err := coordinator.Prepare(risk.Context{Tenant: "integrity-tenant", Operation: "identity.profile.get", Attempt: "original"}, risk.Subject{User: "user"}, risk.BeforeReturn)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := journal.RecordAttempt(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	var pendingSeal []byte
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT replay_seal FROM risk_store.velocity_attempts WHERE sequence=$1`, receipt.state.sequence).Scan(&pendingSeal); err != nil || len(pendingSeal) != 32 {
		t.Fatal("pending intent has no authentication", err)
	}
	var snapshot []risk.Counter
	for _, target := range command.Bindings().Targets {
		snapshot = append(snapshot, risk.Counter{Kind: string(target.Dimension), Value: 7, ObservedAt: now, WindowStartedAt: now, WindowExpiresAt: now.Add(command.Bindings().Window)})
	}
	if err := journal.RecordResult(ctx, receipt, risk.CounterCommitted, snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.ReadResult(ctx, command); err != nil {
		t.Fatal("authentic original unavailable", err)
	}
	var unavailable identity.UnavailableError
	for _, change := range []struct{ mutate, restore string }{
		{`UPDATE risk_store.velocity_snapshots SET value=8 WHERE sequence=$1 AND dimension='tenant'`, `UPDATE risk_store.velocity_snapshots SET value=7 WHERE sequence=$1 AND dimension='tenant'`},
		{`UPDATE risk_store.velocity_snapshots SET observed_at=observed_at+interval '1 microsecond' WHERE sequence=$1`, `UPDATE risk_store.velocity_snapshots SET observed_at=observed_at-interval '1 microsecond' WHERE sequence=$1`},
		{`UPDATE risk_store.velocity_attempts SET recorded_at=recorded_at+interval '1 microsecond' WHERE sequence=$1`, `UPDATE risk_store.velocity_attempts SET recorded_at=recorded_at-interval '1 microsecond' WHERE sequence=$1`},
	} {
		if _, err := cfg.Pool.Raw().Exec(ctx, change.mutate, receipt.state.sequence); err != nil {
			t.Fatal(err)
		}
		if _, err := journal.ReadResult(ctx, command); !errors.As(err, &unavailable) {
			t.Fatal("SQL-valid replacement acquired original evidence custody", err)
		}
		if err := journal.RecordResult(ctx, receipt, risk.CounterCommitted, snapshot); !errors.As(err, &unavailable) {
			t.Fatal("terminal replay blessed corrupted history", err)
		}
		if _, err := cfg.Pool.Raw().Exec(ctx, change.restore, receipt.state.sequence); err != nil {
			t.Fatal(err)
		}
		if _, err := journal.ReadResult(ctx, command); err != nil {
			t.Fatal("restored original denied", err)
		}
	}
	var terminalSeal []byte
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT replay_seal FROM risk_store.velocity_attempts WHERE sequence=$1`, receipt.state.sequence).Scan(&terminalSeal); err != nil || len(terminalSeal) != 32 || string(pendingSeal) == string(terminalSeal) {
		t.Fatal("outcome not bound", err)
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_attempts SET replay_seal=NULL WHERE sequence=$1`, receipt.state.sequence); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.ReadResult(ctx, command); !errors.As(err, &unavailable) {
		t.Fatal("missing seal downgraded authentication", err)
	}
	if err := journal.RecordResult(ctx, receipt, risk.CounterCommitted, snapshot); !errors.As(err, &unavailable) {
		t.Fatal("unsealed history was blessed", err)
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_attempts SET replay_seal=$2 WHERE sequence=$1`, receipt.state.sequence, terminalSeal); err != nil {
		t.Fatal(err)
	}
	unknownCommand, err := coordinator.Prepare(risk.Context{Tenant: "integrity-tenant", Operation: "identity.profile.get", Attempt: "unknown"}, risk.Subject{User: "user"}, risk.BeforeReturn)
	if err != nil {
		t.Fatal(err)
	}
	unknownReceipt, err := journal.RecordAttempt(ctx, unknownCommand)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordResult(ctx, unknownReceipt, risk.CounterUnknown, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.ReadResult(ctx, unknownCommand); err != nil {
		t.Fatal("authenticated unknown lost", err)
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_attempts SET outcome='not_committed' WHERE sequence=$1`, unknownReceipt.state.sequence); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.ReadResult(ctx, unknownCommand); !errors.As(err, &unavailable) {
		t.Fatal("unknown converted to noncommit", err)
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_attempts SET outcome='unknown',replay_seal=$2 WHERE sequence=$1`, unknownReceipt.state.sequence, terminalSeal); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.ReadResult(ctx, unknownCommand); !errors.As(err, &unavailable) {
		t.Fatal("foreign record seal accepted", err)
	}
	// Failure while sealing must roll back the complete intent, not retain a
	// pending row with unauthenticated target/alias history.
	if _, err := cfg.Pool.Raw().Exec(ctx, `CREATE FUNCTION risk_store.fail_velocity_seal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.tenant_id='integrity-rollback' AND NEW.replay_seal IS NOT NULL THEN RAISE EXCEPTION 'seal failure'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER fail_velocity_seal BEFORE UPDATE ON risk_store.velocity_attempts FOR EACH ROW EXECUTE FUNCTION risk_store.fail_velocity_seal()`); err != nil {
		t.Fatal(err)
	}
	rollbackCommand, err := coordinator.Prepare(risk.Context{Tenant: "integrity-rollback", Operation: "identity.profile.get", Attempt: "rollback"}, risk.Subject{User: "user"}, risk.BeforeReturn)
	if err != nil {
		t.Fatal(err)
	}
	if receipt, err := journal.RecordAttempt(ctx, rollbackCommand); !errors.As(err, &unavailable) || receipt.state != nil {
		t.Fatal("failed seal granted receipt", err)
	}
	var count int
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT count(*) FROM risk_store.velocity_attempts WHERE tenant_id='integrity-rollback'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed seal retained partial intent", err)
	}
}
