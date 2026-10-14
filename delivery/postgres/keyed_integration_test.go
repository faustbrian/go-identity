//go:build integration

package postgres

import (
	"errors"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

func TestKeyedDeliveryAdmissionConcurrentRestartAndScope(t *testing.T) {
	ctx, pool := intentDatabase(t)
	history, err := (MigrationSource{Base: identitypostgres.MigrationSource{}, Version: 10, WorkerVersion: 11, PolicyVersion: 12, KeyedVersion: 13}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range history[len(history)-3:] {
		if _, err := pool.Exec(ctx, m.UpSQL()); err != nil {
			t.Fatal("keyed migration", err)
		}
	}
	mapping, err := newKeyedAdmission(ctx, pool, "test", [32]byte{7}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, b, _ := custodyFixture(t)
	op := EnqueueOperation()
	b.Command.OperationID, b.Command.SchemaID = op.OperationID, op.SchemaID
	start := make(chan struct{})
	ids := make(chan identity.CommandID, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			<-start
			candidate := b.Command
			var err error
			candidate.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Error(err)
				return
			}
			id, err := mapping.resolve(ctx, candidate, "synthetic-request-key", [32]byte{1})
			if err != nil {
				t.Error("matching concurrent admission", err)
				return
			}
			ids <- id
		})
	}
	close(start)
	wg.Wait()
	close(ids)
	var original identity.CommandID
	var count int
	for id := range ids {
		count++
		if original == "" {
			original = id
		}
		if id != original {
			t.Fatal("same key allocated multiple commands")
		}
	}
	if count != 8 {
		t.Fatal("lost matching admission")
	}
	restarted, err := newKeyedAdmission(ctx, pool, "test", [32]byte{7}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := restarted.resolve(ctx, b.Command, "synthetic-request-key", [32]byte{1}); err != nil || got != original {
		t.Fatal("restart changed original command", err)
	}
	if got, version, err := restarted.resolveVersion(ctx, b.Command, "synthetic-request-key", [32]byte{1}, 2); err != nil || got != original || version != 1 {
		t.Fatal("unexecuted allocation rotation lost original key", err)
	}
	if _, err := mapping.resolve(ctx, b.Command, "synthetic-request-key", [32]byte{2}); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("changed logical intent reused key", err)
	}
	if _, err := newKeyedAdmission(ctx, pool, "test", [32]byte{8}, time.Second); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("lookup key rotation split admission namespace", err)
	}
	for _, mutate := range []func(*identity.CommandBinding){
		func(v *identity.CommandBinding) { v.TenantID = "other" },
		func(v *identity.CommandBinding) { v.ActorID = "other" },
		func(v *identity.CommandBinding) { v.UserID = "other" },
	} {
		foreign := b.Command
		mutate(&foreign)
		foreign.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		if id, err := mapping.resolve(ctx, foreign, "synthetic-request-key", [32]byte{1}); err != nil || id == original {
			t.Fatal("scoped key crossed authority", err)
		}
	}
	var commands, entries int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.commands),(SELECT count(*) FROM identity.delivery_keyed_commands)`).Scan(&commands, &entries); err != nil || commands != 0 || entries != 4 {
		t.Fatal("key allocation claimed command execution", err, commands, entries)
	}
	for _, sql := range []string{`DELETE FROM identity.delivery_keyed_commands`, `UPDATE identity.delivery_keyed_commands SET intent_digest=decode(repeat('aa',32),'hex')`, `TRUNCATE identity.delivery_keyed_commands`} {
		if _, err := pool.Exec(ctx, sql); err == nil {
			t.Fatal("original mapping history changed")
		}
	}
}
