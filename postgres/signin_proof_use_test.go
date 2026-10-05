package postgres

import (
	"context"
	migrations "github.com/faustbrian/go-migrations/v3"
	"strings"
	"testing"
	"time"
)

// The private storage phase is not an authentication authority. Only the future
// protected issuer may supply authenticated, frozen original proof metadata.
type signInProofUseStager interface {
	stageSignInProofUse(context.Context, string, string, uint64, time.Time) error
}

func TestSignInProofUseMigrationAndInputBounds(t *testing.T) {
	base, err := (MigrationSource{}).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, err := (SignInProofUseMigrationSource{Base: MigrationSource{}, Version: 10}).Load(context.Background())
	if err != nil || len(got) != len(base)+1 {
		t.Fatal("history composition", err)
	}
	for i := range base {
		if base[i].Checksum() != got[i].Checksum() {
			t.Fatal("historical migration changed")
		}
	}
	for _, source := range []SignInProofUseMigrationSource{{}, {Base: MigrationSource{}, Version: 9}, {Base: MigrationSource{}, Version: migrations.Version(^uint64(0))}} {
		if rows, err := source.Load(context.Background()); err == nil || rows != nil {
			t.Fatal("invalid history admitted")
		}
	}
	if _, err := (SignInProofUseMigrationSource{Base: MigrationSource{}, Version: 10}).Load(nil); err == nil {
		t.Fatal("nil context")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (SignInProofUseMigrationSource{Base: MigrationSource{}, Version: 10}).Load(ctx); err != context.Canceled {
		t.Fatal("cancelled migration")
	}
	for _, id := range []string{strings.Repeat("a", 22), strings.Repeat("!", 128)} {
		if !visibleProofID(id) {
			t.Fatal("supported proof ID rejected")
		}
	}
	for _, id := range []string{"", strings.Repeat("a", 21), strings.Repeat("a", 129), strings.Repeat("a", 21) + " ", strings.Repeat("a", 21) + "\x7f", strings.Repeat("a", 21) + "é"} {
		if visibleProofID(id) {
			t.Fatal("invalid proof ID accepted")
		}
	}
}

func TestSignInProofUseInvalidInputPoisonsLiveWorkBeforeSQL(t *testing.T) {
	for _, test := range []struct {
		name, authority, proof                string
		version                               uint64
		expiry                                time.Time
		nilContext, cancelled, wrongOperation bool
	}{
		{name: "authority", proof: strings.Repeat("a", 22), version: 1, expiry: time.Now().Add(time.Minute)},
		{name: "proof", authority: "authority", proof: "short", version: 1, expiry: time.Now().Add(time.Minute)},
		{name: "version", authority: "authority", proof: strings.Repeat("a", 22), expiry: time.Now().Add(time.Minute)},
		{name: "expiry", authority: "authority", proof: strings.Repeat("a", 22), version: 1},
		{name: "UTC overflow", authority: "authority", proof: strings.Repeat("a", 22), version: 1, expiry: time.Date(9999, 12, 31, 23, 30, 0, 0, time.FixedZone("west", -3600))},
		{name: "nil context", authority: "authority", proof: strings.Repeat("a", 22), version: 1, expiry: time.Now().Add(time.Minute), nilContext: true},
		{name: "cancelled", authority: "authority", proof: strings.Repeat("a", 22), version: 1, expiry: time.Now().Add(time.Minute), cancelled: true},
		{name: "foreign operation", authority: "authority", proof: strings.Repeat("a", 22), version: 1, expiry: time.Now().Add(time.Minute), wrongOperation: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := codecBinding()
			if !test.wrongOperation {
				b.OperationID, b.SchemaID, b.RecordID = "identity.session.issue", "session-issue", "session"
			}
			bounded, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			w := Work{state: &workState{ctx: bounded, binding: b, generation: 1}}
			ctx := context.Context(bounded)
			if test.cancelled {
				stop()
			}
			if test.nilContext {
				ctx = nil
			}
			if err := w.stageSignInProofUse(ctx, test.authority, test.proof, test.version, test.expiry); err == nil || w.usable() == nil || w.state.sqlStarted {
				t.Fatal("invalid input retained execution or reached SQL", err)
			}
		})
	}
}

func TestSignInProofUseRejectsUnownedStorage(t *testing.T) {
	stager, ok := any(Work{}).(signInProofUseStager)
	if !ok {
		t.Fatal("native atomic final-authentication proof-use storage is missing")
	}
	if err := stager.stageSignInProofUse(context.Background(), "authority", "proof", 1, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("zero Work acquired proof-use storage")
	}
}

func TestSignInProofUseOutstandingRowsPoisonsAllAliases(t *testing.T) {
	b := codecBinding()
	b.OperationID, b.SchemaID, b.RecordID = "identity.session.issue", "session-issue", "session"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	w := Work{state: &workState{ctx: ctx, binding: b, generation: 1}}
	alias := w
	// Query rejects a second statement before touching the transaction. Closing
	// the original cursor must not restore authority after failed proof staging.
	w.state.rows = &WorkRows{}
	if err := w.stageSignInProofUse(ctx, "authority", strings.Repeat("a", 22), 1, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("outstanding rows admitted proof staging")
	}
	w.state.rows = nil
	if w.usable() == nil || alias.usable() == nil || w.state.sqlStarted {
		t.Fatal("failed proof staging restored execution authority")
	}
}
