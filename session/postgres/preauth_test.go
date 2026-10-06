package postgres

import (
	"bytes"
	"context"
	"errors"
	"math"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func testPreAuth(t testing.TB, now time.Time) session.PreAuthTransaction {
	t.Helper()
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.PersistentSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	s, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{
		Binding: session.PreAuthBinding{ID: "AQEBAQEBAQEBAQEBAQEBAQ", Intent: session.PreAuthIntent{TenantID: "tenant-a", Action: "identity.otp.signin", Origin: "https://identity.test", CallbackURL: "https://app.test/return", Nonce: [32]byte{1}, Remember: remember, PolicyID: "login", PolicyVersion: math.MaxUint64}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}, Cookie: session.TokenDigest{KeyVersion: math.MaxUint32, Sum: [32]byte{2}}, Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPreAuthStorageExactRoundTrip(t *testing.T) {
	original := testPreAuth(t, time.Date(2026, 10, 7, 0, 0, 0, 123456789, time.UTC))
	b, err := encodePreAuth(original)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := decodePreAuth(b)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := original.Bindings()
	got, _ := restored.Bindings()
	gr, _ := got.Binding.Intent.Remember.Bindings()
	wr, _ := want.Binding.Intent.Remember.Bindings()
	got.Binding.Intent.Remember = want.Binding.Intent.Remember
	if got != want || gr != wr {
		t.Fatal("flow binding changed")
	}
	for _, bad := range [][]byte{nil, []byte("null"), append(bytes.Clone(b), ' '), append(bytes.Clone(b), []byte("{}")...), bytes.Replace(b, []byte(`"Schema":1`), []byte(`"Schema":2`), 1), bytes.Replace(b, []byte(`"Nonce":[1,0`), []byte(`"Nonce":[null,0`), 1), bytes.Replace(b, []byte(`"PolicyVersion":18446744073709551615`), []byte(`"PolicyVersion":0`), 1), bytes.Replace(b, []byte(`"Version":1`), []byte(`"Unknown":1`), 1), make([]byte, 8193)} {
		if _, e := decodePreAuth(bad); !errors.Is(e, ErrInvalidRecord) {
			t.Fatal("incomplete flow accepted", e)
		}
	}
	if _, err = encodePreAuth(session.PreAuthTransaction{}); !errors.Is(err, ErrInvalidRecord) {
		t.Fatal("zero encoded")
	}
}

func TestPreAuthNativeInvalidInput(t *testing.T) {
	ctx := context.Background()
	record := testPreAuth(t, time.Now().UTC())
	c := Config{Schema: "session_store", MaximumDuration: time.Second}
	var invalid identity.InvalidInputError
	for _, cfg := range []Config{{}, {Schema: "public", MaximumDuration: time.Second}} {
		if err := RequirePreAuth(ctx, kernel.Work{}, cfg, record); !errors.As(err, &invalid) {
			t.Fatal("invalid config admitted", err)
		}
	}
	if err := RequirePreAuth(nil, kernel.Work{}, c, record); !errors.As(err, &invalid) {
		t.Fatal("nil context admitted", err)
	}
	if err := RequirePreAuth(ctx, kernel.Work{}, c, session.PreAuthTransaction{}); !errors.As(err, &invalid) {
		t.Fatal("zero admitted", err)
	}
	if err := RequirePreAuth(ctx, kernel.Work{}, c, record); err == nil {
		t.Fatal("zero work admitted")
	}
	if err := ReservePreAuth(ctx, kernel.Work{}, c, record, PreAuthUse{}); !errors.As(err, &invalid) {
		t.Fatal("zero custody admitted", err)
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	var canceledError identity.CancelledError
	if err := RequirePreAuth(canceled, kernel.Work{}, c, record); !errors.As(err, &canceledError) {
		t.Fatal("cancellation lost", err)
	}
}

func FuzzPreAuthStoredRecord(f *testing.F) {
	b, err := encodePreAuth(testPreAuth(f, time.Date(2026, 10, 7, 0, 0, 0, 1, time.UTC)))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte("null"))
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := decodePreAuth(b)
		if err == nil {
			again, e := encodePreAuth(r)
			if e != nil || !bytes.Equal(b, again) {
				t.Fatal("accepted flow not canonical")
			}
		}
	})
}

func TestPreAuthMigrationPreservesAllocationAndCancellation(t *testing.T) {
	source := PreAuthMigrationSource{Schema: "session_store", Version: 30}
	history, err := source.Load(context.Background())
	if err != nil || len(history) != 1 || history[0].Version() != 30 || history[0].DownSQL() != "" || history[0].TransactionMode() != migrations.TransactionModeDefault {
		t.Fatal("forward migration not attributable", err)
	}
	for _, invalid := range []PreAuthMigrationSource{{}, {Schema: "public", Version: 30}, {Schema: "session_store", Version: ^migrations.Version(0)}} {
		if result, err := invalid.Load(context.Background()); err == nil || result != nil {
			t.Fatal("invalid allocation admitted")
		}
	}
	if result, err := source.Load(nil); err == nil || result != nil {
		t.Fatal("nil context admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := source.Load(ctx); !errors.Is(err, context.Canceled) || result != nil {
		t.Fatal("cancellation lost")
	}
}
