package velocity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

// The primary check/acknowledgements are deliberate core-authority doubles.
// These tests prove exact custody wiring, not storage or native continuity.
func currentFixture(t *testing.T, namespace [32]byte) (CurrentChain, risk.VelocityJournalVerifier, risk.VelocityNativeIssuer, *atomic.Bool, *atomic.Int32) {
	t.Helper()
	j, reader, native, _ := risk.NewVelocityRecoveryAuthorities()
	lost, reads := &atomic.Bool{}, &atomic.Int32{}
	check := func(context.Context) error {
		reads.Add(1)
		if lost.Load() {
			return errors.New("synthetic primary failure")
		}
		return nil
	}
	var replayClosed atomic.Bool
	replay := func(context.Context) error {
		if replayClosed.Load() {
			return errors.New("replay callbacks closed after activation")
		}
		return nil
	}
	at := time.Date(2026, 10, 8, 3, 0, 0, 0, time.UTC)
	l, err := j.Lease(risk.VelocityLeaseBinding{Tenant: "tenant", Namespace: namespace, Epoch: [16]byte{1}, Owner: [16]byte{2}, Generation: 1, ExpiresAt: at.Add(time.Minute)}, replay)
	if err != nil {
		t.Fatal(err)
	}
	c, err := j.Closure(l, risk.VelocityClosureBinding{ID: [32]byte{3}, ReplayFrom: at.Add(-time.Hour), ReplayThrough: at, JournalStartedAt: at.Add(-time.Hour), MaximumWindow: time.Hour}, replay)
	if err != nil {
		t.Fatal(err)
	}
	p, err := native.AcknowledgePublication(context.Background(), l, c)
	if err != nil {
		t.Fatal(err)
	}
	k, err := j.AcknowledgeConfirmation(context.Background(), l, c, p, replay)
	if err != nil {
		t.Fatal(err)
	}
	a, err := native.AcknowledgeNativeConfirmation(context.Background(), l, c, p, k)
	if err != nil {
		t.Fatal(err)
	}
	h, err := j.AcknowledgeEligibility(context.Background(), l, c, p, k, a, check)
	if err != nil {
		t.Fatal(err)
	}
	reads.Store(0)
	replayClosed.Store(true)
	return CurrentChain{Lease: l, Closure: c, Publication: p, Confirmation: k, Native: a, Eligibility: h}, reader, native, lost, reads
}

func TestCurrentJournalConservesExactChainAndRejectsForeignNative(t *testing.T) {
	f, old := newFixture(t, "committed", false)
	chain, reader, issuer, lost, reads := currentFixture(t, [32]byte{1})
	v, err := issuer.Verifier()
	if err != nil {
		t.Fatal(err)
	}
	j, err := BindCurrentJournal(context.Background(), old.state.journal, reader, v, chain)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		got, err := Current(context.Background(), j, issuer)
		if err != nil || got != chain {
			t.Fatal("original activated chain changed", err)
		}
		got.Lease = risk.VelocityLease{}
	}
	_, _, foreign, _ := risk.NewVelocityRecoveryAuthorities()
	before := reads.Load()
	if _, err := Current(context.Background(), j, foreign); err == nil || reads.Load() != before {
		t.Fatal("foreign graph reached primary IO")
	}
	n, err := BindCurrentNative(context.Background(), j, issuer, old.state.native.state.validate, old.state.native.state.check, old.state.native.state.mutate)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(j, n, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Mutate(context.Background(), f.command); err != nil {
		t.Fatal(err)
	}
	// Equal namespace and even equal graph/chain cannot substitute a separately
	// bound journal owner after the native functions capture the original owner.
	other, err := BindCurrentJournal(context.Background(), old.state.journal, reader, v, chain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(other, n, time.Second); err == nil {
		t.Fatal("native connection accepted substituted primary owner")
	}
	if _, err := NewStore(j, old.state.native, time.Second); err == nil {
		t.Fatal("unbound native bypassed current custody")
	}
	if _, err := NewStore(old.state.journal, n, time.Second); err == nil {
		t.Fatal("current native accepted unbound journal")
	}
	lost.Store(true)
	if _, err := s.Mutate(context.Background(), f.command); err == nil || f.writes != 1 {
		t.Fatal("bound native check cached primary allowance or resent", err)
	}
	if _, err := Current(context.Background(), j, issuer); err == nil {
		t.Fatal("copied chain cached primary allowance")
	}
	if _, err := BindCurrentNative(context.Background(), j, issuer, old.state.native.state.validate, old.state.native.state.check, old.state.native.state.mutate); err == nil {
		t.Fatal("unhealthy factory bound native")
	}
	if !strings.Contains(fmt.Sprintf("%+v", chain), "redacted") {
		t.Fatal("current chain diagnostics exposed custody")
	}
	if _, err := json.Marshal(chain); !errors.Is(err, risk.ErrSensitiveSerialization) {
		t.Fatal("current chain serialized", err)
	}
	if _, err := chain.MarshalText(); !errors.Is(err, risk.ErrSensitiveSerialization) {
		t.Fatal("current chain text serialized", err)
	}
}

func TestCurrentJournalInvalidCustodyCannotInvokePrimary(t *testing.T) {
	_, s := newFixture(t, "committed", true)
	chain, reader, issuer, _, reads := currentFixture(t, [32]byte{1})
	v, err := issuer.Verifier()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []CurrentChain{{}, {Lease: chain.Lease, Closure: chain.Closure, Publication: chain.Publication, Confirmation: chain.Confirmation, Native: chain.Native}} {
		if _, err := BindCurrentJournal(context.Background(), s.state.journal, reader, v, bad); err == nil || reads.Load() != 0 {
			t.Fatal("invalid chain reached primary checker")
		}
	}
	if _, err := BindCurrentJournal(context.Background(), Journal{}, reader, v, chain); err == nil {
		t.Fatal("zero journal bound")
	}
	wrongNamespace := *s.state.journal.state
	wrongNamespace.namespace = [32]byte{9}
	if _, err := BindCurrentJournal(context.Background(), Journal{state: &wrongNamespace}, reader, v, chain); err == nil || reads.Load() != 0 {
		t.Fatal("namespace mismatch reached checker")
	}
	if _, err := BindCurrentJournal(context.Background(), s.state.journal, risk.VelocityJournalVerifier{}, v, chain); err == nil {
		t.Fatal("zero reader bound")
	}
	other, _, _, _, _ := currentFixture(t, [32]byte{9})
	if _, err := BindCurrentJournal(context.Background(), s.state.journal, reader, v, other); err == nil || reads.Load() != 0 {
		t.Fatal("foreign chain reached checker")
	}
	if _, err := BindCurrentJournal(nil, s.state.journal, reader, v, chain); err == nil {
		t.Fatal("nil context admitted")
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := BindCurrentJournal(canceled, s.state.journal, reader, v, chain); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	j, err := BindCurrentJournal(context.Background(), s.state.journal, reader, v, chain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BindCurrentJournal(context.Background(), j, reader, v, chain); err == nil {
		t.Fatal("bound journal custody replaced")
	}
	before := reads.Load()
	if _, err := Current(nil, j, issuer); err == nil {
		t.Fatal("nil current context admitted")
	}
	if _, err := Current(canceled, j, issuer); !errors.Is(err, context.Canceled) {
		t.Fatal("current cancellation lost", err)
	}
	if _, err := Current(context.Background(), s.state.journal, issuer); err == nil {
		t.Fatal("unbound journal exposed current custody")
	}
	if _, err := Current(context.Background(), Journal{}, issuer); err == nil {
		t.Fatal("zero journal exposed custody")
	}
	if _, err := Current(context.Background(), j, risk.VelocityNativeIssuer{}); err == nil || reads.Load() != before {
		t.Fatal("zero issuer reached checker")
	}
	if _, err := BindCurrentNative(context.Background(), j, issuer, nil, s.state.native.state.check, s.state.native.state.mutate); err == nil {
		t.Fatal("invalid callbacks bound")
	}
	if reads.Load() != before {
		t.Fatal("invalid callbacks reached primary IO")
	}
}
