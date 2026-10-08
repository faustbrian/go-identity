//go:build integration

package valkey

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/internal/velocity"
)

// Live service is deliberately separate from the simulated primary authority.
// Each run creates a random isolated namespace; it never flushes shared data.
func TestOwnedCurrentAdmissionLiveValkey(t *testing.T) {
	endpoint := os.Getenv("IDENTITY_RISK_VALKEY_TEST_ENDPOINT")
	if !strings.HasPrefix(endpoint, "rediss://localhost:") {
		t.Fatal("loopback TLS test endpoint required")
	}
	readFile := func(name string) []byte {
		path := os.Getenv(name)
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 16384 {
			t.Fatal("bounded test input file required")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("cannot read test input")
		}
		return data
	}
	trust := readFile("IDENTITY_RISK_VALKEY_TEST_CA")
	credential, err := NewCredential("default", bytes.TrimSpace(readFile("IDENTITY_RISK_VALKEY_TEST_PASSWORD_FILE")))
	if err != nil {
		t.Fatal("invalid test credential")
	}
	var unique [16]byte
	if _, err := rand.Read(unique[:]); err != nil {
		t.Fatal(err)
	}
	policy, keys, _ := commandFixture(t, 9, 8)
	public, err := NewVelocityRecovery(VelocityRecoveryConfig{Namespace: "live-" + hex.EncodeToString(unique[:]), ReplaySecret: bytes.Repeat([]byte{7}, 32), Policy: policy, Keys: keys, Endpoint: endpoint, TLS: &tls.Config{ServerName: "localhost", MinVersion: tls.VersionTLS12}, TrustPEM: trust, Credential: credential, Timeout: 2 * time.Second, PoolSize: 2, Topology: "standalone"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := public.Close(ctx); err != nil {
			t.Error("live native transport did not close", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	transport, layout, owner := public.state.transport, public.state.layout, *public.state
	journal, nativeVerifier, err := public.PrimaryAuthorities()
	if err != nil {
		t.Fatal(err)
	}
	reader, err := journal.Verifier()
	if err != nil {
		t.Fatal(err)
	}
	var replayClosed, unhealthy atomic.Bool
	replayCheck := func(context.Context) error {
		if replayClosed.Load() {
			return errors.New("simulated replay custody closed")
		}
		return nil
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	lease, err := journal.Lease(risk.VelocityLeaseBinding{Tenant: "tenant", Namespace: layout.replay.Namespace(), Epoch: unique, Generation: 1, Owner: [16]byte{1}, ExpiresAt: now.Add(50 * time.Second)}, replayCheck)
	if err != nil {
		t.Fatal(err)
	}
	cut := risk.VelocityClosureBinding{ID: [32]byte{1}, Position: 1, ReplayFrom: now.Add(-time.Hour), ReplayThrough: now, JournalStartedAt: now.Add(-time.Hour), MaximumWindow: time.Hour}
	closure, err := journal.Closure(lease, cut, replayCheck)
	if err != nil {
		t.Fatal(err)
	}
	if err := public.Fence(ctx, lease, risk.VelocityLease{}); err != nil {
		t.Fatal("live recovery fence failed", err)
	}
	// Synthetic primary history supplies original facts; real native restoration
	// must preserve those facts rather than invent a new observation/window.
	originalCoordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Keys: keys, Store: unusedStore{}, Clock: func() time.Time { return now.Add(-time.Minute) }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	originalCommand := prepareFixture(t, originalCoordinator, "tenant", "restored-original", "192.0.2.1")
	originalBinding := originalCommand.Bindings()
	digest, err := layout.replay.Attempt(originalCommand)
	if err != nil {
		t.Fatal(err)
	}
	facts := risk.VelocityHistoryBinding{ID: strings.Repeat("A", 43), Position: 1, Tenant: originalBinding.Tenant, Namespace: layout.replay.Namespace(), Attempt: digest, Fingerprint: originalBinding.Fingerprint, Operation: originalBinding.Operation, Phase: originalBinding.Phase, PolicyVersion: originalBinding.PolicyVersion, PreparedAt: originalBinding.PreparedAt, RecordedAt: now, Window: originalBinding.Window, Limit: originalBinding.Limit, Outcome: risk.VelocityHistoryCommitted, Targets: originalBinding.Targets}
	for _, target := range originalBinding.Targets {
		facts.Snapshot = append(facts.Snapshot, risk.Counter{Kind: string(target.Dimension), Value: 1, ObservedAt: originalBinding.PreparedAt, WindowStartedAt: originalBinding.PreparedAt, WindowExpiresAt: originalBinding.PreparedAt.Add(originalBinding.Window)})
	}
	history, err := journal.History(lease, facts)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := public.Restore(ctx, lease, history)
	if err != nil {
		t.Fatal("live public original restoration failed", err)
	}
	if got, err := nativeVerifier.Applied(ctx, lease, applied); err != nil || got.Position != facts.Position || !reflect.DeepEqual(got.Snapshot, facts.Snapshot) {
		t.Fatal("public restoration lost original facts", err)
	}
	publication, err := public.Publish(ctx, lease, closure)
	if err != nil {
		t.Fatal("live covered publication failed", err)
	}
	confirmation, err := journal.AcknowledgeConfirmation(ctx, lease, closure, publication, replayCheck)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := public.Confirm(ctx, lease, closure, publication, confirmation)
	if err != nil {
		t.Fatal("live native confirmation failed", err)
	}
	health, err := journal.AcknowledgeEligibility(ctx, lease, closure, publication, confirmation, ack, func(context.Context) error {
		if unhealthy.Load() {
			return errors.New("simulated primary unavailable")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	replayClosed.Store(true)
	// Deliberate primary double, not PostgreSQL persistence evidence. This
	// isolates the public native constructor/factory against the real server.
	var primaryMu sync.Mutex
	terminal := map[string]risk.CounterResult{}
	connection, err := velocity.BindJournal(layout.replay.Namespace(), func(c risk.CounterCommand) error { return c.ValidateConfiguration(policy, keys) }, func(context.Context, risk.CounterCommand) error { return nil }, func(_ context.Context, c risk.CounterCommand) (velocity.Attempt, error) {
		attempt := c.Bindings().Attempt
		primaryMu.Lock()
		_, exists := terminal[attempt]
		if !exists {
			terminal[attempt] = risk.CounterResult{}
		}
		primaryMu.Unlock()
		if exists {
			return velocity.Attempt{}, errors.New("simulated original intent exists")
		}
		return velocity.BindAttempt(c, func(_ context.Context, result risk.CounterResult) error {
			primaryMu.Lock()
			defer primaryMu.Unlock()
			terminal[attempt] = result
			return nil
		})
	}, func(_ context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
		primaryMu.Lock()
		defer primaryMu.Unlock()
		result := terminal[c.Bindings().Attempt]
		if _, _, err := result.Declaration(c); err != nil {
			return risk.CounterResult{}, err
		}
		return result, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	connection, err = velocity.BindCurrentJournal(ctx, connection, reader, nativeVerifier, velocity.CurrentChain{Lease: lease, Closure: closure, Publication: publication, Confirmation: confirmation, Native: ack, Eligibility: health})
	if err != nil {
		t.Fatal(err)
	}
	store, err := public.OwnedCounterStore(ctx, connection)
	if err != nil {
		t.Fatal("live public native factory denied", err)
	}
	coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Keys: keys, Clock: func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }, Timeout: 3 * time.Second, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	command := prepareFixture(t, coordinator, "tenant", "first", "192.0.2.1")
	plan, err := layout.prepare(command, unique)
	if err != nil {
		t.Fatal(err)
	}
	read := func(key string) []string {
		// Inspection must obey the production reader's 128-byte element bound;
		// whole stored marker/replay/root payloads deliberately exceed that bound.
		got, err := transport.executeScript(ctx, `return {redis.sha1hex(redis.call('GET',KEYS[1]) or ''),string.format('%.0f',redis.call('PEXPIRETIME',KEYS[1]))}`, []string{key}, nil)
		if err != nil || len(got) != 2 {
			t.Fatal("live state read failed", err)
		}
		return got
	}
	before := read(plan.keys[0])
	if err := owner.checkCurrent(ctx, command, lease, closure, publication, confirmation, ack, health); err != nil {
		t.Fatal("live read-only current check denied", err)
	}
	if !reflect.DeepEqual(before, read(plan.keys[0])) {
		t.Fatal("live current check changed marker or expiry")
	}
	first, err := coordinator.Mutate(ctx, command)
	if err != nil || first.Outcome != risk.CounterCommitted || first.Signal.State != risk.SignalClean {
		t.Fatal("live debit denied", err, first.Outcome)
	}
	state := make([][]string, len(plan.keys))
	for i, key := range plan.keys {
		state[i] = read(key)
	}
	if !reflect.DeepEqual(before, state[0]) {
		t.Fatal("live debit renewed original health")
	}
	if err := owner.checkCurrent(ctx, command, lease, closure, publication, confirmation, ack, health); err != nil {
		t.Fatal("live existing-attempt current check denied", err)
	}
	second, err := coordinator.Mutate(ctx, command)
	if err != nil || second.Outcome != risk.CounterCommitted || !second.Signal.ObservedAt.Equal(first.Signal.ObservedAt) || !second.Signal.ExpiresAt.Equal(first.Signal.ExpiresAt) {
		t.Fatal("live replay renewed observation", err)
	}
	for i, key := range plan.keys {
		if !reflect.DeepEqual(state[i], read(key)) {
			t.Fatal("live replay changed original state or expiry")
		}
	}
	// Separate logical attempts share the same dimensional counters. Native
	// script atomicity must conserve every acknowledged debit under contention.
	results := make(chan risk.CounterEvaluation, 15)
	for i := 0; i < 15; i++ {
		cmd := prepareFixture(t, coordinator, "tenant", "parallel-"+strconv.Itoa(i), "192.0.2.1")
		go func() { result, _ := coordinator.Mutate(ctx, cmd); results <- result }()
	}
	for range 15 {
		result := <-results
		if result.Outcome != risk.CounterCommitted || result.Signal.State != risk.SignalClean && result.Signal.State != risk.SignalThrottle {
			t.Error("live concurrent debit was not attributable")
		}
	}
	root := plan.keys[2+capacityProbeCount+len(keys)-1]
	count, err := transport.executeScript(ctx, `local v=redis.call('GET',KEYS[1]) or ''; return {string.match(v,'^[^|]+|[^|]+|([^|]+)|') or '','count'}`, []string{root}, nil)
	if err != nil || len(count) != 2 || count[0] != "17" {
		t.Fatal("live concurrent debit lost a counter update")
	}
	retainedRoot := read(root)
	for _, current := range []bool{false, true} {
		unhealthy.Store(!current)
		if current {
			if _, err := transport.executeScript(ctx, `return {tostring(redis.call('DEL',KEYS[1])),'deleted'}`, []string{plan.keys[0]}, nil); err != nil {
				t.Fatal("scoped marker deletion failed", err)
			}
		}
		blocked, err := coordinator.Mutate(ctx, command)
		if err := owner.checkCurrent(ctx, command, lease, closure, publication, confirmation, ack, health); err == nil {
			t.Fatal("live current check admitted lost authority or missing marker")
		}
		if err != nil || blocked.Signal.State != risk.SignalUnavailable {
			t.Fatal("lost current authority admitted even matching replay", err)
		}
		if got := read(root); !reflect.DeepEqual(got, retainedRoot) {
			t.Fatal("denial changed retained counters")
		}
	}
	if _, err := reader.Lease(lease); err != nil {
		t.Fatal("native loss corrupted immutable primary facts")
	}
}
