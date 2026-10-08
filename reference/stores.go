// Package reference owns deployment composition for the identity platform.
// This development slice composes PostgreSQL-journaled Valkey velocity recovery
// and optional native OTP Send/delivery. It is not the complete reference server.
package reference

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/risk"
	riskpostgres "github.com/faustbrian/go-identity/risk/postgres"
	riskvalkey "github.com/faustbrian/go-identity/risk/valkey"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
)

// ReferenceDependencies supplies deployment resources, never domain stores or
// workflow callbacks. PostgreSQL remains caller-owned, including after Close.
// Its pool configuration and callbacks must satisfy go-postgres's contract.
// EnvelopeKeys and DeliverySender are required only for selected OTP/delivery.
// They remain caller-owned, cooperative bounded, concurrency-safe dependencies.
type ReferenceDependencies struct {
	PostgreSQL     *database.Pool
	EnvelopeKeys   envelope.KeyProvider
	DeliverySender delivery.Sender
}

// StoreConfiguration contains selected adapter configuration exactly once.
// Velocity is required; OTP and Delivery must be selected together. Zero is
// invalid. Construction copies configuration. Concurrent input mutation during
// construction is forbidden. No optional feature is silently enabled.
type StoreConfiguration struct {
	Velocity VelocityStoreConfiguration
	// OTP selects public Send and its mandatory delivery owner. Nil preserves
	// the recovery-only profile. No caller evaluator or domain store is accepted.
	OTP      *OTPSendConfiguration
	Delivery *DeliveryConfiguration
}

// VelocityStoreConfiguration selects one primary/native recovery pair. Native
// owns namespace, replay secret, policy, key history and transport configuration;
// the primary uses those exact values rather than separately selected custody.
// Tenants is a unique allowlist of 1..128 deployment scopes. Schema must satisfy
// the PostgreSQL adapter. PrimaryTimeout is positive and at most one minute.
// LeaseDuration is positive, microsecond-representable and at most one minute.
// RecoveryTimeout is positive and less than LeaseDuration. Batch is 1..1000
// (reference default 100); MaxRecords is 1..100000. Bounds are explicit: zero
// never silently enables defaults, retries or a healthy initial state.
type VelocityStoreConfiguration struct {
	Native          riskvalkey.VelocityRecoveryConfig
	Schema          string
	Tenants         []string
	PrimaryTimeout  time.Duration
	LeaseDuration   time.Duration
	RecoveryTimeout time.Duration
	Batch           int
	MaxRecords      int
}

// StoreSet is sealed deployment composition. Copies share one lifetime and
// immutable configuration. RecoverVelocity is concurrent-safe across tenants;
// concurrent same-tenant attempts fail rather than queue unbounded work. The
// caller owns Close. Zero grants no authority and can be safely closed.
type StoreSet struct{ state *storeState }

type storeState struct {
	mu       sync.Mutex
	closed   bool
	active   int
	drained  chan struct{}
	lifetime context.Context
	cancel   context.CancelFunc
	tenants  map[string]*tenantRecovery
	native   riskvalkey.VelocityRecovery
	primary  riskpostgres.VelocityRecovery
	config   VelocityStoreConfiguration
	policy   risk.Policy
	keys     []risk.CounterDigestKey
	features *featureState
}

type tenantRecovery struct {
	busy     bool
	previous risk.VelocityLease
	counter  risk.CounterStore
}

// ComposeStores validates/copies deployment configuration without network IO,
// migrations or goroutines. It creates exactly one native custody graph and
// configures the concrete primary adapter with that graph's paired authorities.
// It does not enable traffic: RecoverVelocity must establish real covered
// journal history and native-confirmed activation. Invalid input is redacted.
func ComposeStores(c StoreConfiguration, d ReferenceDependencies) (StoreSet, error) {
	v := c.Velocity
	if len(v.Tenants) < 1 || len(v.Tenants) > 128 || v.Batch < 1 || v.Batch > 1000 || v.MaxRecords < 1 || v.MaxRecords > 100000 || v.RecoveryTimeout <= 0 || v.RecoveryTimeout >= v.LeaseDuration {
		return StoreSet{}, risk.ErrInvalidPolicy
	}
	tenants := make(map[string]*tenantRecovery, len(v.Tenants))
	for _, tenant := range v.Tenants {
		if len(tenant) < 1 || len(tenant) > 128 || tenants[tenant] != nil {
			return StoreSet{}, risk.ErrInvalidPolicy
		}
		// Both concrete adapters require printable ASCII without spaces. Fail
		// composition now instead of retaining an unusable deployment scope.
		for i := range len(tenant) {
			if tenant[i] < '!' || tenant[i] > '~' {
				return StoreSet{}, risk.ErrInvalidPolicy
			}
		}
		tenants[tenant] = &tenantRecovery{}
	}
	journal, err := riskpostgres.NewVelocityJournal(riskpostgres.VelocityJournalConfig{Pool: d.PostgreSQL, Schema: v.Schema, Namespace: v.Native.Namespace, JournalKey: v.Native.ReplaySecret, Policy: v.Native.Policy, Keys: v.Native.Keys, Timeout: v.PrimaryTimeout})
	if err != nil {
		return StoreSet{}, err
	}
	native, err := riskvalkey.NewVelocityRecovery(v.Native)
	if err != nil {
		return StoreSet{}, err
	}
	issuer, verifier, err := native.PrimaryAuthorities()
	if err != nil {
		return StoreSet{}, err
	}
	primary, err := riskpostgres.NewVelocityRecovery(riskpostgres.VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: v.LeaseDuration, JournalIssuer: issuer, NativeVerifier: verifier})
	if err != nil {
		return StoreSet{}, err
	}
	lifetime, cancel := context.WithCancel(context.Background())
	drained := make(chan struct{})
	close(drained)
	// Resource owners already copied the sensitive configuration. Retain only
	// traversal bounds; no caller TLS objects, secret slices or tenant slices.
	retained := VelocityStoreConfiguration{Schema: v.Schema, Batch: v.Batch, MaxRecords: v.MaxRecords, RecoveryTimeout: v.RecoveryTimeout, PrimaryTimeout: v.PrimaryTimeout}
	state := &storeState{drained: drained, lifetime: lifetime, cancel: cancel, tenants: tenants, native: native, primary: primary, config: retained, policy: v.Native.Policy, keys: slices.Clone(v.Native.Keys)}
	if err := state.composeFeatureStores(c, d); err != nil {
		cancel()
		return StoreSet{}, err
	}
	return StoreSet{state: state}, nil
}

// RecoverVelocity performs one explicit bounded recovery, never background
// retry or an implicit debit. It starts a fresh primary-owned generation and
// restores original authenticated terminal history from zero. Unknown/pending
// history, lost acknowledgements, incomplete coverage, concurrent ownership or
// exhausted budgets return no store. Empty fresh storage is unavailable for a
// genuine full hour of journal coverage; no timestamp is backdated here.
// Success returns the exact activated pair's CounterStore, whose later calls
// recheck primary/native eligibility without resetting original expiry. There
// is no healthy-lease renewal. After expiry another explicit recovery is needed.
// A newly composed owner cannot adopt a predecessor's opaque native marker;
// cross-process reconciliation remains unimplemented and fails closed.
func (s StoreSet) RecoverVelocity(ctx context.Context, tenant string) (store risk.CounterStore, err error) {
	if ctx == nil || s.state == nil {
		return nil, risk.ErrInvalidVelocityRecovery
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	state := s.state
	state.mu.Lock()
	t := state.tenants[tenant]
	if state.closed || t == nil || t.busy {
		state.mu.Unlock()
		return nil, identity.UnavailableError{}
	}
	if state.active == 0 {
		state.drained = make(chan struct{})
	}
	state.active++
	t.busy = true
	// A new recovery generation may fence the old owner even when it fails.
	// Never fall back to a previously installed activation after that attempt.
	t.counter = nil
	state.mu.Unlock()
	defer func() {
		state.mu.Lock()
		t.busy = false
		state.active--
		if state.active == 0 {
			close(state.drained)
		}
		state.mu.Unlock()
	}()
	bounded, cancel := context.WithTimeout(ctx, state.config.RecoveryTimeout)
	stop := context.AfterFunc(state.lifetime, cancel)
	defer func() {
		// Primary adapters redact SQL errors. The composition owns the outer
		// lifetime and must preserve its cancellation/deadline, not expose an
		// unavailable substitute or a store activated after shutdown.
		store, err = state.finishVelocityRecovery(bounded, t, store, err)
		stop()
		cancel()
	}()
	var boot [16]byte
	if _, err := rand.Read(boot[:]); err != nil || boot == [16]byte{} {
		return nil, identity.UnavailableError{}
	}
	lease, err := state.primary.Acquire(bounded, tenant, boot)
	if err != nil {
		return nil, err
	}
	owned, err := state.primary.OwnedLease(bounded, lease)
	if err != nil {
		return nil, err
	}
	previous := t.previous
	// Preserve attempted fence custody even on ambiguous native ACK. A later
	// explicit generation must never pretend this attempt did not happen.
	t.previous = owned
	if err := state.native.Fence(bounded, owned, previous); err != nil {
		return nil, err
	}
	cursor, err := state.primary.ResumeApplied(bounded, lease)
	if err != nil {
		return nil, err
	}
	count := 0
	for {
		page, err := state.primary.ReadPage(bounded, lease, cursor, state.config.Batch)
		if err != nil {
			return nil, err
		}
		records := page.Records()
		if len(records) > state.config.MaxRecords-count {
			return nil, identity.UnavailableError{}
		}
		for _, record := range records {
			history, err := state.primary.OwnedHistory(bounded, lease, owned, record)
			if err != nil {
				return nil, err
			}
			ack, err := state.native.Restore(bounded, owned, history)
			if err != nil {
				return nil, err
			}
			if err := state.primary.RecordApplied(bounded, lease, owned, ack); err != nil {
				return nil, err
			}
			count++
		}
		cursor = page.Next()
		if len(records) == 0 {
			break
		}
	}
	cut, err := state.primary.PrepareCoveredClosure(bounded, lease)
	if err != nil {
		return nil, err
	}
	exported, err := state.primary.OwnedClosure(bounded, lease, owned, cut)
	if err != nil {
		return nil, err
	}
	publication, err := state.native.Publish(bounded, owned, exported)
	if err != nil {
		return nil, err
	}
	if err := state.primary.ConfirmPublication(bounded, lease, owned, cut, exported, publication); err != nil {
		return nil, err
	}
	confirmation, err := state.primary.OwnedConfirmation(bounded, lease, owned, cut, exported, publication)
	if err != nil {
		return nil, err
	}
	nativeConfirmation, err := state.native.Confirm(bounded, owned, exported, publication, confirmation)
	if err != nil {
		return nil, err
	}
	healthy, err := state.primary.Activate(bounded, lease, owned, cut, exported, publication, confirmation, nativeConfirmation)
	if err != nil {
		return nil, err
	}
	journal, err := state.primary.OwnedJournal(bounded, healthy)
	if err != nil {
		return nil, err
	}
	store, err = state.native.OwnedCounterStore(bounded, journal)
	return store, err
}

// finishVelocityRecovery publishes the returned handle and deferred routing
// together at one lifetime-checked synchronization point, before busy clears.
func (s *storeState) finishVelocityRecovery(ctx context.Context, t *tenantRecovery, store risk.CounterStore, err error) (risk.CounterStore, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t.counter = nil
	if lifetimeErr := ctx.Err(); lifetimeErr != nil {
		return nil, lifetimeErr
	}
	if s.closed {
		return nil, identity.UnavailableError{}
	}
	if err != nil {
		return nil, err
	}
	t.counter = store
	return store, nil
}

// Close permanently denies new recovery, cancels active primary/native work,
// closes owned native connections and joins recovery within ctx. It never
// closes the caller's pool. A timeout leaves closure permanent; repeat Close
// may finish waiting. No lock spans IO or waiting. Nil ctx is invalid.
func (s StoreSet) Close(ctx context.Context) error {
	if ctx == nil {
		return risk.ErrInvalidVelocityRecovery
	}
	if s.state == nil {
		return nil
	}
	state := s.state
	state.mu.Lock()
	state.closed = true
	state.cancel()
	drained := state.drained
	state.mu.Unlock()
	if err := state.native.Close(ctx); err != nil {
		return err
	}
	select {
	case <-drained:
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (StoreConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.StoreConfiguration(redacted)")
}
func (VelocityStoreConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.VelocityStoreConfiguration(redacted)")
}
func (ReferenceDependencies) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.ReferenceDependencies(redacted)")
}
func (StoreSet) Format(s fmt.State, _ rune)             { _, _ = io.WriteString(s, "reference.StoreSet(redacted)") }
func (StoreConfiguration) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (StoreConfiguration) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (VelocityStoreConfiguration) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (VelocityStoreConfiguration) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (ReferenceDependencies) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (ReferenceDependencies) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (StoreSet) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (StoreSet) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
