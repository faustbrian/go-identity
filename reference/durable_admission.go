package reference

import (
	"context"
	"fmt"
	"io"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	riskvalkey "github.com/faustbrian/go-identity/risk/valkey"
)

// DurableAdmissionConfiguration selects the PostgreSQL-only deployment's
// durable fixed-window admission authority. No store or fabricated result may
// be supplied by callers. Namespace/replay custody is stable across restarts;
// dimension Keys retain complete newest-first history. Tenants is an explicit
// 1..128 scope allowlist. MaximumRecords and Timeout obey DurableCounterConfig.
// Capacity exhaustion denies rather than evicting retained attempts. Protected
// mutation counters remain owned by their native transaction participants.
type DurableAdmissionConfiguration struct {
	Schema, Namespace string
	Policy            risk.Policy
	Keys              []risk.CounterDigestKey
	ReplayKey         []byte
	Tenants           []string
	MaximumRecords    int64
	Timeout           time.Duration
}

func (DurableAdmissionConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.DurableAdmissionConfiguration(redacted)")
}
func (DurableAdmissionConfiguration) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (DurableAdmissionConfiguration) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

func composeDurableAdmission(c StoreConfiguration, d ReferenceDependencies, migrationPolicy *MigrationApplyPolicy, httpRate *httpRateState) (StoreSet, error) {
	if !emptyVelocity(c.Velocity) {
		return StoreSet{}, identity.InvalidInputError{Field: "reference_counter_ownership"}
	}
	n := *c.DurableAdmission
	store, err := riskpg.NewDurableCounterStore(riskpg.DurableCounterConfig{Pool: d.PostgreSQL, Schema: n.Schema, Namespace: n.Namespace, Policy: n.Policy, Keys: n.Keys, ReplayKey: n.ReplayKey, Tenants: n.Tenants, MaximumRecords: n.MaximumRecords, Timeout: n.Timeout})
	if err != nil {
		return StoreSet{}, err
	}
	tenants := make(map[string]*tenantRecovery, len(n.Tenants))
	for _, tenant := range n.Tenants {
		tenants[tenant] = &tenantRecovery{counter: store, health: &velocityHealth{check: func(ctx context.Context) error { return store.Check(ctx, tenant) }}}
	}
	lifetime, cancel := context.WithCancel(context.Background())
	drained := make(chan struct{})
	close(drained)
	state := &storeState{pool: d.PostgreSQL, lifetime: lifetime, cancel: cancel, drained: drained, tenants: tenants, policy: n.Policy, keys: append([]risk.CounterDigestKey(nil), n.Keys...), config: VelocityStoreConfiguration{Schema: n.Schema, PrimaryTimeout: n.Timeout}, migrations: migrationPolicy, httpRate: httpRate, durable: true}
	// Feature builders compare native counter policy/key allocations as well as
	// schema. The selected durable owner supplies all three; these private inputs
	// do not select a second runtime velocity owner (emptyVelocity was checked).
	c.Velocity.Schema = n.Schema
	c.Velocity.Native.Policy = n.Policy
	c.Velocity.Native.Keys = append([]risk.CounterDigestKey(nil), n.Keys...)
	if err := state.composeFeatureStores(c, d); err != nil {
		cancel()
		return StoreSet{}, err
	}
	return StoreSet{state: state}, nil
}

func emptyVelocity(v VelocityStoreConfiguration) bool {
	n := v.Native
	return v.Schema == "" && len(v.Tenants) == 0 && v.PrimaryTimeout == 0 && v.LeaseDuration == 0 && v.RecoveryTimeout == 0 && v.Batch == 0 && v.MaxRecords == 0 && n.Namespace == "" && len(n.ReplaySecret) == 0 && n.Policy == (risk.Policy{}) && len(n.Keys) == 0 && n.Endpoint == "" && n.TLS == nil && len(n.TrustPEM) == 0 && n.Credential == (riskvalkey.Credential{}) && n.Timeout == 0 && n.PoolSize == 0 && n.Topology == ""
}
