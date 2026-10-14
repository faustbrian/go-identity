package reference

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

// These tests isolate routing and lifetime at the owned counter boundary.
// They are not native persistence or public OTP composition evidence.
type routedCounterStore func(context.Context, risk.CounterCommand) (risk.CounterResult, error)

func (s routedCounterStore) Mutate(ctx context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
	return s(ctx, c)
}

func routerPolicy(t *testing.T) (risk.Policy, []risk.CounterDigestKey) {
	t.Helper()
	p, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 2, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"velocity"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	k, err := risk.NewCounterDigestKey(1, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return p, []risk.CounterDigestKey{k}
}

func routerCommand(t *testing.T, p risk.Policy, keys []risk.CounterDigestKey, tenant string) risk.CounterCommand {
	t.Helper()
	c, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: p, Keys: keys, Clock: time.Now, Timeout: time.Second, Store: routedCounterStore(func(context.Context, risk.CounterCommand) (risk.CounterResult, error) {
		panic("prepare must not dispatch")
	})})
	if err != nil {
		t.Fatal(err)
	}
	command, err := c.Prepare(risk.Context{Tenant: tenant, Operation: "identity.otp.send", Attempt: "attempt"}, risk.Subject{Network: "192.0.2.1", Device: "device", IdentifierDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, risk.BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func TestCounterRouterAdmitsOnlyCurrentSelectedActivation(t *testing.T) {
	p, keys := routerPolicy(t)
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	state := &storeState{policy: p, keys: keys, lifetime: lifetime, cancel: cancel, drained: drained, config: VelocityStoreConfiguration{PrimaryTimeout: time.Second}, tenants: map[string]*tenantRecovery{"tenant": {}}}
	router := velocityCounterRouter{state: state}
	command := routerCommand(t, p, keys, "tenant")
	if _, err := router.Mutate(context.Background(), command); err == nil {
		t.Fatal("unrecovered graph admitted a counter")
	}
	calls := 0
	original := risk.CounterResult{}
	state.tenants["tenant"].counter = routedCounterStore(func(_ context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
		calls++
		b := c.Bindings()
		var counters []risk.Counter
		for _, target := range b.Targets {
			counters = append(counters, risk.Counter{Kind: string(target.Dimension), Value: 7, ObservedAt: b.PreparedAt, WindowStartedAt: b.PreparedAt, WindowExpiresAt: b.PreparedAt.Add(b.Window)})
		}
		var err error
		original, err = risk.NewCounterResult(c, risk.CounterCommitted, counters)
		return original, err
	})
	result, err := router.Mutate(context.Background(), command)
	outcome, facts, declarationErr := result.Declaration(command)
	if err != nil || declarationErr != nil || outcome != risk.CounterCommitted || len(facts) != 4 || facts[0].Value != 7 || calls != 1 {
		t.Fatal("router replaced the activated owner's original counter declaration")
	}
	for _, bad := range []risk.CounterCommand{risk.CounterCommand{}, routerCommand(t, p, keys, "foreign")} {
		if _, err := router.Mutate(context.Background(), bad); err == nil {
			t.Fatal("foreign/zero command reached activation")
		}
	}
	foreign, _ := routerPolicy(t)
	if _, err := router.Mutate(context.Background(), routerCommand(t, foreign, keys, "tenant")); err == nil {
		t.Fatal("equivalent foreign policy gained custody")
	}
	state.tenants["tenant"].busy = true
	if _, err := router.Mutate(context.Background(), command); err == nil {
		t.Fatal("recovery in progress reused old activation")
	}
	state.tenants["tenant"].busy = false
	state.closed = true
	if _, err := router.Mutate(context.Background(), command); err == nil {
		t.Fatal("closed graph retained counter admission")
	}
	if calls != 1 {
		t.Fatal("denied routing crossed the counter boundary")
	}
}

func TestCounterRouterCancellationDrainsOriginalMutation(t *testing.T) {
	p, keys := routerPolicy(t)
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	started := make(chan struct{})
	state := &storeState{policy: p, keys: keys, lifetime: lifetime, cancel: cancel, drained: drained, config: VelocityStoreConfiguration{PrimaryTimeout: time.Second}, tenants: map[string]*tenantRecovery{"tenant": {counter: routedCounterStore(func(ctx context.Context, _ risk.CounterCommand) (risk.CounterResult, error) {
		close(started)
		<-ctx.Done()
		return risk.CounterResult{}, ctx.Err()
	})}}}
	router := velocityCounterRouter{state: state}
	done := make(chan error, 1)
	go func() {
		_, err := router.Mutate(context.Background(), routerCommand(t, p, keys, "tenant"))
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("mutation did not enter owned boundary")
	}
	state.mu.Lock()
	state.closed = true
	activeDrain := state.drained
	state.cancel()
	state.mu.Unlock()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("lifetime cancellation lost", err)
		}
	case <-time.After(time.Second):
		t.Fatal("owned mutation did not join")
	}
	select {
	case <-activeDrain:
	default:
		t.Fatal("shutdown observed completion before releasing owned mutation")
	}
	if _, err := (velocityCounterRouter{}).Mutate(context.Background(), risk.CounterCommand{}); !errors.Is(err, risk.ErrInvalidCounterCommand) {
		t.Fatal("zero router did not deny")
	}
	var unavailable identity.UnavailableError
	if _, err := router.Mutate(context.Background(), routerCommand(t, p, keys, "tenant")); !errors.As(err, &unavailable) {
		t.Fatal("closed router did not deny", err)
	}
}

func TestRecoveryPublishesOnlyItsReturnedSuccessfulActivation(t *testing.T) {
	state := &storeState{}
	owner := routedCounterStore(func(context.Context, risk.CounterCommand) (risk.CounterResult, error) {
		panic("publication must not dispatch")
	})
	tenant := &tenantRecovery{}
	health := &velocityHealth{check: func(context.Context) error { panic("publication must not probe") }}
	if store, err := state.finishVelocityRecovery(context.Background(), tenant, owner, health, nil); err != nil || store == nil || tenant.counter == nil || tenant.health != health {
		t.Fatal("successful recovery did not publish its returned owner")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if store, err := state.finishVelocityRecovery(canceled, tenant, owner, health, nil); store != nil || !errors.Is(err, context.Canceled) || tenant.counter != nil || tenant.health != nil {
		t.Fatal("canceled recovery retained an unreturned activation")
	}
	failure := errors.New("fixture unavailable")
	if store, err := state.finishVelocityRecovery(context.Background(), tenant, owner, health, failure); store != nil || !errors.Is(err, failure) || tenant.counter != nil || tenant.health != nil {
		t.Fatal("failed recovery installed activation")
	}
	state.closed = true
	if store, err := state.finishVelocityRecovery(context.Background(), tenant, owner, health, nil); store != nil || err == nil || tenant.counter != nil || tenant.health != nil {
		t.Fatal("shutdown raced successful recovery publication")
	}
}
