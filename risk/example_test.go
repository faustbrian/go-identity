package risk_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

func ExampleNewPolicy() {
	policy := examplePolicy()
	// No facts are supplied: mandatory unknown signals must fail closed. No
	// provider is called and no protected mutation or evidence issuance occurs.
	assessment, err := policy.Assess(context.Background(), risk.Context{Tenant: "example-tenant", Operation: "identity.password.signin", Attempt: "example-attempt", Now: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)}, nil)
	if err != nil {
		panic("invalid evaluation")
	}
	fmt.Println(assessment.Decision.Action)
	// Output: deny
}

// unavailableCounterStore is a demonstration of an unavailable boundary, not
// an application-provided replacement for the required official durable adapters.
type unavailableCounterStore struct{}

func (unavailableCounterStore) Mutate(_ context.Context, command risk.CounterCommand) (risk.CounterResult, error) {
	return risk.NewCounterResult(command, risk.CounterNotCommitted, nil)
}

func ExampleNewCounterCoordinator() {
	// Example-only material; deployments provide independently managed secrets.
	key, err := risk.NewCounterDigestKey(1, make([]byte, 32))
	if err != nil {
		panic("invalid key")
	}
	coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{
		Policy: examplePolicy(), Store: unavailableCounterStore{}, Keys: []risk.CounterDigestKey{key}, Clock: time.Now, Timeout: time.Second,
	})
	if err != nil {
		panic("invalid counter configuration")
	}
	identifier := sha256.Sum256([]byte("example-normalized-identifier"))
	command, err := coordinator.Prepare(risk.Context{Tenant: "example-tenant", Operation: "identity.password.signin", Attempt: "example-attempt"}, risk.Subject{Network: "192.0.2.1", Device: "example-device", IdentifierDigest: hex.EncodeToString(identifier[:])}, risk.BeforeCredential)
	if err != nil {
		panic("invalid counter binding")
	}
	result, err := coordinator.Mutate(context.Background(), command)
	if err != nil {
		panic("invalid dispatch")
	}
	fmt.Println(result.Outcome == risk.CounterNotCommitted, result.Signal.State == risk.SignalUnavailable)
	// Output: true true
}

func ExampleNewCommandCounterPolicy() {
	// Example-only material; production uses managed retained digest keys.
	key, err := risk.NewCounterDigestKey(1, make([]byte, 32))
	if err != nil {
		panic("invalid key")
	}
	policy, err := risk.NewCommandCounterPolicy(risk.CommandCounterPolicyConfig{Policy: examplePolicy(), Keys: []risk.CounterDigestKey{key}})
	if err != nil {
		panic("invalid protected policy")
	}
	scope := risk.Context{Tenant: "example-tenant", Operation: "identity.password.change", Attempt: "example-attempt"}
	subject := risk.Subject{User: "example-user", Session: "example-session", Network: "192.0.2.1"}
	// Production supplies the sole coordinator's primary database time.
	now := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	command, err := policy.Prepare(scope, subject, now)
	if err != nil {
		panic("invalid protected scope")
	}
	fmt.Println(policy.Validate(command, scope, subject, now) == nil)
	// No counter has been mutated and no durable outcome is asserted.
	// Output: true
}

func ExampleNewCarrierEvaluator() {
	// Zero startup configuration explicitly leaves phone recovery disabled.
	// Applications cannot enable it by providing request facts or a phase alone.
	evaluator, err := risk.NewCarrierEvaluator(risk.CarrierEvaluatorConfig{})
	if err != nil {
		panic("invalid startup configuration")
	}
	_, err = evaluator.Assess(context.Background(), risk.CarrierRequest{})
	fmt.Println(err == risk.ErrCarrierRecoveryDisabled)
	// Output: true
}

func examplePolicy() risk.Policy {
	// Values come from the selected deployment profile, not package defaults.
	profiles := []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "captcha"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "captcha"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "captcha"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"status", "captcha"}},
	}
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 1, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: profiles})
	if err != nil {
		panic("invalid deployment policy")
	}
	return policy
}

func ExampleNewEvaluator() {
	// These unavailable readers illustrate fail-closed behavior without claiming
	// live provider or durable adapter composition. Applications must use the
	// platform's completed source adapters, not fabricate authoritative facts.
	sources := make([]risk.Source, 0, 2)
	for _, name := range []string{"status", "captcha"} {
		sources = append(sources, risk.Source{Name: name, Timeout: time.Second, Read: func(_ context.Context, c risk.Context) (risk.Signal, error) {
			return risk.Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: name, State: risk.SignalUnavailable, Trust: risk.ServerVerified}, nil
		}})
	}
	evaluator, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: examplePolicy(), Clock: time.Now, Timeout: 5 * time.Second, Sources: sources})
	if err != nil {
		panic("invalid configured readers")
	}
	result, err := evaluator.Evaluate(context.Background(), risk.EvaluateRequest{Context: risk.Context{Tenant: "example-tenant", Operation: "identity.password.signin", Attempt: "example-attempt"}, Phase: risk.NonIssuing})
	if err != nil {
		panic("invalid evaluation")
	}
	fmt.Println(result.Decision.Action)
	// Output: deny
}
