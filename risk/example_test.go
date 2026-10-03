package risk_test

import (
	"context"
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
