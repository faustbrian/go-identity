package risk

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
)

func TestOAuthProxyForwardRiskBindsOnlyOriginalCallbackDimensions(t *testing.T) {
	now := testContext().Now
	mutations := 0
	cfg := countedConfig(t, &now, counterStoreFunc(func(_ context.Context, c CounterCommand) (CounterResult, error) {
		mutations++
		var dims []Dimension
		for _, target := range c.Bindings().Targets {
			dims = append(dims, target.Dimension)
		}
		if !slices.Equal(dims, []Dimension{TenantDimension, NetworkDimension, ResourceDimension}) {
			t.Fatalf("unexpected dimensions: %v", dims)
		}
		return NewCounterResult(c, CounterCommitted, snapshotFor(c, 1))
	}))
	request := auditRequest(t)
	request.Context.Operation = "identity.oauth.proxy-forward"
	request.Subject = Subject{Network: "192.0.2.17", Resource: "AgICAgICAgICAgICAgICAg"}
	if _, err := cfg.Counters.Prepare(request.Context, request.Subject, BeforeCredential); err == nil {
		t.Fatal("default profile accepted the selected proxy dimensions")
	}
	selected, err := cfg.Policy.WithOAuthProxyForward()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Policy{}).WithOAuthProxyForward(); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("zero policy accepted", err)
	}
	if _, err := cfg.Counters.Prepare(request.Context, request.Subject, BeforeCredential); err == nil {
		t.Fatal("selection mutated the original policy")
	}
	previous := cfg.Counters.state
	counter, err := NewCounterCoordinator(CounterCoordinatorConfig{Policy: selected, Clock: cfg.Clock,
		Timeout: time.Second, Keys: previous.keys, Store: previous.store})
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []Subject{{Network: request.Subject.Network}, {Resource: request.Subject.Resource},
		{Network: request.Subject.Network, Resource: "raw-provider-state"},
		{Network: request.Subject.Network, Resource: request.Subject.Resource, Device: "unbound"}} {
		if _, err := counter.Prepare(request.Context, invalid, BeforeCredential); !errors.Is(err, ErrInvalidCounterCommand) {
			t.Fatal("inexact risk subject admitted", err)
		}
	}
	neighbor := request.Context
	neighbor.Operation = "identity.oauth.callback"
	if _, err := counter.Prepare(neighbor, request.Subject, BeforeCredential); err == nil {
		t.Fatal("proxy selection changed an ordinary OAuth callback")
	}
	if _, err := counter.Prepare(neighbor, counterSubject(), BeforeCredential); err != nil {
		t.Fatal("ordinary OAuth callback lost its existing profile", err)
	}
	audits := 0
	cfg.Policy, cfg.Counters = selected, &counter
	cfg.DecisionAudit = auditedConfig(t, &now, decisionSink(func(_ context.Context, r audit.Record) (audit.AppendResult, error) {
		audits++
		return audit.AppendResult{RecordID: r.ID(), Status: audit.AppendAccepted}, nil
	})).DecisionAudit
	e, err := NewEvaluator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := e.Evaluate(t.Context(), request)
	if err != nil || result.Decision.Action != Allow || audits != 1 || mutations != 1 {
		t.Fatal("did not receive one auditable counted allowance", err)
	}
	if err := e.RequireAuthenticationAdmission(t.Context(), result, request.Context, request.Subject); err != nil {
		t.Fatal("genuine allowance rejected", err)
	}
	foreign := request.Subject
	foreign.Resource = "AwMDAwMDAwMDAwMDAwMDAw"
	if err := e.RequireAuthenticationAdmission(t.Context(), result, request.Context, foreign); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
		t.Fatal("allowance transferred to a different original browser", err)
	}
	now = now.Add(5 * time.Minute)
	if err := e.RequireAuthenticationAdmission(t.Context(), result, request.Context, request.Subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) || audits != 1 || mutations != 1 {
		t.Fatal("allowance renewed or counters and audit re-run at verification", err)
	}
}
