package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/jackc/pgx/v5/pgxpool"
)

type workerPolicyFunc func(context.Context, authorization.DecisionContext) (authorization.Decision, error)

func (f workerPolicyFunc) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	return f(ctx, c)
}

type workerSenderFunc func(context.Context, delivery.Attempt) (delivery.DeliveryResult, error)

func (f workerSenderFunc) Send(ctx context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
	return f(ctx, a)
}

// No IO: inspect the public constructor's snapshot and policy dispatch, not
// durable lease or provider behavior (covered by real PostgreSQL integration).
func TestPublicWorkerScopeSnapshotAndPolicyFailure(t *testing.T) {
	codec, _, _ := custodyFixture(t)
	profile := delivery.DefaultConfig()
	profile.Production = true
	scope := authorization.DecisionContext{PolicyRevision: 1, CorrelationID: "worker-correlation", Request: authorization.Request{Tenant: "tenant-a", Action: "identity.delivery.process", Subject: authorization.Subject{ID: "worker-service", Kind: authorization.SubjectServiceAccount}, Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "worker", Attributes: authorization.Attributes{"region": authorization.StringValue("original")}}}}
	custody := &Contributor{store: &intentStore{codec: codec, profiles: map[uint64]providerProfile{1: {name: "provider", policyVersion: 1}}}}
	s := &EnqueueService{executor: &enqueueExecutor{custody: custody, policyVersion: 1}, policies: &retainedPolicies{pool: &pgxpool.Pool{}, deployment: "test", profiles: map[uint64]delivery.Config{1: profile}, timeout: time.Second}}
	called := 0
	s.executor.authorize = workerPolicyFunc(func(ctx context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		called++
		region, _ := dc.Request.Resource.Attributes["region"].String()
		provider, _ := dc.Request.Resource.Attributes["delivery.provider"].String()
		version, _ := dc.Request.Resource.Attributes["delivery.provider-config-version"].String()
		if region != "original" || provider != "provider" || version != "1" || dc.Request.Environment.Time.IsZero() {
			t.Error("worker policy lost frozen scope/profile")
		}
		dc.Request.Resource.Attributes["region"] = authorization.StringValue("policy-local")
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	})
	sender := workerSenderFunc(func(context.Context, delivery.Attempt) (delivery.DeliveryResult, error) {
		return delivery.DeliveryResult{}, nil
	})
	w, err := s.NewWorker(WorkerConfig{Scope: scope, ProviderConfigVersion: 1}, sender)
	if err != nil {
		t.Fatal(err)
	}
	scope.Request.Resource.Attributes["region"] = authorization.StringValue("caller-private-change")
	for range 2 {
		if err := w.queue.allow(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if called != 2 {
		t.Fatal("policy was cached")
	}
	for _, change := range []func(*authorization.DecisionContext){
		func(dc *authorization.DecisionContext) { dc.Request.Subject.Kind = authorization.SubjectUser },
		func(dc *authorization.DecisionContext) { dc.Request.Action = "identity.delivery.enqueue" },
		func(dc *authorization.DecisionContext) { dc.Request.Resource.Type = "identity.user" },
		func(dc *authorization.DecisionContext) { dc.PolicyRevision = 2 },
		func(dc *authorization.DecisionContext) {
			dc.Request.Resource.Attributes["delivery.provider"] = authorization.StringValue("spoofed")
		},
	} {
		invalid := scope.Clone()
		change(&invalid)
		if _, err := s.NewWorker(WorkerConfig{Scope: invalid, ProviderConfigVersion: 1}, sender); err == nil {
			t.Fatal("spoofed worker scope accepted")
		}
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := w.Claim(cancelled); !errors.Is(err, context.Canceled) || called != 2 {
		t.Fatal("pre-cancelled worker reached policy or database", err)
	}
	if _, err := w.Complete(context.Background(), delivery.CompleteRequest{TenantID: "other", WorkerID: "worker"}); !errors.Is(err, delivery.ErrForbidden) || called != 2 {
		t.Fatal("cross-tenant completion reached IO", err)
	}
	for _, policy := range []workerPolicyFunc{
		func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			panic("private-policy-panic")
		},
		func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{}, errors.New("private-policy-error")
		},
		func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{Outcome: authorization.Allow, Revision: 2}, nil
		},
	} {
		s.executor.authorize = policy
		if err := w.queue.allow(context.Background()); err == nil || strings.Contains(err.Error(), "private") {
			t.Fatal("policy failure leaked or granted", err)
		}
	}
	for _, value := range []any{WorkerConfig{Scope: scope, ProviderConfigVersion: 1}, *w} {
		if _, err := json.Marshal(value); !errors.Is(err, delivery.ErrSerializationForbidden) {
			t.Fatal("worker serialized", err)
		}
		if text := fmt.Sprintf("%#v", value); strings.Contains(text, "private") || !strings.Contains(text, "redacted") {
			t.Fatal("worker diagnostics leaked")
		}
	}
}

func TestPublicWorkerRejectsZero(t *testing.T) {
	for _, w := range []*Worker{nil, {}} {
		if _, err := w.ProcessOne(context.Background()); !errors.Is(err, delivery.ErrInvalidInput) {
			t.Fatal(err)
		}
		if _, err := w.Claim(context.Background()); !errors.Is(err, delivery.ErrInvalidInput) {
			t.Fatal(err)
		}
		if _, err := w.Complete(context.Background(), delivery.CompleteRequest{}); !errors.Is(err, delivery.ErrInvalidInput) {
			t.Fatal(err)
		}
	}
	for _, s := range []*EnqueueService{nil, {}} {
		if _, err := s.NewWorker(WorkerConfig{}, nil); !errors.Is(err, delivery.ErrInvalidInput) {
			t.Fatal(err)
		}
	}
}
