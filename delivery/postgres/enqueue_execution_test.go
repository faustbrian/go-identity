package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
)

type enqueueBoundPolicy struct{ invoked bool }

func (p *enqueueBoundPolicy) Decide(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
	p.invoked = true
	return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
}

func TestEnqueuePolicyRejectsUnboundedAttributesBeforeCallback(t *testing.T) {
	largeSet := make([]string, 65)
	for n := range largeSet {
		largeSet[n] = fmt.Sprint(n)
	}
	aggregateSet := make([]string, 17)
	for n := range aggregateSet {
		aggregateSet[n] = strings.Repeat("x", 4093) + fmt.Sprintf("%03d", n)
	}
	for name, value := range map[string]authorization.Value{
		"cardinality":         authorization.StringSetValue(largeSet),
		"member":              authorization.StringSetValue([]string{strings.Repeat("x", 4097)}),
		"aggregate":           authorization.StringSetValue(aggregateSet),
		"invalid utf8 member": authorization.StringSetValue([]string{"\xff"}),
		"invalid utf8 scalar": authorization.StringValue("\xff"),
		"missing":             {},
	} {
		t.Run(name, func(t *testing.T) {
			b := identity.CommandBinding{TenantID: "tenant", UserID: "user", ActorID: "actor", ActorKind: authorization.SubjectUser, PolicyID: "policy", PolicyVersion: 1, OperationID: "identity.delivery.enqueue", CorrelationID: "correlation"}
			caller := authorization.DecisionContext{PolicyRevision: 1, CorrelationID: b.CorrelationID, Request: authorization.Request{Tenant: "tenant", Action: "identity.delivery.enqueue", Subject: authorization.Subject{ID: "actor", Kind: authorization.SubjectUser}, Resource: authorization.Resource{Type: "identity.user", ID: "user", Attributes: authorization.Attributes{"custom": value}}}}
			p := &enqueueBoundPolicy{}
			e := &enqueueExecutor{authorize: p, policyID: "policy", policyVersion: 1}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := e.allow(ctx, b, caller); !errors.Is(err, delivery.ErrInvalidInput) || p.invoked {
				t.Fatal("unbounded or invalid attribute reached policy", err, p.invoked)
			}
		})
	}
}

func TestEnqueuePolicyBoundsCombinedMapsAndAcceptsBoundedSets(t *testing.T) {
	b := identity.CommandBinding{TenantID: "tenant", UserID: "user", ActorID: "actor", ActorKind: authorization.SubjectUser, PolicyID: "policy", PolicyVersion: 1, OperationID: "identity.delivery.enqueue", CorrelationID: "correlation"}
	caller := authorization.DecisionContext{PolicyRevision: 1, CorrelationID: b.CorrelationID, Request: authorization.Request{Tenant: "tenant", Action: "identity.delivery.enqueue", Subject: authorization.Subject{ID: "actor", Kind: authorization.SubjectUser}, Resource: authorization.Resource{Type: "identity.user", ID: "user"}}}
	members := make([]string, 64)
	for i := range members {
		members[i] = fmt.Sprint(i)
	}
	caller.Request.Attributes = authorization.Attributes{"custom": authorization.StringSetValue(members)}
	p := &enqueueBoundPolicy{}
	e := &enqueueExecutor{authorize: p, policyID: "policy", policyVersion: 1}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := e.allow(ctx, b, caller); err != nil || !p.invoked {
		t.Fatal("bounded collection denied", err)
	}
	p.invoked = false
	// Neither map exceeds its individual limits, but their combined bytes do.
	attrs := authorization.Attributes{}
	for i := 0; i < 9; i++ {
		attrs[authorization.AttributeName(fmt.Sprint(i))] = authorization.StringValue(strings.Repeat("x", 4096))
	}
	caller.Request.Subject.Attributes = attrs
	caller.Request.Resource.Attributes = attrs
	if err := e.allow(ctx, b, caller); !errors.Is(err, delivery.ErrInvalidInput) || p.invoked {
		t.Fatal("combined input exceeded policy byte budget", err)
	}
}
