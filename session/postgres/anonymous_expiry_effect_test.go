package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestAnonymousExpirySessionEffectRequiresServiceOwnerAndExactOperation(t *testing.T) {
	op := anonymousExpirySessionOperation()
	b := identity.CommandBinding{CommandID: "AAAAAAAAAAAAAAAAAAAABA", TenantID: "tenant-a", UserID: "AAAAAAAAAAAAAAAAAAAAAQ", RecordID: "AAAAAAAAAAAAAAAAAAAAAQ", ActorID: "guest-maintenance", ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, PolicyID: "maintenance", PolicyVersion: 1, SchemaID: op.SchemaID, SchemaVersion: 1, CorrelationID: "maintenance-a"}
	l := kernel.LifecyclePlan{BeforeVersion: 1, AfterVersion: 2, EventType: "anonymous.expired.v1"}
	d := kernel.ContributorDescriptor{Owner: "identity/anonymous/postgres", ContractID: "identity.anonymous", Version: 1}
	if !anonymousExpiryBinding(b, op, l, d) {
		t.Fatal("exact service-expiry binding rejected")
	}
	for name, change := range map[string]func(*identity.CommandBinding, *identity.FeatureOperation, *kernel.LifecyclePlan, *kernel.ContributorDescriptor){
		"user actor": func(b *identity.CommandBinding, _ *identity.FeatureOperation, _ *kernel.LifecyclePlan, _ *kernel.ContributorDescriptor) {
			b.ActorKind, b.ActorID = authorization.SubjectUser, identity.ActorID(b.UserID)
		},
		"other record": func(b *identity.CommandBinding, _ *identity.FeatureOperation, _ *kernel.LifecyclePlan, _ *kernel.ContributorDescriptor) {
			b.RecordID = "another"
		},
		"other schema": func(b *identity.CommandBinding, op *identity.FeatureOperation, _ *kernel.LifecyclePlan, _ *kernel.ContributorDescriptor) {
			op.SchemaID, b.SchemaID = "generic", "generic"
		},
		"other event": func(_ *identity.CommandBinding, _ *identity.FeatureOperation, l *kernel.LifecyclePlan, _ *kernel.ContributorDescriptor) {
			l.EventType = "anonymous.deleted.v1"
		},
		"version skip": func(_ *identity.CommandBinding, _ *identity.FeatureOperation, l *kernel.LifecyclePlan, _ *kernel.ContributorDescriptor) {
			l.AfterVersion++
		},
		"other owner": func(_ *identity.CommandBinding, _ *identity.FeatureOperation, _ *kernel.LifecyclePlan, d *kernel.ContributorDescriptor) {
			d.Version++
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate, selected, lifecycle, owner := b, op, l, d
			change(&candidate, &selected, &lifecycle, &owner)
			if anonymousExpiryBinding(candidate, selected, lifecycle, owner) {
				t.Fatal("untrusted expiry revocation admitted")
			}
		})
	}
	var effect *AnonymousDisposalEffect
	if _, err := effect.ApplyExpired(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
		t.Fatal("missing protected work admitted")
	}
	if err := effect.CheckExpired(context.Background(), kernel.Work{}, nil, identity.Command{}, time.Time{}); err == nil {
		t.Fatal("missing final fence admitted")
	}
	if _, err := effect.RecoverExpired(context.Background(), kernel.RecoveryWork{}, nil); err == nil {
		t.Fatal("missing retained recovery admitted")
	}
}
