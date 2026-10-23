package postgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func TestAnonymousExpiryRequiresClosedContributorRegistration(t *testing.T) {
	owner := anonymousCreationDescriptor()
	op := identity.FeatureOperation{Owner: "identity/anonymous", OperationID: "identity.anonymous.expire", SchemaID: "identity.anonymous.expire.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if !featureContributorOwns(owner, op) {
		t.Fatal("exact anonymous expiry owner rejected")
	}
	for _, change := range []func(*identity.FeatureOperation){
		func(op *identity.FeatureOperation) { op.SchemaID = "generic-cleanup" },
		func(op *identity.FeatureOperation) { op.SchemaVersion++ },
		func(op *identity.FeatureOperation) { op.RecordRequirement = identity.FeatureRecordOmitted },
		func(op *identity.FeatureOperation) { op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow },
	} {
		alias := op
		change(&alias)
		if featureContributorOwns(owner, alias) {
			t.Fatal("generic schema bypassed the closed expiry owner")
		}
	}
	for _, other := range []ContributorDescriptor{{Owner: "identity/another/postgres", ContractID: owner.ContractID, Version: 1}, {Owner: owner.Owner, ContractID: "another", Version: 1}, {Owner: owner.Owner, ContractID: owner.ContractID, Version: 2}} {
		if featureContributorOwns(other, op) {
			t.Fatal("unselected contributor claimed expiry ownership")
		}
	}
}

func TestAnonymousExpiryRequiresServiceScopeWithoutWeakeningSelfDeletion(t *testing.T) {
	i := anonymousDisposalFixture()
	op := anonymousExpiryDisposalOperation()
	b := codecBinding()
	b.TenantID = i.Snapshot.Authority.User.TenantID
	b.UserID = i.Snapshot.Authority.User.ID
	b.RecordID = string(b.UserID)
	b.ActorID = "guest-maintenance"
	b.ActorKind = authorization.SubjectServiceAccount
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	l := LifecyclePlan{BeforeVersion: 1, AfterVersion: 2, EventType: "anonymous.expired.v1"}
	if !anonymousDisposalScopeFor(b, op, l, i, anonymousDisposalExpired) {
		t.Fatal("trusted service scope denied")
	}
	for name, change := range map[string]func(*identity.CommandBinding, *identity.FeatureOperation, *LifecyclePlan){
		"user actor": func(b *identity.CommandBinding, _ *identity.FeatureOperation, _ *LifecyclePlan) {
			b.ActorKind, b.ActorID = authorization.SubjectUser, identity.ActorID(b.UserID)
		},
		"api key": func(b *identity.CommandBinding, _ *identity.FeatureOperation, _ *LifecyclePlan) {
			b.ActorKind = authorization.SubjectAPIKey
		},
		"foreign tenant": func(b *identity.CommandBinding, _ *identity.FeatureOperation, _ *LifecyclePlan) {
			b.TenantID = "foreign"
		},
		"foreign subject": func(b *identity.CommandBinding, _ *identity.FeatureOperation, _ *LifecyclePlan) { b.UserID = "another" },
		"foreign record": func(b *identity.CommandBinding, _ *identity.FeatureOperation, _ *LifecyclePlan) {
			b.RecordID = "another"
		},
		"self delete alias": func(b *identity.CommandBinding, op *identity.FeatureOperation, l *LifecyclePlan) {
			*op = anonymousDisposalOperation()
			b.OperationID, b.SchemaID = op.OperationID, op.SchemaID
			l.EventType = "anonymous.deleted.v1"
		},
		"wrong event": func(_ *identity.CommandBinding, _ *identity.FeatureOperation, l *LifecyclePlan) {
			l.EventType = "anonymous.deleted.v1"
		},
		"version skip": func(_ *identity.CommandBinding, _ *identity.FeatureOperation, l *LifecyclePlan) { l.AfterVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			candidate, selected, lifecycle := b, op, l
			change(&candidate, &selected, &lifecycle)
			if anonymousDisposalScopeFor(candidate, selected, lifecycle, i, anonymousDisposalExpired) {
				t.Fatal("untrusted maintenance scope admitted")
			}
		})
	}
	if anonymousDisposalScope(b, op, l, i, false) || anonymousDisposalScope(b, op, l, i, true) {
		t.Fatal("maintenance grants old browser operation authority")
	}
	if anonymousDisposalScopeFor(b, op, l, i, 0) {
		t.Fatal("unknown disposal mode admitted")
	}
	if _, err := (*AnonymousDisposalDomain)(nil).ApplyExpired(context.Background(), Work{}, nil, identity.Command{}, i); err == nil {
		t.Fatal("missing protected work admitted")
	}
	if err := (*AnonymousDisposalDomain)(nil).CheckExpired(context.Background(), Work{}, nil, identity.Command{}, i); err == nil {
		t.Fatal("missing final fence admitted")
	}
	if _, err := (Work{}).AnonymousExpiredDisposal(nil); err == nil {
		t.Fatal("missing actual expiry projection admitted")
	}
}
