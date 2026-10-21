package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func TestAnonymousUpgradeDisposalScopeCannotTargetPermanentUser(t *testing.T) {
	i := anonymousDisposalFixture()
	b := codecBinding()
	b.OperationID, b.SchemaID = "identity.anonymous.upgrade", "identity.anonymous.upgrade.native-v1"
	b.UserID, b.ActorID, b.ActorKind = "permanent", "permanent", authorization.SubjectUser
	b.RecordID = string(i.Snapshot.Authority.User.ID)
	op := identity.FeatureOperation{Owner: "identity/anonymous", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	life := LifecyclePlan{EventType: "anonymous.upgraded.v1", BeforeVersion: 1, AfterVersion: 2}
	if !anonymousDisposalScope(b, op, life, i, true) {
		t.Fatal("distinct guest disposal denied")
	}
	if anonymousDisposalScope(b, op, life, i, false) {
		t.Fatal("delete API admitted target-bound upgrade")
	}
	for _, change := range []func(*identity.CommandBinding, *identity.FeatureOperation, *LifecyclePlan){
		func(b *identity.CommandBinding, _ *identity.FeatureOperation, _ *LifecyclePlan) {
			b.UserID = identity.UserID(b.RecordID)
			b.ActorID = identity.ActorID(b.UserID)
		},
		func(b *identity.CommandBinding, _ *identity.FeatureOperation, _ *LifecyclePlan) {
			b.RecordID = string(b.UserID)
		},
		func(b *identity.CommandBinding, _ *identity.FeatureOperation, _ *LifecyclePlan) {
			b.ActorID = identity.ActorID(b.RecordID)
		},
		func(b *identity.CommandBinding, _ *identity.FeatureOperation, _ *LifecyclePlan) { b.TenantID = "other" },
		func(_ *identity.CommandBinding, op *identity.FeatureOperation, _ *LifecyclePlan) { op.SchemaVersion++ },
		func(_ *identity.CommandBinding, _ *identity.FeatureOperation, l *LifecyclePlan) {
			l.EventType = "anonymous.deleted.v1"
		},
		func(_ *identity.CommandBinding, _ *identity.FeatureOperation, l *LifecyclePlan) { l.AfterVersion++ },
	} {
		other, otherOp, otherLife := b, op, life
		change(&other, &otherOp, &otherLife)
		if anonymousDisposalScope(other, otherOp, otherLife, i, true) {
			t.Fatal("foreign disposal admitted")
		}
	}
	if _, err := (*AnonymousDisposalDomain)(nil).ApplyUpgrade(context.Background(), Work{}, &anonymousUpgradeProbe{}, identity.Command{}, i); err == nil {
		t.Fatal("zero work admitted upgrade disposal")
	}
	if err := (*AnonymousDisposalDomain)(nil).CheckUpgrade(context.Background(), Work{}, &anonymousUpgradeProbe{}, identity.Command{}, i); err == nil {
		t.Fatal("zero final fence admitted")
	}
	if _, err := (Work{}).AnonymousUpgradeDisposal(&anonymousUpgradeProbe{}); err == nil {
		t.Fatal("zero work yielded disposal")
	}
}

func TestAnonymousUpgradeDisposalHistoryPreservesPopulatedPredecessors(t *testing.T) {
	base := AnonymousDisposalMigrationSource{Base: AnonymousIdentityMigrationSource{Base: IdentifierNormalizationMigrationSource{Base: IdentifierMutationMigrationSource{Base: CredentialMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}, Version: 12}, Version: 13}, Version: 14}, Version: 15}
	old, err := base.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	s := AnonymousUpgradeDisposalMigrationSource{Base: base, Version: 16}
	got, err := s.Load(t.Context())
	if err != nil || len(got) != len(old)+1 {
		t.Fatal("upgrade disposal suffix missing", err)
	}
	for n := range old {
		if old[n].Version() != got[n].Version() || old[n].Name() != got[n].Name() || old[n].UpSQL() != got[n].UpSQL() || old[n].DownSQL() != got[n].DownSQL() {
			t.Fatal("populated predecessor rewritten")
		}
	}
	if got[len(got)-1].DownSQL() != "" {
		t.Fatal("destructive downgrade offered")
	}
	for _, bad := range []AnonymousUpgradeDisposalMigrationSource{{}, {Base: base}, {Base: base, Version: 15}, {Base: MigrationSource{}, Version: 16}} {
		if out, err := bad.Load(t.Context()); err == nil || out != nil {
			t.Fatal("missing or out-of-order predecessor admitted")
		}
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if _, err := s.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("migration cancellation lost", err)
	}
}
