package postgres

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

type logoutScopeParticipant struct{ scopeFeatureParticipant }

func (*logoutScopeParticipant) Descriptor() ContributorDescriptor { return SSOOIDCLogoutDescriptor() }

func TestSSOOIDCLogoutScopeIsExactAndDenialsPoisonWork(t *testing.T) {
	ctx := context.Background()
	owner := &logoutScopeParticipant{}
	op := SSOOIDCLogoutOperation()
	b := featureCodecSpec().Binding
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	b.ActorKind, b.ActorID = authorization.SubjectUser, identity.ActorID(b.UserID)
	registration := FeatureRegistration{Operation: op, Contributor: owner.Descriptor()}
	lifecycle := LifecyclePlan{EventType: "session.revoked.v1", BeforeVersion: 3, AfterVersion: 4}
	newWork := func() Work {
		f := registration
		return Work{state: &workState{ctx: ctx, binding: b, feature: &f,
			featureInvocation: owner, subjectType: "session", lifecycle: &workLifecycle{plan: lifecycle}}}
	}
	if err := newWork().RequireSSOOIDCLogoutScope(ctx, owner, b.TenantID, b.UserID, b.RecordID, 3); err != nil {
		t.Fatal("original audience and session transition denied", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*workState)
	}{
		{"foreign invocation", func(s *workState) { s.featureInvocation = &logoutScopeParticipant{} }},
		{"returned invocation", func(s *workState) { s.featureInvocation = nil }},
		{"other contributor", func(s *workState) { s.feature.Contributor.ContractID = "sso.oidc-other" }},
		{"other operation", func(s *workState) { s.feature.Operation = SSOOAuth2SigninOperation() }},
		{"completion operation", func(s *workState) { s.feature.Operation = SSOOIDCLogoutCompleteOperation() }},
		{"completion contributor", func(s *workState) { s.feature.Contributor = SSOOIDCLogoutCompleteDescriptor() }},
		{"callback preparation", func(s *workState) { s.featurePreparationPlan = &admittedKernelPlan{} }},
		{"other tenant", func(s *workState) { s.binding.TenantID = "other-tenant" }},
		{"other user", func(s *workState) { s.binding.UserID = "other-user" }},
		{"other actor", func(s *workState) { s.binding.ActorID = "other-user" }},
		{"nonuser actor", func(s *workState) { s.binding.ActorKind = authorization.SubjectServiceAccount }},
		{"anonymous flow", func(s *workState) { s.binding.AnonymousFlowID = "other-flow" }},
		{"other session", func(s *workState) { s.binding.RecordID = "other-session" }},
		{"other lifecycle subject type", func(s *workState) { s.subjectType = "user" }},
		{"other event", func(s *workState) { s.lifecycle.plan.EventType = "session.created.v1" }},
		{"other event index", func(s *workState) { s.lifecycle.plan.EventIndex = 1 }},
		{"other predecessor", func(s *workState) { s.lifecycle.plan.BeforeVersion = 2 }},
		{"invalid successor", func(s *workState) { s.lifecycle.plan.AfterVersion = 5 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWork()
			tc.edit(w.state)
			err := w.RequireSSOOIDCLogoutScope(ctx, owner, b.TenantID, b.UserID, b.RecordID, 3)
			if err == nil || w.usable() == nil {
				t.Fatal("invalid scope must fail and poison Work")
			}
		})
	}
	for _, version := range []uint64{0, math.MaxUint64} {
		w := newWork()
		w.state.lifecycle.plan.BeforeVersion = version
		w.state.lifecycle.plan.AfterVersion = version + 1
		if err := w.RequireSSOOIDCLogoutScope(ctx, owner, b.TenantID, b.UserID, b.RecordID, version); err == nil {
			t.Fatalf("invalid original version %d admitted", version)
		}
	}
}

func TestSSOOIDCLogoutRegistryHasNoOwnerOrSchemaFallback(t *testing.T) {
	op, descriptor := SSOOIDCLogoutOperation(), SSOOIDCLogoutDescriptor()
	if !featureContributorOwns(descriptor, op) {
		t.Fatal("canonical native owner denied")
	}
	if featureContributorOwns(ssoOIDCSigninDescriptor(), op) {
		t.Fatal("callback owner admitted for logout")
	}
	if featureContributorOwns(SSOOIDCLogoutCompleteDescriptor(), op) {
		t.Fatal("completion owner admitted for logout start")
	}
	changed := op
	changed.SchemaVersion++
	if featureContributorOwns(descriptor, changed) {
		t.Fatal("unreviewed future schema admitted")
	}
	changed = op
	changed.Owner = descriptor.Owner
	if featureContributorOwns(descriptor, changed) {
		t.Fatal("generic contributor ownership admitted an altered profile")
	}
}

func TestSSOOIDCLogoutCompleteRegistryHasNoOwnerOrSchemaFallback(t *testing.T) {
	op, descriptor := SSOOIDCLogoutCompleteOperation(), SSOOIDCLogoutCompleteDescriptor()
	wantOperation := identity.FeatureOperation{Owner: "sso/oidc", OperationID: "identity.sso.oidc-logout-complete", SchemaID: "sso-enterprise-oidc-logout-complete-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	wantDescriptor := ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.oidc-logout-complete", Version: 1}
	if op != wantOperation || descriptor != wantDescriptor {
		t.Fatal("completion must retain its separate exact user-targeted contract")
	}
	owner := &featureRegistryContributor{descriptor: descriptor, operations: []identity.FeatureOperation{op}}
	registry, err := NewContributorRegistry([]Contributor{owner})
	if err != nil {
		t.Fatal("canonical completion registration denied", err)
	}
	registration := FeatureRegistration{Operation: op, Contributor: descriptor}
	entry, err := registry.selectFeatureOperation(registration)
	if err != nil || entry.contributor != owner {
		t.Fatal("completion did not select its original registered owner", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*FeatureRegistration)
	}{
		{"logout start owner", func(f *FeatureRegistration) { f.Contributor = SSOOIDCLogoutDescriptor() }},
		{"signin owner", func(f *FeatureRegistration) { f.Contributor = ssoOIDCSigninDescriptor() }},
		{"oauth2 signin owner", func(f *FeatureRegistration) { f.Contributor = ssoOAuth2SigninDescriptor() }},
		{"other contributor owner", func(f *FeatureRegistration) { f.Contributor.Owner = "sso/other/postgres" }},
		{"future contributor version", func(f *FeatureRegistration) { f.Contributor.Version++ }},
		{"future schema", func(f *FeatureRegistration) { f.Operation.SchemaVersion++ }},
		{"other schema", func(f *FeatureRegistration) { f.Operation.SchemaID = "sso-enterprise-oidc-logout-v1" }},
		{"same-owner fallback", func(f *FeatureRegistration) { f.Operation.Owner = "sso" }},
		{"other operation owner", func(f *FeatureRegistration) { f.Operation.Owner = "sso/oauth2" }},
		{"omitted record", func(f *FeatureRegistration) { f.Operation.RecordRequirement = identity.FeatureRecordOmitted }},
		{"anonymous subject", func(f *FeatureRegistration) { f.Operation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow }},
		{"snapshot import", func(f *FeatureRegistration) { f.Operation.VersionPolicy = identity.FeatureVersionSnapshotImport }},
		{"unchanged version", func(f *FeatureRegistration) { f.Operation.VersionPolicy = identity.FeatureVersionSequentialOrUnchanged }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := registration
			tc.edit(&changed)
			if featureContributorOwns(changed.Contributor, changed.Operation) {
				t.Fatal("altered completion admitted through owner fallback")
			}
			input := &featureRegistryContributor{descriptor: changed.Contributor, operations: []identity.FeatureOperation{changed.Operation}}
			if got, err := NewContributorRegistry([]Contributor{input}); err == nil || got != nil {
				t.Fatal("altered completion registered", err)
			}
			if _, err := registry.selectFeatureOperation(changed); err == nil {
				t.Fatal("altered completion selected from frozen registry")
			}
		})
	}
}

func TestSSOOIDCLogoutCompleteUsesExistingServiceActorRecordLifecycle(t *testing.T) {
	op := SSOOIDCLogoutCompleteOperation()
	b := featureCodecSpec().Binding
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	b.ActorKind, b.ActorID = authorization.SubjectServiceAccount, "logout-callback"
	b.RecordID = "original-logout-transaction"
	if err := b.ValidateFor(op); err != nil {
		t.Fatal("service actor cannot retain original user and exact logout target", err)
	}
	registration := FeatureRegistration{Operation: op, Contributor: SSOOIDCLogoutCompleteDescriptor()}
	w := Work{state: &workState{ctx: context.Background(), binding: b, feature: &registration, subjectType: "sso_logout"}}
	life := LifecyclePlan{EventType: "sso.logout.completed.v1", BeforeVersion: 0, AfterVersion: 1}
	if err := bindLifecyclePlan(w, &life); err != nil {
		t.Fatal("completion requires no new lifecycle admission contract", err)
	}
	if err := w.StageLifecycle(0, time.Date(2026, time.November, 23, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal("completion lifecycle cannot stage through existing Work", err)
	}
	got := w.state.lifecycle.record
	if got == nil || got.UserID != b.UserID || got.SubjectType != "sso_logout" || got.SubjectID != b.RecordID || got.BeforeVersion != 0 || got.AfterVersion != 1 || got.OperationID != op.OperationID {
		t.Fatal("completion lifecycle changed the sealed-state-selected user or target")
	}
	for _, versions := range [][2]uint64{{0, 0}, {0, 2}, {1, 1}, {math.MaxUint64, 0}} {
		if err := op.ValidateRecordVersions(versions[0], versions[1]); err == nil {
			t.Fatalf("invalid completion lifecycle transition %d -> %d admitted", versions[0], versions[1])
		}
	}
}
