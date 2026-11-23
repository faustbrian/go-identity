package postgres

import (
	"context"
	"math"
	"testing"

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
