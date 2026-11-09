package mfapostgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestOAuthLinkFactorAuthorityRequiresOriginalInvocation(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		if state, err := ReadOAuthLinkFactors(ctx, nil, "tenant", "user", time.Second); err == nil || state.Version() != 0 {
			t.Fatal("missing primary inferred no factors")
		}
		if state, err := RequireOAuthLinkStartFactors(ctx, kernel.Work{}, nil, identity.Command{}, 1); err == nil || state.Version() != 0 {
			t.Fatal("unowned start Work supplied authority")
		}
		if state, err := RequireOAuthLinkPreparationFactors(ctx, kernel.AccountLinkPreparationWork{}, nil, 1); err == nil || state.Version() != 0 {
			t.Fatal("unowned preparation Work supplied authority")
		}
		if state, err := RequireOAuthLinkFactors(ctx, kernel.AccountLinkWork{}, nil, 1); err == nil || state.Version() != 0 {
			t.Fatal("unowned link Work supplied authority")
		}
	}
}

func oauthLinkStartFactorFixture(t *testing.T) (identity.FeatureCommandSpec, kernel.FeatureRegistration, kernel.LifecyclePlan) {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	op := identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.account.link-start", SchemaID: "identity.account.link-start.rp-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser}
	s := identity.FeatureCommandSpec{Binding: identity.CommandBinding{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", ActorKind: authorization.SubjectUser, RecordID: "flow-a", OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "link", PolicyVersion: 1, CorrelationID: string(id)}, Operation: op, Fields: []identity.FeatureField{{Name: "flow", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "flow-a"}}}}
	f := kernel.FeatureRegistration{Contributor: kernel.ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.rp-initiation", Version: 1}, Operation: op}
	return s, f, kernel.LifecyclePlan{EventType: "oauth.rp_transaction.created.v1", AfterVersion: 1}
}

func TestOAuthLinkStartFactorScopeIsExact(t *testing.T) {
	s, f, life := oauthLinkStartFactorFixture(t)
	if err := oauthLinkStartFactorScope(s, s.Binding, f, life); err != nil {
		t.Fatal("exact original scope denied", err)
	}
	for name, mutate := range map[string]func(*identity.FeatureCommandSpec, *kernel.FeatureRegistration, *kernel.LifecyclePlan){
		"actor": func(s *identity.FeatureCommandSpec, _ *kernel.FeatureRegistration, _ *kernel.LifecyclePlan) {
			s.Binding.ActorID = "other"
		},
		"tenant": func(s *identity.FeatureCommandSpec, _ *kernel.FeatureRegistration, _ *kernel.LifecyclePlan) {
			s.Binding.TenantID = ""
		},
		"user": func(s *identity.FeatureCommandSpec, _ *kernel.FeatureRegistration, _ *kernel.LifecyclePlan) {
			s.Binding.UserID = ""
		},
		"anonymous": func(s *identity.FeatureCommandSpec, _ *kernel.FeatureRegistration, _ *kernel.LifecyclePlan) {
			s.Binding.AnonymousFlowID = "anonymous"
		},
		"schema": func(s *identity.FeatureCommandSpec, f *kernel.FeatureRegistration, _ *kernel.LifecyclePlan) {
			s.Operation.SchemaID += ".alias"
			s.Binding.SchemaID = s.Operation.SchemaID
			f.Operation = s.Operation
		},
		"subject-profile": func(s *identity.FeatureCommandSpec, f *kernel.FeatureRegistration, _ *kernel.LifecyclePlan) {
			s.Operation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
			f.Operation = s.Operation
		},
		"owner": func(_ *identity.FeatureCommandSpec, f *kernel.FeatureRegistration, _ *kernel.LifecyclePlan) {
			f.Contributor.Owner = "identity/session/postgres"
		},
		"contract": func(_ *identity.FeatureCommandSpec, f *kernel.FeatureRegistration, _ *kernel.LifecyclePlan) {
			f.Contributor.ContractID = "identity.oauth.account-link"
		},
		"owner-version": func(_ *identity.FeatureCommandSpec, f *kernel.FeatureRegistration, _ *kernel.LifecyclePlan) {
			f.Contributor.Version = 2
		},
		"event": func(_ *identity.FeatureCommandSpec, _ *kernel.FeatureRegistration, l *kernel.LifecyclePlan) {
			l.EventType = "session.created.v1"
		},
		"event-index": func(_ *identity.FeatureCommandSpec, _ *kernel.FeatureRegistration, l *kernel.LifecyclePlan) {
			l.EventIndex = 1
		},
		"before": func(_ *identity.FeatureCommandSpec, _ *kernel.FeatureRegistration, l *kernel.LifecyclePlan) {
			l.BeforeVersion = 1
		},
		"after": func(_ *identity.FeatureCommandSpec, _ *kernel.FeatureRegistration, l *kernel.LifecyclePlan) {
			l.AfterVersion = 2
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, f, l := oauthLinkStartFactorFixture(t)
			mutate(&s, &f, &l)
			if err := oauthLinkStartFactorScope(s, s.Binding, f, l); err == nil {
				t.Fatal("foreign scope admitted")
			}
		})
	}
	b := s.Binding
	b.RecordID = "other-flow"
	if err := oauthLinkStartFactorScope(s, b, f, life); err == nil {
		t.Fatal("substituted command admitted")
	}
}

func TestOAuthLinkRootFactorScopeIsExplicitSelfOnly(t *testing.T) {
	s, _, _ := oauthLinkStartFactorFixture(t)
	b := s.Binding
	b.OperationID, b.SchemaID, b.SchemaVersion = "identity.account.link-token", "identity-account", 1
	b.LinkMode = identity.AccountLinkExplicit
	if err := oauthLinkFactorScope(b); err != nil {
		t.Fatal("canonical root link scope denied", err)
	}
	for name, mutate := range map[string]func(*identity.CommandBinding){
		"operation": func(b *identity.CommandBinding) {
			b.OperationID = "identity.account.unlink"
		},
		"schema":         func(b *identity.CommandBinding) { b.SchemaID += ".alias" },
		"schema-version": func(b *identity.CommandBinding) { b.SchemaVersion = 2 },
		"implicit": func(b *identity.CommandBinding) {
			b.LinkMode = identity.AccountLinkImplicit
		},
		"administrative": func(b *identity.CommandBinding) {
			b.LinkMode = identity.AccountLinkAdministrative
		},
		"actor": func(b *identity.CommandBinding) { b.ActorID = "other-user" },
		"actor-kind": func(b *identity.CommandBinding) {
			b.ActorKind = authorization.SubjectServiceAccount
		},
		"user":      func(b *identity.CommandBinding) { b.UserID = "" },
		"anonymous": func(b *identity.CommandBinding) { b.AnonymousFlowID = "anonymous" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := b
			mutate(&changed)
			if err := oauthLinkFactorScope(changed); err == nil {
				t.Fatal("foreign root scope admitted")
			}
		})
	}
}
