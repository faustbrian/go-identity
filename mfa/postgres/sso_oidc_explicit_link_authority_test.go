package mfapostgres

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func ssoOIDCExplicitLinkFactorFixture(t *testing.T, callback bool) (identity.FeatureCommandSpec, kernel.FeatureRegistration, kernel.LifecyclePlan) {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	start, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	op := identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.signin-start", SchemaID: "identity.sso.signin-start.oidc-link-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser}
	contributor := kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.oidc-login-start", Version: 1}
	life := kernel.LifecyclePlan{EventType: "oauth.rp_transaction.created.v1", AfterVersion: 1}
	if !callback {
		start = id
	}
	if callback {
		op = identity.FeatureOperation{Owner: "sso/oidc", OperationID: "identity.sso.oidc-callback", SchemaID: "sso-enterprise-oidc-explicit-link-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
		contributor.ContractID = "sso.oidc-login-callback"
		life = kernel.LifecyclePlan{EventType: "enterprise_provider.account_linked.v1", BeforeVersion: 1, AfterVersion: 2}
	}
	spec := identity.FeatureCommandSpec{Operation: op, Binding: identity.CommandBinding{
		CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", ActorKind: authorization.SubjectUser,
		RecordID: string(start), OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1,
		PolicyID: "link", PolicyVersion: 1, CorrelationID: string(id),
	}, Fields: []identity.FeatureField{{Name: "flow", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(start)}}}}
	return spec, kernel.FeatureRegistration{Contributor: contributor, Operation: op}, life
}

func ssoOIDCExplicitLinkFactorCommand(t *testing.T, spec identity.FeatureCommandSpec) identity.Command {
	t.Helper()
	token := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	command, err := identity.NewFeatureSessionCommand(spec, token)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func TestSSOOIDCExplicitLinkFactorAuthorityRequiresOriginalInvocation(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		if state, err := ReadSSOOIDCExplicitLinkFactors(ctx, nil, "tenant-a", "user-a", time.Second); err == nil || state.Version() != 0 {
			t.Fatal("missing primary inferred known-empty factors")
		}
		if state, err := RequireSSOOIDCExplicitLinkFactors(ctx, kernel.Work{}, nil, identity.Command{}, 1); err == nil || state.Version() != 0 {
			t.Fatal("unowned invocation supplied factor authority")
		}
	}
}

func TestSSOOIDCExplicitLinkFactorScopeIsExact(t *testing.T) {
	for _, callback := range []bool{false, true} {
		name := "start"
		if callback {
			name = "callback"
		}
		t.Run(name, func(t *testing.T) {
			spec, registration, life := ssoOIDCExplicitLinkFactorFixture(t, callback)
			command := ssoOIDCExplicitLinkFactorCommand(t, spec)
			if err := ssoOIDCExplicitLinkFactorScope(command, spec.Binding, registration, life); err != nil {
				t.Fatal("exact member-bound scope denied", err)
			}
			plain, err := identity.NewFeatureCommand(spec)
			if err != nil {
				t.Fatal(err)
			}
			if err := ssoOIDCExplicitLinkFactorScope(plain, spec.Binding, registration, life); err == nil {
				t.Fatal("command without original session custody admitted")
			}
			for name, mutate := range map[string]func(*identity.FeatureCommandSpec, *kernel.FeatureRegistration, *kernel.LifecyclePlan){
				"other-actor": func(s *identity.FeatureCommandSpec, _ *kernel.FeatureRegistration, _ *kernel.LifecyclePlan) {
					s.Binding.ActorID = "other-user"
				},
				"service-actor": func(s *identity.FeatureCommandSpec, _ *kernel.FeatureRegistration, _ *kernel.LifecyclePlan) {
					s.Binding.ActorKind = authorization.SubjectServiceAccount
				},
				"anonymous": func(s *identity.FeatureCommandSpec, _ *kernel.FeatureRegistration, _ *kernel.LifecyclePlan) {
					s.Operation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
					s.Binding.UserID, s.Binding.AnonymousFlowID = "", "anonymous"
				},
				"schema-alias": func(s *identity.FeatureCommandSpec, _ *kernel.FeatureRegistration, _ *kernel.LifecyclePlan) {
					s.Operation.SchemaID += ".alias"
					s.Binding.SchemaID = s.Operation.SchemaID
				},
				"schema-version": func(s *identity.FeatureCommandSpec, _ *kernel.FeatureRegistration, _ *kernel.LifecyclePlan) {
					s.Operation.SchemaVersion = 2
					s.Binding.SchemaVersion = 2
				},
				"operation-owner": func(s *identity.FeatureCommandSpec, _ *kernel.FeatureRegistration, _ *kernel.LifecyclePlan) {
					s.Operation.Owner = "identity/oauth"
				},
				"owner": func(_ *identity.FeatureCommandSpec, f *kernel.FeatureRegistration, _ *kernel.LifecyclePlan) {
					f.Contributor.Owner = "identity/oauth/postgres"
				},
				"contract": func(_ *identity.FeatureCommandSpec, f *kernel.FeatureRegistration, _ *kernel.LifecyclePlan) {
					f.Contributor.ContractID += ".alias"
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
				"before-version": func(_ *identity.FeatureCommandSpec, _ *kernel.FeatureRegistration, l *kernel.LifecyclePlan) {
					l.BeforeVersion++
				},
				"after-version": func(_ *identity.FeatureCommandSpec, _ *kernel.FeatureRegistration, l *kernel.LifecyclePlan) {
					l.AfterVersion++
				},
			} {
				t.Run(name, func(t *testing.T) {
					s, f, l := ssoOIDCExplicitLinkFactorFixture(t, callback)
					mutate(&s, &f, &l)
					f.Operation = s.Operation
					if err := ssoOIDCExplicitLinkFactorScope(ssoOIDCExplicitLinkFactorCommand(t, s), s.Binding, f, l); err == nil {
						t.Fatal("foreign scope admitted")
					}
				})
			}
			changed := spec.Binding
			changed.RecordID = "other-flow"
			if err := ssoOIDCExplicitLinkFactorScope(command, changed, registration, life); err == nil {
				t.Fatal("substituted original binding admitted")
			}
			cookie := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
			preauth, err := identity.NewFeaturePreAuthCommand(spec, cookie)
			if err != nil {
				t.Fatal(err)
			}
			if err := ssoOIDCExplicitLinkFactorScope(preauth, spec.Binding, registration, life); err == nil {
				t.Fatal("anonymous browser custody substituted for member session")
			}
			code, err := auth.NewOneTimeCode("123456")
			if err != nil {
				t.Fatal(err)
			}
			codeCommand, err := identity.NewFeatureOneTimeCodeSessionCommand(spec, code, cookie)
			if err != nil {
				t.Fatal(err)
			}
			if err := ssoOIDCExplicitLinkFactorScope(codeCommand, spec.Binding, registration, life); err == nil {
				t.Fatal("code-bearing session command borrowed code-free link scope")
			}
		})
	}
}
