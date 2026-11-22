package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func ssoOIDCSessionCredentialFixture() (Work, *scopeFeatureParticipant, CredentialAdmission) {
	op := identity.FeatureOperation{Owner: "identity/session", OperationID: "identity.session.revoke-one", SchemaID: "session-revoke-one", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	owner := &scopeFeatureParticipant{operations: []identity.FeatureOperation{op}}
	b := codecBinding()
	b.OperationID, b.SchemaID, b.RecordID = op.OperationID, op.SchemaID, "target-session"
	b.ActorID = identity.ActorID(b.UserID)
	feature := &FeatureRegistration{Contributor: owner.Descriptor(), Operation: op}
	w := Work{state: &workState{ctx: context.Background(), binding: b, feature: feature, lifecycle: &workLifecycle{plan: LifecyclePlan{EventType: "session.revoked.v1", BeforeVersion: 7, AfterVersion: 8}}, featureInvocation: owner}}
	expected := CredentialAdmission{Credential: identity.CredentialRef{TenantID: b.TenantID, UserID: b.UserID, ID: "sso-reference", Kind: identity.CredentialProvider, Owner: "sso", Version: 3}, UserAuthorityVersion: 11, IdentifierAuthorityVersion: 13, CredentialAuthorityVersion: 17}
	return w, owner, expected
}

func TestSSOOIDCSessionCredentialRejectsUnownedScope(t *testing.T) {
	for _, repo := range []*Repository{nil, {}} {
		if err := repo.CheckLinkedSSOOIDCProviderCredential(t.Context(), CredentialAdmission{}); err == nil {
			t.Fatal("unowned SSO credential read admitted")
		}
	}
	if err := (Work{}).RequireLinkedSSOOIDCProviderCredential(t.Context(), nil, CredentialAdmission{}); err == nil {
		t.Fatal("zero Work admitted SSO credential")
	}
}

func TestSSOOIDCSessionCredentialRejectsForeignNativeScopeBeforeSQL(t *testing.T) {
	for name, mutate := range map[string]func(Work, *CredentialAdmission){
		"returned invocation":         func(w Work, _ *CredentialAdmission) { w.state.featureInvocation = nil },
		"preparation callback":        func(w Work, _ *CredentialAdmission) { w.state.featurePreparationPlan = &admittedKernelPlan{} },
		"foreign descriptor owner":    func(w Work, _ *CredentialAdmission) { w.state.feature.Contributor.Owner = "sso/postgres" },
		"foreign descriptor contract": func(w Work, _ *CredentialAdmission) { w.state.feature.Contributor.ContractID = "identity.session" },
		"foreign descriptor version":  func(w Work, _ *CredentialAdmission) { w.state.feature.Contributor.Version++ },
		"callback operation": func(w Work, _ *CredentialAdmission) {
			w.state.feature.Operation.OperationID = "identity.sso.oidc-callback"
		},
		"foreign operation owner": func(w Work, _ *CredentialAdmission) { w.state.feature.Operation.Owner = "sso" },
		"foreign schema":          func(w Work, _ *CredentialAdmission) { w.state.feature.Operation.SchemaID = "session-issue" },
		"foreign schema version":  func(w Work, _ *CredentialAdmission) { w.state.feature.Operation.SchemaVersion++ },
		"foreign binding":         func(w Work, _ *CredentialAdmission) { w.state.binding.OperationID = "identity.session.issue" },
		"anonymous binding":       func(w Work, _ *CredentialAdmission) { w.state.binding.AnonymousFlowID = "callback" },
		"foreign tenant":          func(_ Work, a *CredentialAdmission) { a.Credential.TenantID = "other-tenant" },
		"foreign user":            func(_ Work, a *CredentialAdmission) { a.Credential.UserID = "other-user" },
		"foreign actor":           func(w Work, _ *CredentialAdmission) { w.state.binding.ActorID = "other-user" },
		"service actor":           func(w Work, _ *CredentialAdmission) { w.state.binding.ActorKind = authorization.SubjectServiceAccount },
		"social credential":       func(_ Work, a *CredentialAdmission) { a.Credential.Owner = "identity/oauth" },
		"password credential": func(_ Work, a *CredentialAdmission) {
			a.Credential.Kind = identity.CredentialPassword
			a.Credential.Owner = "identity/password"
		},
		"missing user epoch":        func(_ Work, a *CredentialAdmission) { a.UserAuthorityVersion = 0 },
		"missing identifier epoch":  func(_ Work, a *CredentialAdmission) { a.IdentifierAuthorityVersion = 0 },
		"missing credential epoch":  func(_ Work, a *CredentialAdmission) { a.CredentialAuthorityVersion = 0 },
		"foreign lifecycle":         func(w Work, _ *CredentialAdmission) { w.state.lifecycle.plan.EventType = "session.issued.v1" },
		"foreign lifecycle index":   func(w Work, _ *CredentialAdmission) { w.state.lifecycle.plan.EventIndex = 1 },
		"missing original version":  func(w Work, _ *CredentialAdmission) { w.state.lifecycle.plan.BeforeVersion = 0 },
		"overflow original version": func(w Work, _ *CredentialAdmission) { w.state.lifecycle.plan.BeforeVersion = ^uint64(0) },
		"foreign successor":         func(w Work, _ *CredentialAdmission) { w.state.lifecycle.plan.AfterVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			w, owner, expected := ssoOIDCSessionCredentialFixture()
			mutate(w, &expected)
			var invalid identity.InvalidInputError
			if err := w.RequireLinkedSSOOIDCProviderCredential(t.Context(), owner, expected); !errors.As(err, &invalid) || w.state.failed == nil || w.state.sqlStarted {
				t.Fatal("foreign authority reached SQL or ignored denial left Work usable", err)
			}
		})
	}
	for _, mode := range []string{"nil context", "cancelled context", "foreign instance"} {
		t.Run(mode, func(t *testing.T) {
			w, owner, expected := ssoOIDCSessionCredentialFixture()
			ctx := context.Context(t.Context())
			if mode == "nil context" {
				ctx = nil
			}
			if mode == "cancelled context" {
				cancelled, stop := context.WithCancel(ctx)
				stop()
				ctx = cancelled
			}
			if mode == "foreign instance" {
				owner = &scopeFeatureParticipant{operations: owner.operations}
			}
			if err := w.RequireLinkedSSOOIDCProviderCredential(ctx, owner, expected); err == nil || w.state.failed == nil || w.state.sqlStarted {
				t.Fatal("foreign invocation escaped poisoned Work", err)
			}
		})
	}
}
